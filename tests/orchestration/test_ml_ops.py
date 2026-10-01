"""orchestration/ops/training.py and review.py: the model's lifecycle,
without ClickHouse, Kafka or Groq.

Training runs for real (LightGBM, where installed) on a small synthetic
set; the reviewer talks to a stand-in for Groq's API.
"""

import json
import random
import urllib.error

import pytest

from core import ml
from orchestration.ops import review, training


# --- training ------------------------------------------------------------------------

def row(label, i, reviewed=False, **features):
    event = {f: 0.0 for f in ml.FEATURES}
    event.update(features)
    return {**event, "event_id": f"e{i}", "event_type": "BUILD_FAILURE", "rule_score": 0.0, "rule_hits": "",
            "label": label, "weight": 1.0, "reviewed": reviewed}


def synthetic(n=3000, seed=5):
    rng = random.Random(seed)
    rows = []
    for i in range(n):
        incident = rng.random() < 0.1
        rows.append(row(int(incident), i,
                        failed_builds_5m=rng.randint(20, 60) if incident else rng.randint(0, 6),
                        unique_projects_5m=rng.randint(5, 20) if incident else rng.randint(1, 2),
                        events_1m=rng.randint(1, 80)))
    return rows


def test_the_split_is_stable_and_keeps_reviewer_labels_out_of_the_holdout():
    rows = synthetic(1000) + [row(1, 10_000 + i, reviewed=True) for i in range(50)]
    train, test = training.split(rows)
    assert training.split(rows) == (train, test)                    # a rerun splits the same way
    assert not any(r["reviewed"] for r in test)
    assert 0.1 < len(test) / len(rows) < 0.3


def test_metrics():
    m = training.metrics([0.9, 0.8, 0.7, 0.2, 0.1], [1, 0, 1, 0, 0])
    assert m["average_precision"] == pytest.approx((1 / 1 + 2 / 3) / 2)
    assert m["recall_at_alert"] == 1.0 and m["false_positive_rate_at_alert"] == pytest.approx(1 / 3)


def holdout(ap, fp):
    return {"average_precision": ap, "false_positives": fp}


@pytest.mark.parametrize("candidate, incumbent, reviewed, promoted", [
    (holdout(0.95, 0), None, None, True),                        # nothing live yet
    (holdout(0.9999, 2), holdout(0.9991, 0), (0, 3), True),     # measured 2026-09-28: noise, and it fixed the AI's 3
    (holdout(0.95, 3), holdout(0.95, 0), None, True),            # 3 of ~1,500 after 0: within chance
    (holdout(0.95, 8), holdout(0.95, 0), None, False),           # 8 after 0: not chance
    (holdout(0.90, 0), holdout(0.95, 0), None, False),           # ranks incidents worse
    (holdout(0.99, 0), holdout(0.95, 0), (2, 1), False),         # unlearned a correction
])
def test_promotion_needs_a_model_at_least_as_good(candidate, incumbent, reviewed, promoted):
    assert training.better(candidate, incumbent, reviewed)[0] is promoted


def test_the_false_alarm_margin_grows_with_the_count():
    assert 4 < training.false_alarm_bound(0) < 5
    assert 18 < training.false_alarm_bound(10) < 19


def test_a_trained_model_is_small_enough_for_the_stream_and_scores_through_the_job_code():
    pytest.importorskip("lightgbm")
    rows = synthetic()
    booster = training.train(rows)
    assert booster.num_trees() <= training.MAX_TREES
    model = ml.Model(booster.dump_model(), "t")                       # what the job loads
    train, test = training.split(rows)
    m = training.metrics([model.score(r) for r in test], [r["label"] for r in test])
    assert m["average_precision"] > 0.9


class FakeClickHouse:
    def __init__(self, rows, active=None):
        self._rows, self.active_model = rows, active
        self.inserted = {}

    def rows(self, sql, **params):
        if "ml_model_active" in sql:
            return [{"version": "old", "model": json.dumps(self.active_model)}] if self.active_model else []
        if "cityHash64" in sql:                  # recent traffic, for the shadow check: ordinary hours
            return [r for r in self._rows if not r["label"]]
        return self._rows

    def insert(self, table, rows):
        self.inserted.setdefault(table, []).extend(rows)


def test_run_registers_every_model_and_promotes_only_a_better_one():
    pytest.importorskip("lightgbm")
    ch = FakeClickHouse(synthetic())
    first = training.run(ch)
    assert first["promoted"] and first["why"] == "no active model yet"
    assert [r["version"] for r in ch.inserted["watchtower.ml_model_active"]] == [first["version"]]

    # Against an identical incumbent it is "at least as good": promoted again.
    incumbent = json.loads(ch.inserted["watchtower.ml_models"][0]["model"])
    ch = FakeClickHouse(synthetic(), active=incumbent)
    assert training.run(ch)["incumbent"]["version"] == "old"
    assert len(ch.inserted["watchtower.ml_models"]) == 1


def test_normal_events_are_sampled_per_source_and_weighted_back_to_the_real_count():
    sampler = training.NormalSampler(per_source=5, rng=random.Random(1))
    for i in range(1000):
        sampler.add("10.0.0.1", f"busy{i}")          # a monitoring agent
    for i in range(3):
        sampler.add("102.67.14.54", f"spot{i}")      # a quiet cloud runner
    rows = sampler.rows()
    by_source = {}
    for r in rows:
        by_source.setdefault(r["event_id"][:3], []).append(r["weight"])
    assert len(by_source["bus"]) == 5 and sum(by_source["bus"]) == 1000
    assert len(by_source["spo"]) == 3 and sum(by_source["spo"]) == 3   # the quiet host is kept, whole


def test_a_reviewer_label_weighs_half_a_typical_sampled_row():
    rows = [row(0, 1) | {"weight": 40.0}, row(0, 2) | {"weight": 60.0}, row(0, 3, reviewed=True) | {"weight": 0.5}]
    assert training.weights(rows) == [40.0, 60.0, 25.0]


@pytest.mark.parametrize("shadowed, promoted", [
    ({"rows": 20000, "candidate_alerts": 30, "incumbent_alerts": 25}, True),
    # measured 2026-09-28: ~1.7% of live events alerted on by the model alone
    ({"rows": 20000, "candidate_alerts": 340, "incumbent_alerts": 14}, False),
    ({"rows": 20000, "candidate_alerts": 60, "incumbent_alerts": 10}, False),     # six times the active model
    ({"rows": 0, "candidate_alerts": 0, "incumbent_alerts": None}, True),        # no recent traffic: not judged
])
def test_the_shadow_check_refuses_a_model_that_would_flood_the_on_call(shadowed, promoted):
    good = {"average_precision": 0.99, "false_positives": 0}
    assert training.better(good, good, None, shadowed)[0] is promoted


def test_a_model_alerting_on_a_whole_group_of_hosts_is_refused():
    # Few alerts in total, but on eight times as many hosts: the 2026-09-28
    # pattern -- one alert per remote-staff VPN host, on all of them.
    good = {"average_precision": 0.99, "false_positives": 0}
    shadowed = {"rows": 20000, "candidate_alerts": 40, "incumbent_alerts": 30,
                "candidate_sources": 40, "incumbent_sources": 5}
    ok, why = training.better(good, good, None, shadowed)
    assert not ok and "on 40 hosts vs 5" in why


def test_the_shadow_sample_counts_hosts():
    pytest.importorskip("lightgbm")
    rows = synthetic(2000)
    dump = training.train(rows).dump_model()
    traffic = [r | {"runner_ip": f"10.0.0.{i % 7}"} for i, r in enumerate(rows) if not r["label"]]
    out = training.shadow(dump, dump, traffic)
    assert out["sources"] == 7 and out["candidate_alerts"] == out["incumbent_alerts"]
    assert out["candidate_sources"] == out["incumbent_sources"] <= 7


def test_even_a_first_model_must_pass_the_shadow_check():
    good = {"average_precision": 0.99, "false_positives": 0}
    assert not training.better(good, None, None, {"rows": 1000, "candidate_alerts": 50, "incumbent_alerts": None})[0]


def test_too_little_data_is_a_skip_not_a_bad_model():
    report = training.run(FakeClickHouse(synthetic(100)))
    assert report["status"] == "skipped"


# --- review --------------------------------------------------------------------------

EVENT = {"event_id": "u1", "timestamp": "2026-09-28 10:00:00.000", "runner_ip": "102.67.14.98",
         "event_type": "BUILD_SUCCESS", "project": "payments-api", "triggered_by": "svc-ci", "dest_ip": "10.0.40.10",
         "duration_ms": 95_000, "is_internal_ip": 0, "is_night": 1, "events_1m": 30, "failed_builds_1m": 8,
         "failed_builds_5m": 26, "unique_projects_5m": 1, "oom_kills_5m": 0, "slow_steps_5m": 0,
         "dependency_404_1m": 0, "published_bytes_5m": 0, "rule_hits": "", "ml_score": 0.61,
         "recommended_action": "ok", "why_selected": "near_miss"}


def groq(verdicts, tokens=2000):
    """A stand-in for Groq: records the request, answers with `verdicts`."""
    calls = []

    def post(body, key):
        calls.append(body)
        return {"choices": [{"message": {"content": json.dumps({"verdicts": verdicts})}}],
                "usage": {"total_tokens": tokens}}
    post.calls = calls
    return post


def test_the_reviewer_sees_the_event_in_context():
    text = review.describe(EVENT)
    assert "external runner 102.67.14.98, night" in text and "26/5min" in text
    assert "build of payments-api succeeded after 95s" in text and "Model score 0.61" in text


def test_verdicts_become_reviews_labels_and_alerts():
    post = groq([{"id": "0", "verdict": "incident", "confidence": 0.95, "reason": "green after 26 failures: flaky, not fixed"}])
    reviews = review.review([EVENT], "key", "run1", post=post)
    body = post.calls[0]
    assert (body["model"], body["reasoning_effort"], body["stream"]) == (
        "openai/gpt-oss-safeguard-20b", "medium", False)
    [r] = reviews
    assert (r["verdict"], r["pipeline_action"], r["why_selected"]) == ("incident", "ok", "near_miss")
    [label] = review.labels_from(reviews)
    assert label["label"] == 1 and label["source"] == "reviewer" and label["weight"] < 1
    assert review.urgent(reviews) == reviews


def test_a_normal_verdict_on_a_model_only_alert_teaches_the_model_to_be_quieter():
    alert = {**EVENT, "recommended_action": "alert", "why_selected": "model_alert", "ml_score": 0.8,
             "ml_reason": "ml: failed_builds_5m"}
    reviews = review.review([alert], "k", "r", post=groq(
        [{"id": "0", "verdict": "normal", "confidence": 0.9, "reason": "an ordinary red build on a spot runner"}]))
    [label] = review.labels_from(reviews)
    assert label["label"] == 0 and review.urgent(reviews) == []


def test_an_answer_wrapped_in_prose_is_still_read():
    content = 'Here you go:\n```json\n{"verdicts": [{"id": "0", "verdict": "normal", ' \
              '"confidence": 0.7, "reason": "routine"}]}\n```'

    def post(body, key):
        return {"choices": [{"message": {"content": content}}]}
    assert review.ask([EVENT], "k", post=post)[0] == {0: ("normal", 0.7, "routine")}


def test_unsure_or_normal_verdicts_teach_nothing():
    for verdict, confidence in (("degraded", 0.5), ("normal", 0.99)):
        reviews = review.review([EVENT], "k", "r", post=groq(
            [{"id": "0", "verdict": verdict, "confidence": confidence, "reason": "x"}]))
        assert review.labels_from(reviews) == [] and review.urgent(reviews) == []


def test_malformed_or_missing_verdicts_are_dropped_not_guessed():
    post = groq([{"id": "0", "verdict": "probably fine", "confidence": 0.9},
                 {"id": "7", "verdict": "incident", "confidence": 0.9},
                 {"id": "0"}])
    assert review.review([EVENT], "k", "r", post=post) == []


def test_rate_limits_are_retried_when_the_server_says():
    waits = []
    answers = [urllib.error.HTTPError("u", 429, "slow down", {"retry-after": "7"}, None),
               {"choices": [{"message": {"content": json.dumps({"verdicts": []})}}]}]

    def post(body, key):
        answer = answers.pop(0)
        if isinstance(answer, Exception):
            raise answer
        return answer
    assert review.ask([EVENT], "k", post=post, sleep=waits.append) == ({}, 0)
    assert waits == [7.0]


class FakeTime:
    def __init__(self):
        self.now, self.waits = 0.0, []

    def clock(self):
        return self.now

    def sleep(self, seconds):
        self.waits.append(seconds)
        self.now += seconds


def test_every_page_fits_its_share_of_the_minute():
    rows = [EVENT] * 150
    cut = list(review.pages(rows))
    assert sum(len(p) for p in cut) == 150
    assert all(len(p) <= review.BATCH and review.page_cost(p) <= review.PAGE_TOKENS for p in cut)


def test_no_minute_ever_goes_over_the_limit():
    t = FakeTime()
    sent = []

    def post(body, key):
        sent.append((t.now, body))
        t.now += 3.0                                     # a call takes 3 s
        # The page costs about what was booked: no correction in our favour.
        cost = review.estimate_tokens(body["messages"][0]["content"] + body["messages"][1]["content"]) \
            + body["max_completion_tokens"]
        return {"choices": [{"message": {"content": '{"verdicts": []}'}}], "usage": {"total_tokens": cost}}

    review.review([EVENT] * 150, "k", "r", post=post, sleep=t.sleep, clock=t.clock)
    costs = [(at, review.estimate_tokens(b["messages"][0]["content"] + b["messages"][1]["content"])
              + b["max_completion_tokens"]) for at, b in sent]
    for start, _ in costs:
        in_minute = sum(c for at, c in costs if start <= at < start + 60)
        assert in_minute <= review.TOKENS_PER_MINUTE
    assert len(sent) == 15 and t.waits                  # paced, not refused


def test_cheap_answers_free_the_minute_for_the_next_page():
    t = FakeTime()

    def post(body, key):
        t.now += 3.0
        return {"choices": [{"message": {"content": '{"verdicts": []}'}}], "usage": {"total_tokens": 500}}
    review.review([EVENT] * 150, "k", "r", post=post, sleep=t.sleep, clock=t.clock)
    assert t.now < 120                                  # 15 pages in under two minutes


def test_what_was_judged_survives_groq_giving_up():
    calls = []

    def post(body, key):
        calls.append(body)
        if len(calls) > 1:
            raise urllib.error.HTTPError("u", 401, "no", {}, None)
        return {"choices": [{"message": {"content": json.dumps({"verdicts": [
            {"id": "0", "verdict": "normal", "confidence": 0.9, "reason": "x"}]})}}]}
    reviews = review.review([EVENT] * 15, "k", "r", post=post, sleep=lambda s: None)
    assert len(reviews) == 1 and len(calls) == 2


def test_an_unusable_api_is_reported():
    def post(body, key):
        raise urllib.error.HTTPError("u", 401, "bad key", {}, None)
    with pytest.raises(review.ReviewerUnavailable, match="401"):
        review.ask([EVENT], "k", post=post, sleep=lambda s: None)


class Budget:
    def __init__(self, used):
        self.used = used

    def value(self, sql, **params):
        return self.used


@pytest.mark.parametrize("used, caps", [
    (0, {"random": 30, "model_alert": 20, "near_miss": 50, "unusual": 50}),
    (2_900, {"random": 30, "model_alert": 20, "near_miss": 50, "unusual": 0}),
    (2_980, {"random": 20, "model_alert": 0, "near_miss": 0, "unusual": 0}),   # the random sample goes first
    (3_000, {"random": 0, "model_alert": 0, "near_miss": 0, "unusual": 0}),
])
def test_the_daily_budget(used, caps):
    assert review.budget(Budget(used)) == caps


# --- the guard: automatic rollback ------------------------------------------------------

class GuardClickHouse:
    def __init__(self, history, reviewed, false_alarms):
        self.history, self.stats = history, {"reviewed": reviewed, "false_alarms": false_alarms}
        self.inserted = []

    def rows(self, sql, **params):
        if "ml_model_active" in sql:
            return [{"version": v} for v in self.history]
        return [self.stats]

    def insert(self, table, rows):
        self.inserted.extend(rows)


def test_a_model_whose_alerts_are_mostly_false_alarms_is_rolled_back():
    ch = GuardClickHouse(["v3", "v2", "v1"], reviewed=30, false_alarms=21)
    rolled = training.guard(ch)
    assert (rolled["from"], rolled["to"]) == ("v3", "v2")
    assert ch.inserted[0]["version"] == "v2" and "21 of 30" in ch.inserted[0]["reason"]


@pytest.mark.parametrize("history, reviewed, false_alarms", [
    (["v3", "v2"], 30, 12),     # mostly right: kept
    (["v3", "v2"], 10, 9),      # too few reviewed to judge
    (["v1"], 30, 29),           # nothing to roll back to
])
def test_the_guard_leaves_a_model_alone_otherwise(history, reviewed, false_alarms):
    ch = GuardClickHouse(history, reviewed, false_alarms)
    assert training.guard(ch) is None and ch.inserted == []


def test_requests_carry_a_user_agent(monkeypatch):
    # Without one, Groq's firewall answers 403 (error 1010) to every call.
    seen = {}

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def read(self):
            return b'{"choices": []}'

    def urlopen(request, timeout):
        seen.update(request.headers)
        return Response()
    monkeypatch.setattr(review.urllib.request, "urlopen", urlopen)
    review._post({"model": "m"}, "k")
    assert seen["User-agent"] == review.USER_AGENT
