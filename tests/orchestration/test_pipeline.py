"""orchestration/ops/pipeline.py: the end-to-end verdict, without a pipeline.

The Flink REST API, the clock and ClickHouse are stand-ins, so every path
of ensure_stream_job -- running, waiting, restarting, giving up -- is
driven directly.
"""

import pytest

from etl import config
from orchestration.ops import pipeline


def jobs(*states, running=2, total=2):
    """A /jobs/overview answer: one stream job per state, newest last."""
    return {"jobs": [{"name": pipeline.FLINK_JOB, "state": s, "jid": f"j{i}", "start-time": i,
                      "tasks": {"running": running if s == "RUNNING" else 0, "total": total}}
                     for i, s in enumerate(states)]}


class Flink:
    """Answers /jobs/overview from a script, one answer per call; None
    means unreachable. The last answer repeats."""

    def __init__(self, *answers):
        self.answers = list(answers)

    def __call__(self, url):
        answer = self.answers.pop(0) if len(self.answers) > 1 else self.answers[0]
        if answer is None:
            raise OSError("connection refused")
        return answer


class Clock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now

    def sleep(self, seconds):
        self.now += seconds


def ensure(flink, restart=lambda: None, wait_s=60):
    clock = Clock()
    return pipeline.ensure_stream_job(wait_s=wait_s, poll_s=10, get_json=flink, restart=restart,
                                      sleep=clock.sleep, clock=clock)


class Restarts:
    def __init__(self):
        self.calls = 0

    def __call__(self):
        self.calls += 1


# --- the stream job ------------------------------------------------------------

def test_a_running_job_passes_at_once():
    [r] = ensure(Flink(jobs("RUNNING")))
    assert r["passed"] and "RUNNING" in r["detail"]


def test_a_running_job_wins_over_an_older_failed_one():
    assert pipeline.stream_job_state(Flink(jobs("FAILED", "RUNNING")))[0] == "RUNNING"
    assert pipeline.stream_job_state(Flink(jobs("RUNNING", "FAILED")))[0] == "RUNNING"


def test_a_restarting_job_is_waited_for_not_restarted():
    restarts = Restarts()
    results = ensure(Flink(jobs("RESTARTING"), None, jobs("RUNNING")), restart=restarts)
    assert [r["passed"] for r in results] == [True] and restarts.calls == 0


def test_running_without_its_tasks_is_not_running():
    # No TaskManager: Flink says RUNNING, its tasks wait for a slot.
    starved = jobs("RUNNING", running=0)
    assert pipeline.stream_job_state(Flink(starved))[0] == pipeline.DEPLOYING
    [r] = ensure(Flink(starved))
    assert not r["passed"] and "DEPLOYING" in r["detail"]
    # ...until a TaskManager arrives.
    [r] = ensure(Flink(starved, jobs("RUNNING")))
    assert r["passed"]


def test_a_failed_job_is_reported_where_restarts_are_off(monkeypatch):
    monkeypatch.setattr(pipeline, "FLINK_RESTART", "none")
    restarts = Restarts()
    [r] = ensure(Flink(jobs("FAILED")), restart=restarts)
    assert not r["passed"] and "docker compose restart flink-jobmanager" in r["detail"]
    assert restarts.calls == 0


def test_a_failed_job_is_restarted_through_the_operator(monkeypatch):
    monkeypatch.setattr(pipeline, "FLINK_RESTART", "operator")
    restarts = Restarts()
    # FAILED -> (restart) -> JobManager replaced, unreachable -> RUNNING
    results = ensure(Flink(jobs("FAILED"), None, None, jobs("RUNNING")), restart=restarts)
    assert restarts.calls == 1
    running, restarted = results
    assert running["passed"] and running["severity"] == "fail"
    # Recorded, visible, but it does not fail the stage: the job is back.
    assert restarted["check_name"] == "restarted" and restarted["severity"] == "warn"
    assert pipeline.failures(results) == []


def test_restarted_only_once_per_run(monkeypatch):
    monkeypatch.setattr(pipeline, "FLINK_RESTART", "operator")
    restarts = Restarts()
    [r] = ensure(Flink(jobs("FAILED")), restart=restarts)
    assert restarts.calls == 1 and not r["passed"]


def test_an_unreachable_jobmanager_fails_after_the_wait():
    [r] = ensure(Flink(None))
    assert not r["passed"] and "unreachable" in r["detail"]


# --- extract / transform / load ----------------------------------------------------

def sample(arriving=100.0, scored=99.0, refused=0.0, stream_lag=500, intake_lag=10, dq=None):
    return {
        "seconds": 20.0,
        "rate": {config.KAFKA_TOPIC: arriving, config.SCORED_TOPIC: scored, config.REJECTED_TOPIC: refused},
        "lag": {config.CONSUMER_GROUP: stream_lag, pipeline.CLICKHOUSE_GROUP: intake_lag},
        "dq": dq,
    }


def by_name(results):
    return {r["check_name"]: r for r in results}


def test_extract_fails_when_nothing_arrives():
    r = by_name(pipeline.judge_extract(sample(arriving=0.0, scored=0.0), min_rate=1.0))
    assert not r["input_rate"]["passed"]
    assert r["rejected_share"]["value"] is None and r["rejected_share"]["passed"]


def test_transform_lag_is_in_seconds_of_traffic():
    # 500 events waiting at 100/s: 5 s behind -- one checkpoint interval.
    r = by_name(pipeline.judge_transform(sample()))
    assert r["lag_seconds"]["value"] == 5.0 and r["lag_seconds"]["passed"]
    r = by_name(pipeline.judge_transform(sample(stream_lag=100 * 300)))
    assert not r["lag_seconds"]["passed"]


def test_transform_fails_when_flink_stops_writing():
    r = by_name(pipeline.judge_transform(sample(scored=0.0)))
    assert r["output_ratio"]["value"] == 0.0 and not r["output_ratio"]["passed"]


def test_rejected_results_count_as_written():
    r = by_name(pipeline.judge_transform(sample(scored=60.0, refused=40.0)))
    assert r["output_ratio"]["value"] == 1.0


# --- data quality between the steps ------------------------------------------------

def test_doubtful_events_warn_with_the_culprits_named():
    dq = {"scored": 1000.0, "normalize_missing_project": 50.0, "enrich_unknown_region": 5.0,
          "features_window_inconsistent": 0.0}
    r = by_name(pipeline.judge_transform(sample(dq=dq)))
    assert r["doubtful_share"]["value"] == 0.055 and not r["doubtful_share"]["passed"]
    assert "normalize_missing_project 50, enrich_unknown_region 5" in r["doubtful_share"]["detail"]
    assert pipeline.failures(list(r.values())) == []          # a warning, not a failure


def test_one_inconsistent_decision_fails_transform():
    r = by_name(pipeline.judge_transform(sample(dq={"scored": 1000.0, "rules_action_mismatch": 1.0})))
    assert not r["logic_inconsistent"]["passed"] and r["logic_inconsistent"]["severity"] == "fail"


def test_unreadable_counters_are_not_judged():
    r = by_name(pipeline.judge_transform(sample(dq=None)))
    assert r["doubtful_share"]["passed"] and r["logic_inconsistent"]["passed"]


def test_dq_counters_sum_every_subtask():
    base = pipeline.FLINK_REST_URL + "/jobs/j0"
    answers = {
        pipeline.FLINK_REST_URL + "/jobs/overview": jobs("RUNNING"),
        base: {"vertices": [{"id": "v1"}, {"id": "v2"}]},
        base + "/vertices/v1/metrics": [{"id": "0.parse.watchtower.dq_normalize_missing_project"},
                                        {"id": "1.parse.watchtower.dq_normalize_missing_project"},
                                        {"id": "0.parse.numRecordsIn"}],
        base + "/vertices/v1/metrics?get=0.parse.watchtower.dq_normalize_missing_project,"
               "1.parse.watchtower.dq_normalize_missing_project":
            [{"id": "0.parse.watchtower.dq_normalize_missing_project", "value": "3"},
             {"id": "1.parse.watchtower.dq_normalize_missing_project", "value": "4"}],
        base + "/vertices/v2/metrics": [{"id": "0.rules.watchtower.scored_events"}],
        base + "/vertices/v2/metrics?get=0.rules.watchtower.scored_events":
            [{"id": "0.rules.watchtower.scored_events", "value": "900"}],
    }
    assert pipeline.dq_counters(answers.__getitem__) == {"normalize_missing_project": 7.0, "scored": 900.0}


class FakeClickHouse:
    def __init__(self, values=None, rows=None):
        self.values = values or {}
        self._rows = rows or []

    def value(self, sql, **params):
        return next(v for key, v in self.values.items() if key in sql)

    def rows(self, sql, **params):
        return self._rows


LOAD = {"count()": 5000, "quantile": 180.0, "kafka_consumers": 0}


def test_load_passes_when_rows_land():
    results = pipeline.judge_load(sample(), FakeClickHouse(LOAD), min_rate=1.0)
    assert pipeline.failures(results) == []


def test_load_fails_when_no_rows_land():
    ch = FakeClickHouse({**LOAD, "count()": 0})
    r = by_name(pipeline.judge_load(sample(), ch, min_rate=1.0))
    assert not r["rows_last_minute"]["passed"]


def test_no_input_is_not_blamed_on_load():
    ch = FakeClickHouse({**LOAD, "count()": 0})
    r = by_name(pipeline.judge_load(sample(arriving=0.0, scored=0.0), ch, min_rate=1.0))
    assert r["rows_last_minute"]["passed"] and r["rows_last_minute"]["value"] is None


def test_slow_rows_and_intake_errors_only_warn():
    ch = FakeClickHouse({**LOAD, "quantile": 9000.0, "kafka_consumers": 1})
    results = pipeline.judge_load(sample(), ch, min_rate=1.0)
    assert pipeline.failures(results) == []
    assert {r["check_name"] for r in results if not r["passed"]} == {"latency_p95_ms", "intake_errors"}


# --- the verdict other DAGs wait for ------------------------------------------------

@pytest.mark.parametrize("rows, healthy", [
    ([], False),                                                     # no recent run
    ([{"run_id": "r", "at": "x", "failed": 0, "load_checks": 4}], True),
    ([{"run_id": "r", "at": "x", "failed": 1, "load_checks": 4}], False),
    ([{"run_id": "r", "at": "x", "failed": 0, "load_checks": 0}], False),  # stopped before load
])
def test_healthy_recently(rows, healthy):
    assert pipeline.healthy_recently(FakeClickHouse(rows=rows)) is healthy
