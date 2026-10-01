"""core/ml and stream/models: the model inside the stream.

A hand-written two-tree model pins the policy (what the model may decide
on its own) without LightGBM; where LightGBM is installed, a trained model
proves the compiled scorer gives LightGBM's own numbers.
"""

import json

import pytest

from core import ml
from core.rules import score_event
from stream.models import ModelSource

F = ml.FEATURES.index


def leaf(value):
    return {"leaf_value": value}


def split(feature, threshold, left, right, value=0.0):
    return {"split_feature": F(feature), "threshold": threshold, "decision_type": "<=",
            "left_child": left, "right_child": right, "internal_value": value}


# Raw score: -4 for a quiet event; +6 with 20+ failed builds in 5 minutes
# (p ~0.88), a little more at night.
DUMP = {
    "objective": "binary sigmoid:1",
    "feature_names": list(ml.FEATURES),
    "tree_info": [
        {"tree_structure": split("failed_builds_5m", 19.5, leaf(-4.0), leaf(2.0), value=-3.0)},
        {"tree_structure": split("is_night", 0.5, leaf(0.0), leaf(0.5), value=0.1)},
    ],
}

QUIET = {"event_type": "BUILD_FAILURE", "failed_builds_5m": 3, "is_night": 0}
NOISY = {"event_type": "BUILD_FAILURE", "failed_builds_5m": 25, "is_night": 0}


def scored(event, model):
    event = score_event(dict(event))
    return ml.apply(event, model)


def test_the_compiled_model_follows_its_trees():
    model = ml.Model(DUMP, "v1")
    assert model.score(QUIET) == pytest.approx(1 / (1 + 2.718281828 ** 4))
    assert model.score(NOISY) == pytest.approx(1 / (1 + 2.718281828 ** -2))


def test_no_model_means_rules_alone():
    event = scored(NOISY, None)
    assert (event["ml_score"], event["ml_model"], event["ml_reason"]) == (0.0, "", "")


def test_the_model_alone_can_alert_but_not_quarantine(monkeypatch):
    monkeypatch.setattr(ml, "ML_CAN_QUARANTINE", False)
    # 25 failures in 5 min is below the failure-storm rule's 1-minute line:
    # no rule fires, the model says 0.88.
    event = scored(NOISY, ml.Model(DUMP, "v1"))
    assert event["rule_hits"] == "" and event["ml_score"] > 0.85
    assert event["recommended_action"] == "alert"
    assert event["ml_reason"] == "ml: failed_builds_5m"


def test_it_can_quarantine_once_allowed_to(monkeypatch):
    monkeypatch.setattr(ml, "ML_CAN_QUARANTINE", True)
    assert scored(NOISY, ml.Model(DUMP, "v1"))["recommended_action"] == "quarantine"


def test_the_model_never_lowers_what_a_rule_decided():
    crash = {"event_type": "COMPILE_STEP", "failure_signature": "ice", "is_failure_signature": 1}
    event = scored(crash, ml.Model(DUMP, "v1"))      # the model sees nothing wrong
    assert event["ml_score"] < 0.1 and event["recommended_action"] == "quarantine"
    assert event["ml_reason"] == ""                  # the rules decided, not the model


def test_a_higher_score_on_a_rule_decided_quarantine_is_not_the_models_decision(monkeypatch):
    # A quarantine-level rule fired (failure storm, 0.90); the model scores
    # the event higher still. The decision is the rule's: no ml_reason.
    monkeypatch.setattr(ml, "ML_CAN_QUARANTINE", False)
    event = scored({**NOISY, "failed_builds_1m": 25, "is_night": 1}, ml.Model(DUMP, "v1"))   # model ~0.92
    assert event["rule_hits"] and event["recommended_action"] == "quarantine"
    assert event["ml_score"] > event["rule_score"] and event["ml_reason"] == ""


def test_raising_an_alert_level_rule_to_quarantine_is_the_models_decision(monkeypatch):
    # A lone untrusted fetch alerts (0.70); the model, sure, takes it to
    # quarantine -- allowed, a rule agrees -- and says why.
    monkeypatch.setattr(ml, "ML_CAN_QUARANTINE", False)
    probe = {**NOISY, "event_type": "DEPENDENCY_FETCH", "is_untrusted_fetch": 1, "http_status": 200}
    event = scored(probe, ml.Model(DUMP, "v1"))
    assert event["rule_hits"] == "untrusted_fetch" and event["recommended_action"] == "quarantine"
    assert event["ml_reason"].startswith("ml: ")


def test_a_model_trained_on_other_features_is_refused():
    with pytest.raises(ValueError, match="different features"):
        ml.Model({**DUMP, "feature_names": ["a", "b"]}, "v0")


# --- the job's model source ----------------------------------------------------

class Fetch:
    def __init__(self, active):
        self.active = active
        self.models_fetched = 0

    def __call__(self, sql, **params):
        if "ml_model_active" in sql:
            if isinstance(self.active, Exception):
                raise self.active
            return self.active + "\n"
        self.models_fetched += 1
        return json.dumps(DUMP)


def test_the_model_is_fetched_once_per_version_and_polled_sparingly():
    fetch = Fetch("v1")
    source = ModelSource(fetch, enabled=True)
    assert source.refresh(0).version == "v1"
    fetch.active = "v2"
    assert source.refresh(1_000).version == "v1"              # not due yet
    assert source.refresh(10**9).version == "v2"              # due: the new one
    assert fetch.models_fetched == 2


def test_clickhouse_down_keeps_the_current_model():
    fetch = Fetch("v1")
    source = ModelSource(fetch, enabled=True)
    source.refresh(0)
    fetch.active = OSError("connection refused")
    assert source.refresh(10**9).version == "v1"


def test_the_kill_switch():
    assert ModelSource(Fetch("v1"), enabled=False).refresh(0) is None


# --- against LightGBM itself ---------------------------------------------------------

def test_compiled_scores_equal_lightgbm():
    lgb = pytest.importorskip("lightgbm")
    np = pytest.importorskip("numpy")
    rng = np.random.default_rng(3)
    x = rng.gamma(1.0, 4.0, size=(3000, len(ml.FEATURES)))
    y = (x[:, F("failed_builds_5m")] + x[:, F("distinct_exit_codes_5m")] > 12).astype(int)
    booster = lgb.train({"objective": "binary", "num_leaves": 15, "verbose": -1},
                        lgb.Dataset(x, y, feature_name=list(ml.FEATURES)), num_boost_round=50)
    model = ml.Model(booster.dump_model(), "t")
    for row, want in zip(x[:300], booster.predict(x[:300])):
        assert model._raw(list(map(float, row))) == pytest.approx(np.log(want / (1 - want)), abs=1e-9)


def test_a_production_size_model_fits_the_budget_many_times_over():
    """At 1,000 events/s an event has 1 ms, end to end. The model may use a
    small part of it: ~8 us measured for 120 trees (tools/bench_detection.py);
    this fails far below the budget, well above noise."""
    import time

    lgb = pytest.importorskip("lightgbm")
    np = pytest.importorskip("numpy")
    rng = np.random.default_rng(9)
    x = rng.gamma(1.0, 4.0, size=(5000, len(ml.FEATURES)))
    y = (x[:, F("failed_builds_5m")] * x[:, F("is_night")] + x[:, F("distinct_exit_codes_5m")] > 14).astype(int)
    booster = lgb.train({"objective": "binary", "num_leaves": 15, "verbose": -1, "min_data_in_leaf": 5},
                        lgb.Dataset(x, y, feature_name=list(ml.FEATURES)), num_boost_round=120)
    model = ml.Model(booster.dump_model(), "size")
    events = [dict(zip(ml.FEATURES, map(float, row))) for row in x[:2000]]
    t0 = time.perf_counter()
    for event in events:
        model.score(event)
    per_event_us = (time.perf_counter() - t0) / len(events) * 1e6
    assert per_event_us < 100, f"{per_event_us:.1f} us per event"
