"""core/dq: the checks between transformation steps.

A clean event must pass every boundary silently -- the counters are only
worth watching if normal traffic keeps them at zero -- and each doubtful
case must be named at the step where it becomes visible.
"""

from datetime import datetime, timezone

import pytest

from conftest import make_event
from core import dq
from core.processor import SourceState
from core.records import enrich, normalize, reject_reason

NOW_MS = int(datetime(2026, 9, 20, 14, 0, 1, tzinfo=timezone.utc).timestamp() * 1000)


def through(**overrides):
    """An event through validate/normalize/enrich, with each boundary's issues."""
    event = {k: v for k, v in make_event(**overrides).items() if k != "scenario"}
    assert reject_reason(event) is None
    raw_severity = event.get("severity")
    normalized = normalize(event)
    after_normalize = dq.after_normalize(raw_severity, normalized)
    enriched = enrich(normalized)
    ts_ms = int(enriched["_ts"].timestamp() * 1000)
    return enriched, after_normalize, dq.after_enrich(enriched, NOW_MS, ts_ms)


def test_a_clean_event_passes_every_boundary():
    event, normalized, enriched = through()
    row = SourceState().process(event)
    assert (normalized, enriched, dq.after_features(row), dq.after_rules(row)) == ((), (), (), ())


@pytest.mark.parametrize("severity", [None, "", "loud"])
def test_a_missing_or_unknown_severity_is_counted_as_defaulted(severity):
    _, issues, _ = through(severity=severity)
    assert "severity_defaulted" in issues


def test_a_build_without_a_project():
    _, issues, _ = through(project="")
    assert "missing_project" in issues


def test_a_dependency_fetch_needs_no_project():
    _, issues, _ = through(project="", event_type="DEPENDENCY_FETCH")
    assert "missing_project" not in issues


def test_an_external_runner_the_inventory_cannot_place():
    _, _, issues = through(runner_ip="203.0.113.7")
    assert "unknown_region" in issues


@pytest.mark.parametrize("timestamp, issue", [
    ("2026-09-20T14:30:00+00:00", "future_timestamp"),     # 30 min ahead of the job's clock
    ("2026-09-18T14:00:00+00:00", "stale_timestamp"),      # two days late
])
def test_event_time_far_from_the_job_clock(timestamp, issue):
    _, _, issues = through(timestamp=timestamp)
    assert issues == (issue,)


def test_windows_must_nest():
    assert dq.after_features({"failed_builds_1m": 3, "failed_builds_5m": 2, "events_1m": 5}) == \
        ("window_inconsistent",)
    assert dq.after_features({"failed_builds_1m": 0, "failed_builds_5m": 0, "events_1m": 0}) == \
        ("window_inconsistent",)


@pytest.mark.parametrize("row, issue", [
    ({"final_anomaly_score": 1.5, "recommended_action": "quarantine"}, "score_out_of_range"),
    ({"final_anomaly_score": 0.9, "recommended_action": "ok"}, "action_mismatch"),
])
def test_the_decision_must_follow_the_score(row, issue):
    assert dq.after_rules(row) == (issue,)


def test_every_named_issue_is_declared():
    # The job registers dq.ISSUES up front so each exports 0 before it fires.
    declared = {i for issues in dq.ISSUES.values() for i in issues}
    assert {"severity_defaulted", "missing_project", "missing_hostname", "unknown_region",
            "future_timestamp", "stale_timestamp", "window_inconsistent",
            "score_out_of_range", "action_mismatch"} == declared
