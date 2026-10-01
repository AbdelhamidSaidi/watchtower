"""Data quality between the transformation steps, per event, in the stream.

    decode -> validate -> normalize -> enrich -> features -> rules
            ^          ^           ^         ^           ^
          reason    defaulted   unknown   window      score/action
          counted   fields      country,  counters    consistent
                                clock     consistent

Each function looks at one step's output and returns the names of what is
wrong with it -- almost always an empty tuple. They never change or drop an
event: validate already refuses what cannot be scored; these count what
got through but is doubtful, so a runner that starts sending events without
a project, or a clock gone wrong, shows as a rising counter instead of quietly
weaker detection.

Cheap by design: a few comparisons on fields already in hand, ~1-2 us per
event against the ~173 us the job spends (docs/streaming.md). The job counts
the names (etl/stream/job.py, `dq_<step>_<issue>`); Prometheus alerts on
them and the Airflow pipeline DAG reads them.
"""

from core.vocab import DEFAULT_SEVERITY
from core.rules import action_for

# Event types that belong to a project's build: without a project they
# cannot feed per-project features (unique_projects_5m) or the engineer's
# question "whose build".
PROJECT_EVENTS = frozenset({"BUILD_STARTED", "BUILD_SUCCESS", "BUILD_FAILURE", "COMPILE_STEP", "TEST_RUN"})

# Event time further than this from the job's clock is a clock problem at
# the source (future) or a delivery problem (old): features and the
# 1- and 5-minute windows assume roughly current events.
FUTURE_MS = 5 * 60_000
STALE_MS = 24 * 3_600_000

ISSUES = {
    "normalize": ("severity_defaulted", "missing_project", "missing_hostname"),
    "enrich": ("unknown_region", "future_timestamp", "stale_timestamp"),
    "features": ("window_inconsistent",),
    "rules": ("score_out_of_range", "action_mismatch"),
}


def after_normalize(raw_severity, event):
    issues = ()
    # normalize() replaces a missing or unknown severity with the default.
    if (raw_severity or "").strip().upper() != event["severity"] and event["severity"] == DEFAULT_SEVERITY:
        issues += ("severity_defaulted",)
    if event["event_type"] in PROJECT_EVENTS and not event["project"]:
        issues += ("missing_project",)
    if not event["hostname"]:
        issues += ("missing_hostname",)
    return issues


def after_enrich(event, now_ms, ts_ms):
    issues = ()
    # An external runner the inventory does not place: the region
    # indicator is blank for it.
    if not event["is_internal_ip"] and not event["region"]:
        issues += ("unknown_region",)
    if ts_ms - now_ms > FUTURE_MS:
        issues += ("future_timestamp",)
    elif now_ms - ts_ms > STALE_MS:
        issues += ("stale_timestamp",)
    return issues


def after_features(row):
    # The 1-minute window is inside the 5-minute one, and an event always
    # counts itself: anything else is a window bug or corrupted state.
    if row["failed_builds_1m"] > row["failed_builds_5m"] or row["events_1m"] < 1:
        return ("window_inconsistent",)
    return ()


def after_rules(row):
    score = row["final_anomaly_score"]
    if not 0.0 <= score <= 1.0:
        return ("score_out_of_range",)
    if row["recommended_action"] != action_for(score):
        return ("action_mismatch",)
    return ()
