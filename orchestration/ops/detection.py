"""Detection quality, measured on a schedule.

Runs tools/evaluate_detection.py against the live pipeline -- the synthetic
producer's ground truth joined to the decisions in ClickHouse -- and judges
the report against thresholds. Only meaningful where the synthetic
producer is the traffic (WATCHTOWER_SYNTHETIC_TRAFFIC=true).
"""

import json

from etl import config

# What a healthy run looks like. The thresholds were set on the Flink path
# at 1,000 events/s over 15 minutes with the earlier (security-log)
# simulator: coverage 100%, every incident caught, the first flag 0.4-1.6 s
# in, under 0.001% of normal events quarantined on uninvolved runners. They
# have not been re-measured on build-farm traffic (`make evaluate`); the
# simulator's incidents are tuned to the same rates, so they should hold.
#
# Incidents are judged one by one -- was each caught, and how fast -- not by
# the share of incident EVENTS flagged. That share depends on the mix: a
# behavioural rule needs its first few events (20 for a failure storm, 8
# projects for a broken toolchain) before it can fire, so a window holding
# two small incidents can come out well under 100% with both caught within
# seconds. It is reported, not gated.
THRESHOLDS = {
    # Every event read from Kafka has a decision in ClickHouse.
    "min_coverage": 0.999,
    "max_missed_incidents": 0,
    # From an incident's first event to its first flag, for runners with no
    # incident in the 5 minutes before (tools/evaluate_detection.py).
    "max_median_time_to_flag_s": 5.0,
    # Normal traffic quarantined on runners that were NOT affected.
    "max_uninvolved_quarantined_share": 0.0001,
}


def run(minutes):
    from tools import evaluate_detection

    return evaluate_detection.evaluate(
        kafka=config.KAFKA_BOOTSTRAP_SERVERS,
        topic=config.KAFKA_TOPIC,
        registry=config.SCHEMA_REGISTRY_URL,
        clickhouse=f"http://{config.CLICKHOUSE_HOST}:{config.CLICKHOUSE_PORT}",
        password=config.clickhouse_password(),
        minutes=minutes,
    )


def assess(report, thresholds=None):
    """What is wrong with this report, as sentences. Empty means passed."""
    t = {**THRESHOLDS, **(thresholds or {})}
    s = report["summary"]
    if not report["window"]["events"]:
        return ["no events in the window -- is the producer running?"]

    failures = []
    if s["coverage"] is not None and s["coverage"] < t["min_coverage"]:
        failures.append(f"coverage {s['coverage']:.4%} < {t['min_coverage']:.4%}: "
                        "events in Kafka without a decision in ClickHouse")
    # A window without incidents says nothing about catching them.
    if s["incidents_seen"]:
        missed = s["incidents_seen"] - s["incidents_caught"]
        if missed > t["max_missed_incidents"]:
            failures.append(f"{missed} of {s['incidents_seen']} incidents never flagged")
        median = s["median_time_to_flag_s"]
        if median is not None and median > t["max_median_time_to_flag_s"]:
            failures.append(f"median time to first flag {median:.1f} s "
                            f"> {t['max_median_time_to_flag_s']:.1f} s")
    if s["normal_events"]:
        share = s["normal_quarantined_uninvolved"] / s["normal_events"]
        if share > t["max_uninvolved_quarantined_share"]:
            failures.append(f"normal events quarantined on uninvolved runners {share:.4%} "
                            f"> {t['max_uninvolved_quarantined_share']:.4%} "
                            f"({s['normal_quarantined_uninvolved']} of {s['normal_events']})")
    return failures


def row(report, failures, run_id):
    """The report as a watchtower.detection_quality row."""
    s = report["summary"]
    return {
        "run_id": run_id,
        "window_minutes": report["window"]["minutes"],
        "events": report["window"]["events"],
        "coverage": s["coverage"],
        "incidents_seen": s["incidents_seen"],
        "incidents_caught": s["incidents_caught"],
        "incident_events_flagged": s["incident_flagged"],
        "incident_events_quarantined": s["incident_quarantined"],
        "normal_quarantined": s["normal_quarantined"],
        "normal_quarantined_uninvolved": s["normal_quarantined_uninvolved"],
        "normal_events": s["normal_events"],
        "precision_quarantine": s["precision_quarantine"],
        "median_time_to_flag_s": s["median_time_to_flag_s"],
        "passed": 0 if failures else 1,
        "failures": failures,
        "report": json.dumps(report),
    }
