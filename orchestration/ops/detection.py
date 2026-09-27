"""Detection quality, measured on a schedule.

Runs tools/evaluate_detection.py against the live pipeline -- the synthetic
producer's ground truth joined to the decisions in ClickHouse -- and judges
the report against thresholds. Only meaningful where the synthetic
producer is the traffic (WATCHTOWER_SYNTHETIC_TRAFFIC=true).
"""

import json

from etl import config

# What a healthy run looks like. Measured on the Flink path at 1,000
# events/s over 15 minutes: coverage 100%, 29/29 attacks caught, the first
# flag 0.4-1.6 s into an attack, 7 of 868,112 normal events blocked on
# uninvolved hosts (0.0008%). The thresholds leave room below that.
#
# Attacks are judged one by one -- was each caught, and how fast -- not by
# the share of attack EVENTS flagged. That share depends on the mix: a
# behavioural rule needs its first few events (7 for lateral movement, 19
# for a password spray) before it can fire, so a window holding two small
# attacks came out at 91.9% with both caught within 1.5 s, while the
# 29-attack window above came out at 99.3%. It is reported, not gated.
THRESHOLDS = {
    # Every event read from Kafka has a decision in ClickHouse.
    "min_coverage": 0.999,
    "max_missed_attacks": 0,
    # From an attack's first event to its first flag, for sources with no
    # attack in the 5 minutes before (tools/evaluate_detection.py).
    "max_median_time_to_flag_s": 5.0,
    # Normal traffic blocked on hosts that were NOT attacking.
    "max_uninvolved_blocked_share": 0.0001,
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
    # A window without attacks says nothing about catching them.
    if s["attacks_seen"]:
        missed = s["attacks_seen"] - s["attacks_caught"]
        if missed > t["max_missed_attacks"]:
            failures.append(f"{missed} of {s['attacks_seen']} attacks never flagged")
        median = s["median_time_to_flag_s"]
        if median is not None and median > t["max_median_time_to_flag_s"]:
            failures.append(f"median time to first flag {median:.1f} s "
                            f"> {t['max_median_time_to_flag_s']:.1f} s")
    if s["normal_events"]:
        share = s["normal_blocked_uninvolved"] / s["normal_events"]
        if share > t["max_uninvolved_blocked_share"]:
            failures.append(f"normal events blocked on uninvolved hosts {share:.4%} "
                            f"> {t['max_uninvolved_blocked_share']:.4%} "
                            f"({s['normal_blocked_uninvolved']} of {s['normal_events']})")
    return failures


def row(report, failures, run_id):
    """The report as a watchtower.detection_quality row."""
    s = report["summary"]
    return {
        "run_id": run_id,
        "window_minutes": report["window"]["minutes"],
        "events": report["window"]["events"],
        "coverage": s["coverage"],
        "attacks_seen": s["attacks_seen"],
        "attacks_caught": s["attacks_caught"],
        "attack_events_flagged": s["attack_flagged"],
        "attack_events_blocked": s["attack_blocked"],
        "normal_blocked": s["normal_blocked"],
        "normal_blocked_uninvolved": s["normal_blocked_uninvolved"],
        "normal_events": s["normal_events"],
        "precision_block": s["precision_block"],
        "median_time_to_flag_s": s["median_time_to_flag_s"],
        "passed": 0 if failures else 1,
        "failures": failures,
        "report": json.dumps(report),
    }
