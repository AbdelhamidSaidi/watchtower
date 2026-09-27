"""Hourly data-quality checks on what the stream stored.

Prometheus (deploy/observability/alerts.yml) watches the PIPELINE: is the
job up, is it keeping up, how long does an event take. These checks watch
the DATA it wrote, one closed hour at a time: was anything stored, did too
much get refused, are rows complete, did the share of blocks jump.

Each check is one SQL query returning one number, compared to a threshold.
  fail  -- the DAG run fails (and alerts, via Airflow's own notifications)
  warn  -- recorded in watchtower.data_quality_checks, nothing more
"""

import math
import operator
from dataclasses import dataclass
from datetime import timezone

EVENTS = "watchtower.security_events"
# Parameters arrive as strings and are read as UTC here, whatever the
# server's own timezone.
START = "toDateTime64({start:String}, 3, 'UTC')"
END = "toDateTime64({end:String}, 3, 'UTC')"
IN_HOUR = f"timestamp >= {START} AND timestamp < {END}"

OPS = {"<=": operator.le, ">=": operator.ge, "==": operator.eq}


@dataclass(frozen=True)
class Check:
    name: str
    severity: str
    op: str
    threshold: float
    description: str
    sql: str


CHECKS = (
    Check("volume", "fail", ">=", 1,
          "events stored for the hour",
          f"SELECT count() FROM {EVENTS} WHERE {IN_HOUR}"),

    # Refused messages carry Kafka's append time, not an event time: the
    # message may not have had a readable one.
    Check("rejected_share", "fail", "<=", 0.01,
          "share of the hour's messages refused into rejected_events",
          "SELECT r / nullIf(r + e, 0) FROM ("
          " SELECT (SELECT count() FROM watchtower.rejected_events"
          f"         WHERE kafka_timestamp >= {START} AND kafka_timestamp < {END}) AS r,"
          f"        (SELECT count() FROM {EVENTS} WHERE {IN_HOUR}) AS e)"),

    # Detection is keyed by source_ip; an event without one, or without a
    # type, was scored against nothing.
    Check("missing_identity", "fail", "==", 0,
          "events with an empty source_ip or event_type",
          f"SELECT countIf(source_ip = '' OR event_type = '') FROM {EVENTS} WHERE {IN_HOUR}"),

    # Hourly and looser than the StreamLatencyHigh alert: a slow hour that
    # the alert missed, e.g. while Prometheus was down.
    Check("latency_p95_ms", "warn", "<=", 2000,
          "p95 of ingested_at - timestamp, milliseconds",
          "SELECT quantile(0.95)(toUnixTimestamp64Milli(ingested_at) - toUnixTimestamp64Milli(timestamp)) "
          f"FROM {EVENTS} WHERE {IN_HOUR}"),

    # At-least-once delivery stores a replayed event twice until
    # ReplacingMergeTree merges the copies. Some is normal after a restart;
    # a lot means the job is restarting over and over.
    Check("duplicate_share", "warn", "<=", 0.01,
          "share of rows that are copies not yet merged away",
          f"SELECT (a - f) / nullIf(a, 0) FROM ("
          f" SELECT (SELECT count() FROM {EVENTS} WHERE {IN_HOUR}) AS a,"
          f"        (SELECT count() FROM {EVENTS} FINAL WHERE {IN_HOUR}) AS f)"),

    # Five times the usual share of blocks is either an attack wave or a
    # rule gone wrong. Either way a human should look.
    Check("block_share_vs_7d", "warn", "<=", 5.0,
          "the hour's share of blocks, as a multiple of the trailing 7 days'",
          "SELECT h / nullIf(w, 0) FROM ("
          " SELECT (SELECT countIf(recommended_action = 'block') / nullIf(count(), 0)"
          f"         FROM {EVENTS} WHERE {IN_HOUR}) AS h,"
          "        (SELECT countIf(recommended_action = 'block') / nullIf(count(), 0)"
          f"         FROM {EVENTS}"
          f"         WHERE timestamp >= {START} - INTERVAL 7 DAY AND timestamp < {START}) AS w)"),
)

BY_NAME = {check.name: check for check in CHECKS}
NAMES = [check.name for check in CHECKS]


def judge(check, value):
    """The verdict on one measured value. No data is not a failure here:
    `volume` is the check that says whether there was data."""
    if value is None or (isinstance(value, float) and math.isnan(value)):
        return {"check_name": check.name, "severity": check.severity, "value": None,
                "threshold": check.threshold, "passed": True,
                "detail": f"{check.name}: no data in the interval"}
    passed = OPS[check.op](value, check.threshold)
    return {
        "check_name": check.name, "severity": check.severity, "value": float(value),
        "threshold": check.threshold, "passed": passed,
        "detail": f"{check.name} = {value:g}, must be {check.op} {check.threshold:g} "
                  f"({check.description})",
    }


def ch_time(moment):
    """A datetime as the string START/END parse, in UTC."""
    if moment.tzinfo is not None:
        moment = moment.astimezone(timezone.utc)
    return moment.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]


def run(ch, name, start, end):
    check = BY_NAME[name]
    value = ch.value(check.sql, start=ch_time(start), end=ch_time(end))
    return judge(check, value)


def failures(results):
    return [r for r in results if r["severity"] == "fail" and not r["passed"]]
