"""Hourly data-quality checks on what the stream stored.

Prometheus (deploy/observability/alerts.yml) watches the PIPELINE: is the
job up, is it keeping up, how long does an event take. These checks watch
the DATA it wrote, one closed hour at a time: was anything stored, did too
much get refused, are rows complete, did the share of quarantines jump.

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

    # Detection is keyed by runner_ip; an event without one, or without a
    # type, was scored against nothing.
    Check("missing_identity", "fail", "==", 0,
          "events with an empty runner_ip or event_type",
          f"SELECT countIf(runner_ip = '' OR event_type = '') FROM {EVENTS} WHERE {IN_HOUR}"),

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

    # Five times the usual share of quarantines is either an incident wave
    # (a bad commit, a registry outage) or a rule gone wrong. Either way a human should look.
    Check("quarantine_share_vs_7d", "warn", "<=", 5.0,
          "the hour's share of quarantines, as a multiple of the trailing 7 days'",
          "SELECT h / nullIf(w, 0) FROM ("
          " SELECT (SELECT countIf(recommended_action = 'quarantine') / nullIf(count(), 0)"
          f"         FROM {EVENTS} WHERE {IN_HOUR}) AS h,"
          "        (SELECT countIf(recommended_action = 'quarantine') / nullIf(count(), 0)"
          f"         FROM {EVENTS}"
          f"         WHERE timestamp >= {START} - INTERVAL 7 DAY AND timestamp < {START}) AS w)"),
)

# Population stability index of the model's scores: this hour against the
# trailing week, over ten score bands. Under 0.1 is stable, 0.1-0.25 a
# shift worth watching, above 0.25 the traffic the model sees is no longer
# the traffic it was judged on -- retrain, or find out what changed.
_BANDS = "least(toUInt8(ml_score * 10), 9)"
CHECKS += (
    Check("ml_score_drift_psi", "warn", "<=", 0.25,
          "population stability of the model's scores, the hour vs the trailing 7 days",
          "SELECT if(count() = 0, NULL, sum((h - w) * log(h / w))) FROM ("
          " SELECT (ifNull(hc, 0) + 0.5) / (sum(ifNull(hc, 0)) OVER () + 5) AS h,"
          "        (ifNull(wc, 0) + 0.5) / (sum(ifNull(wc, 0)) OVER () + 5) AS w"
          f" FROM (SELECT {_BANDS} AS b, count() AS hc FROM {EVENTS}"
          f"       WHERE {IN_HOUR} AND ml_model != '' GROUP BY b) AS hour"
          f" FULL OUTER JOIN (SELECT {_BANDS} AS b, count() AS wc FROM {EVENTS}"
          f"       WHERE timestamp >= {START} - INTERVAL 7 DAY AND timestamp < {START} AND ml_model != ''"
          "       GROUP BY b) AS week USING (b))"),
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
