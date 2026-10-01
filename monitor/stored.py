"""What the pipeline stored: throughput, end-to-end latency, decisions,
which model decided, the model's score distribution, refused messages.

Each pass reads only the rows stored since the last one -- (since, upto]
by ingested_at, with upto 2 s behind now so a block still being inserted
is not half-counted -- and adds them to cumulative counters and histograms.
Prometheus computes rates and percentiles over any window from those.
The exact percentiles of the last 60 s are published too, as `make latency`
computes them, so the dashboard and the Makefile agree to the millisecond.

End-to-end is ingested_at - timestamp: from the producer stamping the event
to the row landing in ClickHouse -- Kafka, Flink and ClickHouse's intake
together.
"""

from monitor.exposition import counter, gauge, histogram

LATENCY_MS = (25, 50, 100, 150, 200, 250, 300, 400, 500, 750, 1000, 1500, 2000, 3000, 5000,
              10_000, 30_000, 60_000)
SCORE = tuple(round(0.05 * i, 2) for i in range(1, 21))     # 0.05 ... 1.0
# The primary key leads with the event's 10-minute bucket: a timestamp
# bound keeps each pass on recent parts. Two hours still sees the rows of
# a backlog replayed after an outage.
LOOKBACK_MS = 2 * 3600 * 1000

WINDOW = """
SELECT recommended_action AS action, ml_model AS model,
       multiIf(ml_reason != '', 'model', rule_hits != '', 'rules', 'none') AS decided_by,
       count() AS n,
       sum(greatest(l, 0)) AS latency_sum,
       sumForEach(arrayMap(b -> toUInt64(l <= b), {latency:Array(Int64)})) AS latency_le,
       countIf(ml_model != '') AS scored,
       sumForEach(arrayMap(b -> toUInt64(ml_model != '' AND ml_score <= b), {score:Array(Float64)})) AS score_le,
       sumIf(ml_score, ml_model != '') AS score_sum
FROM (
    SELECT recommended_action, ml_model, ml_reason, rule_hits, ml_score,
           toUnixTimestamp64Milli(ingested_at) - toUnixTimestamp64Milli(timestamp) AS l
    FROM watchtower.security_events
    WHERE timestamp > fromUnixTimestamp64Milli({since:Int64} - {lookback:Int64})
      AND ingested_at > fromUnixTimestamp64Milli({since:Int64})
      AND ingested_at <= fromUnixTimestamp64Milli({upto:Int64})
)
GROUP BY action, model, decided_by"""

LAST_MINUTE = """
SELECT count() AS n, quantilesExact(0.5, 0.95, 0.99)(l) AS q, max(l) AS top,
       toUnixTimestamp64Milli(now64(3)) - toUnixTimestamp64Milli(max(ingested_at)) AS age_ms
FROM (
    SELECT ingested_at, toUnixTimestamp64Milli(ingested_at) - toUnixTimestamp64Milli(timestamp) AS l
    FROM watchtower.security_events
    WHERE timestamp > now64(3) - INTERVAL 2 HOUR AND ingested_at > now64(3) - INTERVAL 60 SECOND
)"""

NEWEST_AGE = """
SELECT toUnixTimestamp64Milli(now64(3)) - toUnixTimestamp64Milli(max(ingested_at)) AS age_ms, count() AS n
FROM watchtower.security_events
WHERE timestamp > now64(3) - INTERVAL 2 HOUR"""

REFUSED = """
SELECT reject_reason AS reason, count() AS n
FROM watchtower.rejected_events
WHERE rejected_at > fromUnixTimestamp64Milli({since:Int64})
  AND rejected_at <= fromUnixTimestamp64Milli({upto:Int64})
GROUP BY reason"""


class Stored:
    name = "stored"
    interval = 5.0

    def __init__(self, ch):
        self.ch = ch
        self.since = None
        self.events = {}            # (action, model, decided_by) -> n
        self.refused = {}           # reason -> n
        self.latency = [0] * len(LATENCY_MS)
        self.latency_sum = self.latency_count = 0
        self.score = [0] * len(SCORE)
        self.score_sum, self.score_count = 0.0, 0
        self.last_minute = None     # the gauges of the latest pass; None when it failed

    def collect(self):
        self.last_minute = None
        upto = self.ch.row("SELECT toUnixTimestamp64Milli(now64(3)) - 2000 AS upto")["upto"]
        if self.since is None:
            self.since = upto       # count from now on
        if upto > self.since:
            self._window(self.since, upto)
            self.since = upto
        self.last_minute = self._last_minute()
        return self.families()

    def _window(self, since, upto):
        rows = self.ch.rows(WINDOW, since=since, upto=upto, lookback=LOOKBACK_MS,
                            latency=LATENCY_MS, score=SCORE)
        refused = self.ch.rows(REFUSED, since=since, upto=upto)
        # Only once both reads succeeded, so a failed pass is re-read whole.
        for r in rows:
            key = (r["action"], r["model"], r["decided_by"])
            self.events[key] = self.events.get(key, 0) + int(r["n"])
            self.latency = [a + int(b) for a, b in zip(self.latency, r["latency_le"])]
            self.latency_sum += int(r["latency_sum"])
            self.latency_count += int(r["n"])
            self.score = [a + int(b) for a, b in zip(self.score, r["score_le"])]
            self.score_sum += float(r["score_sum"] or 0)
            self.score_count += int(r["scored"])
        for r in refused:
            self.refused[r["reason"]] = self.refused.get(r["reason"], 0) + int(r["n"])

    def _last_minute(self):
        row = self.ch.row(LAST_MINUTE)
        if int(row["n"]):
            p50, p95, p99 = row["q"]
            return {"events": int(row["n"]), "p50": p50, "p95": p95, "p99": p99, "max": row["top"],
                    "age_ms": row["age_ms"]}
        newest = self.ch.row(NEWEST_AGE)
        return {"events": 0, "age_ms": newest["age_ms"] if int(newest["n"]) else None}

    def after_error(self):
        return self.families()

    def families(self):
        events = counter("watchtower_stored_events_total",
                         "Rows stored in security_events, by final action, the model version that scored "
                         "them, and what decided: the model (it raised the rules' action), rules, or none (allowed).")
        for (action, model, decided_by), n in sorted(self.events.items()):
            events.add(n, action=action, model=model or "none", decided_by=decided_by)
        refused = counter("watchtower_refused_messages_total",
                          "Messages refused into rejected_events, by reason.")
        for reason, n in sorted(self.refused.items()):
            refused.add(n, reason=reason)
        f = [
            events, refused,
            histogram("watchtower_e2e_latency_ms",
                      "End to end, event created -> row stored in ClickHouse (ingested_at - timestamp).",
                      LATENCY_MS, self.latency, self.latency_sum, self.latency_count),
            histogram("watchtower_ml_score",
                      "The model's score on every event it scored: its distribution, for drift.",
                      SCORE, self.score, self.score_sum, self.score_count),
        ]
        if self.last_minute is not None:
            m = self.last_minute
            exact = gauge("watchtower_e2e_latency_last_minute_ms",
                          "End-to-end latency of the rows stored in the last 60 s, exact (as `make latency`).")
            for stat in ("p50", "p95", "p99", "max"):
                exact.add(m.get(stat), stat=stat)
            f += [
                exact,
                gauge("watchtower_stored_last_minute_events",
                      "Rows stored in the last 60 s.").add(m["events"]),
                gauge("watchtower_newest_row_age_seconds",
                      "Seconds since the newest row was stored (absent if none in 2 h).")
                .add(None if m["age_ms"] is None else m["age_ms"] / 1000),
            ]
        return f
