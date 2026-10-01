#!/usr/bin/env python3
"""Benchmark the real ClickHouse workload against a table (or two, to compare).

    python3 tools/bench_queries.py security_events [security_events_v2]

Each query runs 3 times with the mark cache dropped and the query-condition
cache off; the report is the
median of rows read, bytes read, time and memory, from system.query_log --
ClickHouse's own accounting, not client-side timing.

The queries are the ones people run: the build engineer's investigation queries
(NOTE_TO_BUILD_ENGINEER.md), the detection evaluator (tools/evaluate_detection.py),
and the operational latency check (make latency). Time windows are anchored on
the newest event in the table, so the benchmark works on historical data.
"""

import statistics
import subprocess
import sys
import uuid

PASSWORD = open("secrets/clickhouse_password").read().strip()


def ch(query):
    out = subprocess.run(
        ["docker", "exec", "-i", "watchtower-clickhouse", "clickhouse-client",
         "--user", "watchtower", "--password", PASSWORD, "--multiquery"],
        input=query, capture_output=True, text=True,
    )
    if out.returncode:
        raise SystemExit(out.stderr.strip()[:600])
    return out.stdout.strip()


def workload(t):
    anchor = ch(f"SELECT max(timestamp) FROM watchtower.{t}")
    ip, eid = ch(
        f"SELECT runner_ip, toString(event_id) FROM watchtower.{t} "
        f"WHERE timestamp > toDateTime64('{anchor}', 3) - INTERVAL 2 HOUR "
        f"AND recommended_action = 'quarantine' LIMIT 1 FORMAT TSV"
    ).split("\t")
    a = f"toDateTime64('{anchor}', 3)"
    newest_ingest = ch(f"SELECT max(ingested_at) FROM watchtower.{t}")
    return {
        "event by id (alert drill-down)":
            f"SELECT * FROM watchtower.{t} WHERE event_id = '{eid}'",
        "one IP, +-15 min (investigation)":
            f"SELECT timestamp, event_type, project, failed_builds_5m, distinct_exit_codes_5m, ml_score, ml_reason "
            f"FROM watchtower.{t} WHERE runner_ip = '{ip}' "
            f"AND timestamp > {a} - INTERVAL 45 MINUTE AND timestamp < {a} - INTERVAL 15 MINUTE ORDER BY timestamp",
        "one IP, whole history":
            f"SELECT count(), countIf(recommended_action = 'quarantine'), min(timestamp), max(timestamp) "
            f"FROM watchtower.{t} WHERE runner_ip = '{ip}'",
        "last 10 min, model-driven alerts":
            f"SELECT count() FROM watchtower.{t} WHERE timestamp > {a} - INTERVAL 10 MINUTE "
            f"AND ml_reason != ''",
        "top quarantined IPs, last hour":
            f"SELECT runner_ip, count() c FROM watchtower.{t} WHERE timestamp > {a} - INTERVAL 1 HOUR "
            f"AND recommended_action = 'quarantine' GROUP BY runner_ip ORDER BY c DESC LIMIT 10",
        "evaluator, last 15 min":
            f"SELECT event_id, recommended_action, rule_hits FROM watchtower.{t} "
            f"WHERE timestamp > {a} - INTERVAL 15 MINUTE FORMAT Null",
        # As `make latency` runs it: a fixed point in time (now64() live),
        # not a subquery that would itself scan the column.
        "latency check (ingested_at, 60 s)":
            f"SELECT quantile(0.5)(toUnixTimestamp64Milli(ingested_at) - toUnixTimestamp64Milli(timestamp)) "
            f"FROM watchtower.{t} WHERE ingested_at > toDateTime64('{newest_ingest}', 3) - INTERVAL 60 SECOND",
    }


def measure(sql):
    runs = []
    for _ in range(3):
        tag = uuid.uuid4().hex
        # use_query_condition_cache=0: ClickHouse 25.x otherwise remembers
        # which granules matched a filter, and a repeated query skips the
        # work a real one-off query does.
        ch(f"SYSTEM DROP MARK CACHE; {sql} SETTINGS log_comment='{tag}', "
           f"use_query_condition_cache=0 FORMAT Null")
        ch("SYSTEM FLUSH LOGS")
        runs.append([float(x) for x in ch(
            "SELECT read_rows, read_bytes, query_duration_ms, memory_usage FROM system.query_log "
            f"WHERE log_comment = '{tag}' AND type = 'QueryFinish' FORMAT TSV").split("\t")])
    return [statistics.median(col) for col in zip(*runs)]


def human(n):
    for unit in ("", "K", "M", "G"):
        if abs(n) < 1000:
            return f"{n:.0f}{unit}"
        n /= 1000
    return f"{n:.0f}T"


tables = sys.argv[1:] or ["security_events"]
results = {t: {name: measure(sql.replace(" FORMAT Null", "")) for name, sql in workload(t).items()} for t in tables}
names = list(results[tables[0]])
print(f"{'query':36s}" + "".join(f" | {t[:30]:>30s}" for t in tables))
print(f"{'':36s}" + " | {:>30s}".format("rows read / bytes / ms / mem") * len(tables))
for name in names:
    cells = []
    for t in tables:
        rows, byts, ms, mem = results[t][name]
        cells.append(f"{human(rows):>7s} / {human(byts)+'B':>6s} / {ms:>4.0f} / {human(mem)+'B':>5s}")
    print(f"{name:36s}" + "".join(f" | {c:>30s}" for c in cells))
