#!/usr/bin/env python3
"""Move an existing security_events table onto the layout in 01_schema.sql.

    python3 tools/relayout_security_events.py                  # dev (docker compose)
    python3 tools/relayout_security_events.py --exec "kubectl -n watchtower-staging exec -i clickhouse-0 --"

ClickHouse cannot change a table's sorting key in place, so this:

  1. creates security_events_v2 from 01_schema.sql's definition
  2. copies the rows ONE HOUR AT A TIME, by column name (a table migrated
     with ALTER ... ADD COLUMN has its columns in a different order than
     the file, so SELECT * would misalign them), with merges paused -- a
     single INSERT ... SELECT of 43M wide rows exceeded ClickHouse's
     memory cap on a 4 GB machine
  3. merges, checks the row counts match, then swaps the two tables
     atomically (EXCHANGE TABLES)
  4. recreates the two materialized views bound to security_events
  5. KEEPS the old data as security_events_before_relayout. Drop it
     yourself once you are satisfied.

Stop the writer first (the Flink job): rows that
arrive during the copy would land only in the old table. Re-runnable: it
resumes from whatever step it reached.
"""

import argparse
import re
import shlex
import subprocess
import sys

DB = "watchtower"


def client(prefix, password):
    base = shlex.split(prefix) + ["clickhouse-client", "--user", "watchtower", "--password", password, "--multiquery"]

    def ch(sql):
        out = subprocess.run(base, input=sql, capture_output=True, text=True)
        if out.returncode:
            sys.exit(f"clickhouse error:\n{out.stderr.strip()[:800]}\n-- in: {sql[:300]}")
        return out.stdout.strip()

    return ch


def table_ddl(name):
    sql = open("clickhouse/init/01_schema.sql").read()
    start = sql.index(f"CREATE TABLE IF NOT EXISTS {DB}.security_events\n")
    end = sql.index(";", sql.index("ENGINE", start)) + 1
    ddl = sql[start:end]
    return ddl.replace(f"{DB}.security_events\n", f"{DB}.{name}\n", 1)


def mv_ddl():
    """The two views bound to security_events, as the init files define them."""
    v02 = open("clickhouse/init/02_v2_request_context.sql").read()
    v03 = open("clickhouse/init/03_streaming_ingest.sql").read()
    suspicious = re.search(r"CREATE MATERIALIZED VIEW IF NOT EXISTS watchtower\.mv_suspicious_events.*?;", v02, re.S).group(0)
    from_queue = re.search(r"CREATE MATERIALIZED VIEW IF NOT EXISTS watchtower\.security_events_from_queue.*?;", v03, re.S).group(0)
    return [("mv_suspicious_events", suspicious), ("security_events_from_queue", from_queue)]


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("--exec", default="docker exec -i watchtower-clickhouse",
                    help="how to reach clickhouse-client (default: the dev container)")
    ap.add_argument("--password-file", default="secrets/clickhouse_password")
    args = ap.parse_args()
    ch = client(args.exec, open(args.password_file).read().strip())
    exists = lambda t: ch(f"EXISTS TABLE {DB}.{t}") == "1"  # noqa: E731

    if exists("security_events_before_relayout") and not exists("security_events_v2"):
        print("already migrated (security_events_before_relayout exists)")
        return
    ch(table_ddl("security_events_v2"))

    columns = ch(f"SELECT arrayStringConcat(groupArray(name), ', ') FROM "
                 f"(SELECT name FROM system.columns WHERE database='{DB}' AND table='security_events' ORDER BY position)")
    old = int(ch(f"SELECT count() FROM {DB}.security_events"))
    new = int(ch(f"SELECT count() FROM {DB}.security_events_v2"))
    if new != old:
        if new:
            # a partial copy, or a finished one already merged (merging
            # collapses duplicate events, so it counts fewer rows)
            print(f"security_events_v2 has {new:,} rows, not {old:,} -- copying again")
            ch(f"TRUNCATE TABLE {DB}.security_events_v2")
        ch(f"SYSTEM STOP MERGES {DB}.security_events_v2")
        hours = ch(f"SELECT DISTINCT toStartOfHour(timestamp) h FROM {DB}.security_events ORDER BY h FORMAT TSV").split("\n")
        for i, hour in enumerate(h for h in hours if h):
            ch(f"INSERT INTO {DB}.security_events_v2 ({columns}) SELECT {columns} FROM {DB}.security_events "
               f"WHERE toStartOfHour(timestamp) = '{hour}' SETTINGS max_threads=1, max_insert_threads=1, "
               f"max_block_size=16384, min_insert_block_size_rows=65536, min_insert_block_size_bytes=0")
            print(f"  copied {hour} ({i + 1}/{len(hours)})", flush=True)
        ch(f"SYSTEM START MERGES {DB}.security_events_v2")
        new = int(ch(f"SELECT count() FROM {DB}.security_events_v2"))
    if new != old:
        sys.exit(f"row counts differ after copy: old {old:,}, new {new:,} -- nothing swapped")

    for partition in ch(f"SELECT DISTINCT partition FROM system.parts WHERE database='{DB}' "
                        f"AND table='security_events_v2' AND active FORMAT TSV").split("\n"):
        if partition:
            ch(f"OPTIMIZE TABLE {DB}.security_events_v2 PARTITION '{partition}' FINAL")

    views = mv_ddl()
    for name, _ in views:
        ch(f"DROP VIEW IF EXISTS {DB}.{name}")
    ch(f"EXCHANGE TABLES {DB}.security_events AND {DB}.security_events_v2")
    ch(f"RENAME TABLE {DB}.security_events_v2 TO {DB}.security_events_before_relayout")
    for _, ddl in views:
        ch(ddl)
    print(f"done: {new:,} rows on the new layout; old data kept in "
          f"{DB}.security_events_before_relayout")


if __name__ == "__main__":
    main()
