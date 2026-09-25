#!/usr/bin/env python3
"""Step load test of the whole dev pipeline: producer -> Kafka -> Flink ->
Kafka -> ClickHouse. Finds the highest rate every stage sustains.

    python3 tools/load_test.py 1000 2000 3000 4000 5000 --step-seconds 240

For each rate it starts producer containers (the simulator, split across
`--producers` containers so a single Python producer is not the ceiling),
holds the rate for --step-seconds, and samples every --sample seconds:

    in/s        what Kafka actually received (end-offset delta, not the target)
    decided/s   what Flink got through (its consumer group's committed offsets)
    stored/s    rows ClickHouse inserted (ingested_at)
    backlog     events in Kafka Flink has not read (consumer-group lag)
    latency     event created -> row stored, from ClickHouse
    cpu / mem   per container, and the VM's swap

A step is SUSTAINED when the backlog does not grow over its second half and
ClickHouse stores what arrives. The report is written as JSON next to the
printed table, for docs.
"""

import argparse
import json
import re
import subprocess
import time

PW = open("secrets/clickhouse_password").read().strip()


def sh(cmd, timeout=60):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout).stdout.strip()


def ch(sql):
    return sh(f"docker exec watchtower-clickhouse clickhouse-client --user watchtower --password '{PW}' -q \"{sql}\"")


def kafka_end_offsets():
    out = sh("docker exec watchtower-kafka /opt/kafka/bin/kafka-get-offsets.sh --bootstrap-server localhost:9092 --topic security-logs")
    return sum(int(line.rsplit(":", 1)[1]) for line in out.splitlines() if line.count(":") == 2)


def group_lag_and_committed(group="watchtower-stream"):
    out = sh(f"docker exec watchtower-kafka /opt/kafka/bin/kafka-consumer-groups.sh --bootstrap-server localhost:9092 --describe --group {group}")
    lag = committed = 0
    for line in out.splitlines():
        cols = line.split()
        if len(cols) >= 6 and cols[1] == "security-logs" and cols[3].isdigit():
            committed += int(cols[3])
            lag += int(cols[5]) if cols[5].isdigit() else 0
    return lag, committed


def container_stats():
    out = sh("docker stats --no-stream --format '{{.Name}}|{{.CPUPerc}}|{{.MemUsage}}'")
    stats = {}
    for line in out.splitlines():
        name, cpu, mem = line.split("|")
        used = mem.split("/")[0].strip()
        value, unit = re.match(r"([\d.]+)\s*([KMG]i?B)", used).groups()
        mib = float(value) * {"KiB": 1 / 1024, "MiB": 1, "GiB": 1024, "KB": 1 / 1000, "MB": 1, "GB": 1000}[unit]
        stats[name.replace("watchtower-", "")] = (float(cpu.rstrip("%")), mib)
    return stats


def vm_swap_used_mib():
    line = sh("docker exec watchtower-kafka sh -c 'top -b -n 1 | grep \"MiB Swap\"'")
    m = re.search(r"([\d.]+) used", line)
    return float(m.group(1)) if m else None


def latency(since, until):
    row = ch(
        "SELECT count(), round(avg(l)), round(quantile(0.5)(l)), round(quantile(0.95)(l)), "
        "round(quantile(0.99)(l)), max(l), round(countIf(l < 100) / greatest(count(), 1) * 100, 1) FROM "
        "(SELECT toUnixTimestamp64Milli(ingested_at) - toUnixTimestamp64Milli(timestamp) AS l "
        "FROM watchtower.security_events WHERE ingested_at >= toDateTime64('" + since + "', 3) "
        "AND ingested_at < toDateTime64('" + until + "', 3)) FORMAT TSV"
    ).split("\t")
    keys = ["rows", "avg_ms", "p50_ms", "p95_ms", "p99_ms", "max_ms", "pct_under_100ms"]
    return dict(zip(keys, (float(x) for x in row)))


def start_producers(rate, n):
    per = rate // n
    for i in range(n):
        sh(f"docker compose --profile sim run -d --rm --name loadgen-{i} -e LOGS_PER_SECOND={per} producer")


def stop_producers(n):
    for i in range(n):
        sh(f"docker stop loadgen-{i}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("rates", type=int, nargs="+")
    ap.add_argument("--step-seconds", type=int, default=240)
    ap.add_argument("--sample", type=int, default=20)
    ap.add_argument("--producers", type=int, default=2)
    ap.add_argument("--out", default="load_test_results.json")
    args = ap.parse_args()

    results = []
    for rate in args.rates:
        print(f"\n=== {rate} events/s (target), {args.producers} producers, {args.step_seconds} s ===", flush=True)
        start_producers(rate, args.producers)
        time.sleep(15)  # producers connect and fetch the schema
        t_start = time.time()
        k0, (lag0, c0) = kafka_end_offsets(), group_lag_and_committed()
        ts0 = ch("SELECT toString(now64(3))")
        samples = []
        prev = (time.time(), k0, c0)
        print(f"{'t':>4} {'in/s':>7} {'decided/s':>9} {'stored/s':>8} {'backlog':>8} {'p50':>6} {'p95':>6}  "
              f"{'cpu tm/ch/kafka/prod':>22}  swap", flush=True)
        while time.time() - t_start < args.step_seconds:
            time.sleep(args.sample)
            now = time.time()
            k, (lag, c) = kafka_end_offsets(), group_lag_and_committed()
            dt = now - prev[0]
            stats = container_stats()
            since = ch(f"SELECT toString(now64(3) - INTERVAL {args.sample} SECOND)")
            until = ch("SELECT toString(now64(3))")
            lat = latency(since, until)
            prod_cpu = sum(v[0] for n, v in stats.items() if n.startswith("loadgen"))
            s = {
                "t": round(now - t_start), "in_per_s": (k - prev[1]) / dt, "decided_per_s": (c - prev[2]) / dt,
                "stored_per_s": lat["rows"] / args.sample, "backlog": lag, "lat": lat,
                "cpu": {n: v[0] for n, v in stats.items()}, "mem_mib": {n: v[1] for n, v in stats.items()},
                "swap_mib": vm_swap_used_mib(),
            }
            samples.append(s)
            prev = (now, k, c)
            print(f"{s['t']:>4} {s['in_per_s']:>7.0f} {s['decided_per_s']:>9.0f} {s['stored_per_s']:>8.0f} "
                  f"{lag:>8} {lat['p50_ms']:>6.0f} {lat['p95_ms']:>6.0f}  "
                  f"{sum(v[0] for n, v in stats.items() if n.startswith('flink-taskmanager')):>5.0f}/{stats.get('clickhouse', (0,))[0]:>4.0f}/"
                  f"{stats.get('kafka', (0,))[0]:>4.0f}/{prod_cpu:>4.0f}%  {s['swap_mib']}", flush=True)
        ts1 = ch("SELECT toString(now64(3))")
        k1, (lag1, c1) = kafka_end_offsets(), group_lag_and_committed()
        elapsed = time.time() - t_start
        stop_producers(args.producers)

        half = samples[len(samples) // 2:]
        # Backlog trend: least-squares slope over the WHOLE step. The backlog
        # is read from checkpoint commits (every 10 s), so single samples jump
        # by a checkpoint's worth of events; a two-point difference read that
        # noise as growth.
        ts = [x["t"] for x in samples]
        bs = [x["backlog"] for x in samples]
        mt, mb = sum(ts) / len(ts), sum(bs) / len(bs)
        backlog_growth = (sum((t - mt) * (b - mb) for t, b in zip(ts, bs))
                          / max(1e-9, sum((t - mt) ** 2 for t in ts)))
        summary = {
            "target": rate,
            "in_per_s": (k1 - k0) / elapsed,
            "decided_per_s": (c1 - c0) / elapsed,
            "stored_per_s": sum(x["stored_per_s"] for x in samples) / len(samples),
            "backlog_start": lag0, "backlog_end": lag1,
            "backlog_growth_per_s_second_half": backlog_growth,
            "latency_second_half": latency(ch(f"SELECT toString(toDateTime64('{ts0}', 3) + INTERVAL {int(elapsed / 2)} SECOND)"), ts1),
            "cpu_avg": {n: round(sum(x["cpu"].get(n, 0) for x in half) / len(half)) for n in half[-1]["cpu"]},
            "mem_max_mib": {n: round(max(x["mem_mib"].get(n, 0) for x in half)) for n in half[-1]["mem_mib"]},
            "swap_max_mib": max((x["swap_mib"] or 0) for x in half),
            "samples": samples,
        }
        # Sustained: the backlog trend is within 2% of the input rate (noise),
        # and Flink and ClickHouse both keep pace with what Kafka received.
        summary["sustained"] = (
            backlog_growth < 0.02 * summary["in_per_s"]
            and summary["decided_per_s"] > 0.97 * summary["in_per_s"]
            and summary["stored_per_s"] > 0.95 * summary["in_per_s"]
        )
        results.append(summary)
        print(f"--> in {summary['in_per_s']:.0f}/s, decided {summary['decided_per_s']:.0f}/s, "
              f"stored {summary['stored_per_s']:.0f}/s, backlog {lag0} -> {lag1} "
              f"({backlog_growth:+.0f}/s), SUSTAINED={summary['sustained']}", flush=True)
        json.dump(results, open(args.out, "w"), indent=1)
        # let the pipeline drain before the next step
        for _ in range(60):
            if group_lag_and_committed()[0] < 2000:
                break
            time.sleep(10)
        if not summary["sustained"] and len(results) >= 2 and not results[-2]["sustained"]:
            print("two unsustained steps in a row: stopping", flush=True)
            break


if __name__ == "__main__":
    main()
