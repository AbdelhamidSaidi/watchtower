#!/usr/bin/env python3
"""Capacity WITHIN RAM: the highest rate the pipeline sustains before the
machine starts swapping. For low-memory machines, where any long run ends in
swap and the swap -- not the pipeline -- then sets the numbers.

    python3 tools/swap_bounded_test.py 1000 1500 2000 2500 3000

For each rate:
  1. restart the whole dev stack (releases all swap), wait for zero backlog
  2. start ceil(rate/1000) simulator containers at the rate
  3. sample every 5 s; STOP as soon as the PIPELINE starts swapping:
       the Flink TaskManager or ClickHouse has > 50 MB of its own memory
       in swap, or the VM's swap used grows > 150 MB over the clean start.
     (VM-wide swap-in is recorded but not a trigger: Docker's own daemons
     sit partly in swap and page in whenever `docker exec` runs -- the
     monitoring itself -- while the pipeline is unaffected.)
  4. judge the SWAP-FREE window only (after a short warm-up; on a 4 GB
     machine it is ~20 s long, so samples are 2 s apart):
       in/s      input topic end offsets        (what arrived)
       out/s     scored topic end offsets       (what Flink decided -- live,
                                                  unlike checkpoint-based lag)
       backlog   in - out, cumulative
       latency   event created -> row stored (ClickHouse), and Kafka ->
                 decision (Flink's own metric)
     KEEPS UP = out >= 97% of in and the backlog trend < 2% of the rate.
  5. next rate; stops after two rates in a row that do not keep up.
"""

import argparse
import json
import math
import re
import subprocess
import time

PW = open("secrets/clickhouse_password").read().strip()


def sh(cmd, timeout=120):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout).stdout.strip()


def ch(sql):
    return sh(f"docker exec watchtower-clickhouse clickhouse-client --user watchtower --password '{PW}' -q \"{sql}\"")


def end_offsets(topic):
    out = sh(f"docker exec watchtower-kafka /opt/kafka/bin/kafka-get-offsets.sh --bootstrap-server localhost:9092 --topic {topic}")
    return sum(int(line.rsplit(":", 1)[1]) for line in out.splitlines() if line.count(":") == 2)


def vm_swap():
    """(swap used MiB, pages swapped in so far) for the Docker VM."""
    top = sh("docker exec watchtower-kafka sh -c 'top -b -n 1 | grep \"MiB Swap\"'")
    used = float(re.search(r"([\d.]+) used", top).group(1))
    vmstat = sh("docker exec watchtower-kafka cat /proc/vmstat")
    pswpin = int(re.search(r"^pswpin (\d+)", vmstat, re.M).group(1))
    return used, pswpin


def proc_swap_mib(container):
    line = sh(f"docker exec {container} sh -c 'grep VmSwap /proc/1/status'")
    m = re.search(r"(\d+) kB", line)
    return int(m.group(1)) / 1024 if m else 0.0


def flink_metric(name):
    m = re.search(rf"^flink_taskmanager_job_task_operator_watchtower_{name}\S* ([\d.]+)", sh("curl -s localhost:9250/metrics"), re.M)
    return float(m.group(1)) if m else None


def latency(seconds):
    row = ch(
        "SELECT count(), avg(l), quantile(0.5)(l), quantile(0.95)(l), quantile(0.99)(l), max(l) FROM "
        "(SELECT toUnixTimestamp64Milli(ingested_at) - toUnixTimestamp64Milli(timestamp) AS l "
        f"FROM watchtower.security_events WHERE ingested_at > now64(3) - INTERVAL {seconds} SECOND) FORMAT TSV"
    ).split("\t")
    return [float(x) if x not in ("nan", "") else None for x in row]


def restart_stack():
    sh("docker compose --profile sim down", timeout=300)
    sh("docker compose up -d", timeout=600)
    for _ in range(120):
        if '"state":"RUNNING"' in sh("curl -s localhost:8082/jobs/overview"):
            break
        time.sleep(2)
    # wait until Flink has caught up with everything already in Kafka
    last = None
    for _ in range(120):
        gap = end_offsets("security-logs") - end_offsets("security-events-scored")
        if last is not None and abs(gap - last) < 50:
            break
        last = gap
        time.sleep(5)
    return end_offsets("security-logs") - end_offsets("security-events-scored")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("rates", type=int, nargs="+")
    ap.add_argument("--sample", type=int, default=2)
    ap.add_argument("--warmup", type=int, default=6)
    ap.add_argument("--max-seconds", type=int, default=300)
    ap.add_argument("--out", default="swap_bounded_results.json")
    args = ap.parse_args()

    results = []
    for rate in args.rates:
        producers = max(1, math.ceil(rate / 1000))
        print(f"\n=== {rate} events/s, {producers} simulator(s) ===", flush=True)
        offset_gap = restart_stack()   # in - out already present (rejects/dups/old)
        swap0, pswpin0 = vm_swap()
        print(f"clean start: swap used {swap0:.0f} MiB", flush=True)
        for i in range(producers):
            sh(f"docker compose --profile sim run -d --rm --name loadgen-{i} -e LOGS_PER_SECOND={rate // producers} producer")
        t0 = time.time()
        prev = (t0, end_offsets("security-logs"), end_offsets("security-events-scored"), pswpin0)
        samples, stop_reason = [], "time limit"
        print(f"{'t':>4} {'in/s':>6} {'out/s':>6} {'backlog':>8} {'e2e p50':>8} {'p95':>6}  "
              f"{'job p50/p95':>11}  {'swap MiB':>8} {'swap-in/s':>9} {'tm/ch swap':>10}", flush=True)
        while time.time() - t0 < args.max_seconds:
            time.sleep(args.sample)
            now = time.time()
            k_in, k_out = end_offsets("security-logs"), end_offsets("security-events-scored")
            used, pswpin = vm_swap()
            dt = now - prev[0]
            s = {
                "t": round(now - t0, 1),
                "in": (k_in - prev[1]) / dt, "out": (k_out - prev[2]) / dt,
                "backlog": k_in - k_out - offset_gap,
                "lat": latency(args.sample),
                "job_p50": flink_metric("kafka_to_scored_p50"), "job_p95": flink_metric("kafka_to_scored_p95"),
                "swap_used": used, "swapin_per_s": (pswpin - prev[3]) / dt,
                "tm_swap": proc_swap_mib("watchtower-flink-taskmanager-1"),
            "ch_swap": proc_swap_mib("watchtower-clickhouse"),
            }
            samples.append(s)
            prev = (now, k_in, k_out, pswpin)
            lat = s["lat"]
            print(f"{s['t']:>4.0f} {s['in']:>6.0f} {s['out']:>6.0f} {s['backlog']:>8.0f} "
                  f"{(lat[2] or 0):>8.0f} {(lat[3] or 0):>6.0f}  {s['job_p50'] or 0:>5.0f}/{s['job_p95'] or 0:<5.0f}  "
                  f"{used:>8.0f} {s['swapin_per_s']:>9.0f} {s['tm_swap']:>5.0f}/{s['ch_swap']:<4.0f}", flush=True)
            if used - swap0 > 150:
                stop_reason = "swap growth"
            elif s["tm_swap"] > 50:
                stop_reason = "TaskManager swapped"
            elif s["ch_swap"] > 50:
                stop_reason = "ClickHouse swapped"
            else:
                continue
            break
        for i in range(producers):
            sh(f"docker stop loadgen-{i}")

        window = [s for s in samples if s["t"] > args.warmup]
        if stop_reason != "time limit":
            window = window[:-1]  # the sample that tripped the swap check
        summary = {"rate": rate, "producers": producers, "stop": stop_reason,
                   "swap_free_seconds": window[-1]["t"] if window else 0, "samples": samples}
        if len(window) >= 4:
            ts, bs = [s["t"] for s in window], [s["backlog"] for s in window]
            mt, mb = sum(ts) / len(ts), sum(bs) / len(bs)
            slope = sum((t - mt) * (b - mb) for t, b in zip(ts, bs)) / max(1e-9, sum((t - mt) ** 2 for t in ts))
            rows = [s["lat"][0] or 0 for s in window]
            wavg = lambda i: sum((s["lat"][i] or 0) * (s["lat"][0] or 0) for s in window) / max(1, sum(rows))  # noqa: E731
            summary.update({
                "in_per_s": sum(s["in"] for s in window) / len(window),
                "out_per_s": sum(s["out"] for s in window) / len(window),
                "backlog_trend_per_s": slope,
                "latency_avg_ms": wavg(1), "latency_p50_ms": sorted(s["lat"][2] or 0 for s in window)[len(window) // 2],
                "latency_p95_ms": sorted(s["lat"][3] or 0 for s in window)[len(window) // 2],
                "latency_max_ms": max(s["lat"][5] or 0 for s in window),
                "job_p50_ms": sorted(s["job_p50"] or 0 for s in window)[len(window) // 2],
            })
            summary["keeps_up"] = (summary["out_per_s"] >= 0.97 * summary["in_per_s"]
                                   and slope < 0.02 * summary["in_per_s"])
        else:
            summary["keeps_up"] = None  # swap came too fast to judge
        results.append(summary)
        json.dump(results, open(args.out, "w"), indent=1)
        if summary["keeps_up"] is None:
            print(f"--> swap after {summary['swap_free_seconds']:.0f} s: too short to judge", flush=True)
        else:
            print(f"--> swap-free for {summary['swap_free_seconds']:.0f} s ({stop_reason}): "
                  f"in {summary['in_per_s']:.0f}/s, out {summary['out_per_s']:.0f}/s, "
                  f"backlog {summary['backlog_trend_per_s']:+.0f}/s, latency avg {summary['latency_avg_ms']:.0f} ms "
                  f"p50 {summary['latency_p50_ms']:.0f} p95 {summary['latency_p95_ms']:.0f} | "
                  f"KEEPS UP = {summary['keeps_up']}", flush=True)
        last_two = [r["keeps_up"] for r in results[-2:]]
        if len(last_two) == 2 and all(x is False for x in last_two):
            print("two rates in a row do not keep up: stopping", flush=True)
            break

    sh("docker compose --profile sim down", timeout=300)
    print("\nstack stopped", flush=True)


if __name__ == "__main__":
    main()
