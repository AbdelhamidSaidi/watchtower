"""
Per-event detection cost with and without the ML model -- the budget test.

At 1,000 events/s every event has 1 ms, end to end, before the next
second's arrive. This runs a realistic stream -- ~1,800 sources, normal
traffic plus brute-force and scan bursts that fill the rolling windows --
through the job's own per-event code (validate -> normalize -> enrich ->
dedup + features + rules [+ model]), once without the model and once with
it, and reports what the model adds.

    python tools/bench_detection.py --dump model.json      # a real model
    python tools/bench_detection.py                        # rules only

This is the detection code alone, in plain Python; the Flink job adds its
state backend and serialisation on top (~173 us per event in total,
docs/streaming.md). The model's share is the difference between the runs.
"""

import argparse
import json
import os
import random
import sys
import time
import uuid
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "etl"))

from core.ml import Model  # noqa: E402
from core.processor import SourceState  # noqa: E402
from core.records import enrich, normalize, reject_reason  # noqa: E402

T0 = datetime(2026, 9, 28, 14, 0, tzinfo=timezone.utc)
HOSTILE = ["185.23.44.12", "41.251.72.91", "45.134.26.7", "193.201.9.88"]
PATHS = ["/dashboard", "/api/v1/orders", "/login", "/static/app.js", "/reports/export"]


def stream(n, rate, seed=11):
    """n events at `rate` per second: 97% normal from ~1,800 hosts, 3%
    attack bursts from a few hostile sources."""
    rng = random.Random(seed)
    hosts = [f"192.168.{i // 250}.{i % 250 + 2}" for i in range(1780)]
    out = []
    for i in range(n):
        ts = (T0 + timedelta(seconds=i / rate)).isoformat()
        base = {"event_id": str(uuid.UUID(int=rng.getrandbits(128), version=4)), "timestamp": ts,
                "severity": "INFO", "hostname": "ws-001"}
        if rng.random() < 0.03:
            src, kind = rng.choice(HOSTILE), rng.choice(["brute", "scan", "web"])
            if kind == "brute":
                base.update(event_type="LOGIN_FAILURE", source_ip=src, user=rng.choice(["root", "admin"]),
                            auth_method="password")
            elif kind == "scan":
                base.update(event_type="PORT_SCAN", source_ip=src, user="", target_port=rng.randint(1, 1024))
            else:
                base.update(event_type="HTTP_REQUEST", source_ip=src, user="", http_method="GET",
                            url_path=f"/admin/{rng.randint(1, 500)}", http_status=404, user_agent="sqlmap/1.8")
        else:
            kind = rng.choices(["HTTP_REQUEST", "LOGIN_SUCCESS", "FILE_ACCESS", "COMMAND_EXECUTION",
                                "LOGIN_FAILURE"], weights=[50, 15, 15, 15, 5])[0]
            base.update(event_type=kind, source_ip=rng.choice(hosts), user=f"user{rng.randint(1, 900)}",
                        http_method="GET", url_path=rng.choice(PATHS), http_status=200,
                        user_agent="Mozilla/5.0", bytes_sent=rng.randint(200, 40_000),
                        command="ls -la" if kind == "COMMAND_EXECUTION" else None, process_uid=1001)
        out.append(base)
    return out


def run(events, model):
    """Seconds per event through the per-event path; the scored events."""
    states, scored = {}, []
    t0 = time.perf_counter()
    for raw in events:
        event = dict(raw)
        if reject_reason(event):
            continue
        event = enrich(normalize(event))
        state = states.get(event["source_ip"])
        if state is None:
            state = states[event["source_ip"]] = SourceState(model=model)
        if state.process(event) is not None:
            scored.append(event)
    return (time.perf_counter() - t0) / len(events), scored


def score_only(model, events, repeat=20_000):
    samples = []
    for i in range(repeat):
        e = events[i % len(events)]
        t0 = time.perf_counter_ns()
        model.score(e)
        samples.append(time.perf_counter_ns() - t0)
    samples.sort()
    return samples[len(samples) // 2] / 1000, samples[int(len(samples) * 0.99)] / 1000


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    parser.add_argument("--dump", help="a LightGBM dump_model() JSON file (watchtower.ml_models.model)")
    parser.add_argument("--events", type=int, default=60_000)
    parser.add_argument("--rate", type=int, default=1_000)
    parser.add_argument("--rounds", type=int, default=3)
    args = parser.parse_args()

    events = stream(args.events, args.rate)
    model = None
    if args.dump:
        with open(args.dump) as handle:
            model = Model(json.load(handle), os.path.basename(args.dump))

    rules = [run(events, None)[0] for _ in range(args.rounds)]
    print(f"{args.events:,} events at {args.rate:,}/s, best of {args.rounds} rounds\n")
    print(f"rules only           {min(rules) * 1e6:8.1f} us/event   {1 / min(rules):>10,.0f} events/s")
    if model is None:
        return
    runs = [run(events, model) for _ in range(args.rounds)]
    with_model = min(t for t, _ in runs)
    scored = runs[0][1]
    raised = sum(1 for e in scored if e.get("ml_reason"))
    p50, p99 = score_only(model, scored)
    added = with_model - min(rules)
    print(f"rules + model        {with_model * 1e6:8.1f} us/event   {1 / with_model:>10,.0f} events/s")
    print(f"model adds           {added * 1e6:8.1f} us/event   (score alone: p50 {p50:.1f} us, p99 {p99:.1f} us; "
          f"{model.trees} trees)")
    print(f"raised by the model  {raised} of {len(scored):,} events (explanations included above)")
    budget = 1e6 / args.rate
    print(f"\nbudget at {args.rate:,}/s: {budget:.0f} us per event on one core. "
          f"The Flink job measured ~173 us with rules only; with the model ~{173 + added * 1e6:.0f} us "
          f"= {(173 + added * 1e6) / budget:.0%} of the budget, "
          f"~{1e6 / (173 + added * 1e6):,.0f} events/s per TaskManager.")


if __name__ == "__main__":
    main()
