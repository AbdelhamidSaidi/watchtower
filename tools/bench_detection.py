"""
Per-event detection cost with and without the ML model -- the budget test.

At 1,000 events/s every event has 1 ms, end to end, before the next
second's arrive. This runs a realistic stream -- ~1,800 runners, normal
build traffic plus failure-storm and 404-flood bursts that fill the rolling windows --
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
SICK = ["10.0.14.16", "10.0.14.17", "192.168.4.94", "102.67.14.189"]
PROJECTS = ["payments-api", "web-frontend", "auth-service", "search-indexer", "kernel-modules"]
ARTIFACTS = ["/maven2/org/x/lib-1.0.jar", "/npm/react/-/react-18.2.0.tgz", "/crates/api/v1/crates/serde/1.0.1/download"]


def stream(n, rate, seed=11):
    """n events at `rate` per second: 97% normal from ~1,800 runners, 3%
    incident bursts from a few sick runners."""
    rng = random.Random(seed)
    runners = [f"192.168.{i // 250}.{i % 250 + 2}" for i in range(1780)]
    out = []
    for i in range(n):
        ts = (T0 + timedelta(seconds=i / rate)).isoformat()
        base = {"event_id": str(uuid.UUID(int=rng.getrandbits(128), version=4)), "timestamp": ts,
                "severity": "INFO", "hostname": "ws-001"}
        if rng.random() < 0.03:
            src, kind = rng.choice(SICK), rng.choice(["retry", "oom", "missing"])
            if kind == "retry":
                base.update(event_type="BUILD_FAILURE", runner_ip=src, project=rng.choice(PROJECTS),
                            reason="compile_error", exit_code=1, error_message="error: expected ';'")
            elif kind == "oom":
                base.update(event_type="COMPILE_STEP", runner_ip=src, project=rng.choice(PROJECTS),
                            exit_code=137, error_message="clang: error: unable to execute command: Killed",
                            duration_ms=rng.randint(20_000, 120_000), peak_memory_mb=rng.randint(7_000, 16_000))
            else:
                base.update(event_type="DEPENDENCY_FETCH", runner_ip=src, project=rng.choice(PROJECTS),
                            http_method="GET", url_path=f"/maven2/com/acme/legacy-{rng.randint(1, 500)}/1.0/x.jar",
                            http_status=404)
        else:
            kind = rng.choices(["COMPILE_STEP", "DEPENDENCY_FETCH", "BUILD_SUCCESS", "TEST_RUN",
                                "BUILD_FAILURE"], weights=[50, 15, 15, 15, 5])[0]
            base.update(event_type=kind, runner_ip=rng.choice(runners), project=rng.choice(PROJECTS),
                        http_method="GET", url_path=rng.choice(ARTIFACTS), http_status=200,
                        user_agent="gradle/8.10.2", bytes_sent=rng.randint(200, 400_000),
                        command="gcc -O2 -c src/net/parser.c" if kind == "COMPILE_STEP" else None,
                        duration_ms=rng.randint(300, 20_000), peak_memory_mb=rng.randint(60, 900),
                        cache_status="hit" if rng.random() < 0.8 else "miss", process_uid=1001)
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
        state = states.get(event["runner_ip"])
        if state is None:
            state = states[event["runner_ip"]] = SourceState(model=model)
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
