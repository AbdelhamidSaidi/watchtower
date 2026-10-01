#!/usr/bin/env python3
"""Replay the simulator through the per-event detection path, with no Kafka,
Flink or ClickHouse.

    python3 tools/replay_offline.py --seconds 900 --seed 7

The producer's generators feed the same Avro encode -> decode -> validate ->
normalize -> enrich -> window -> rules path the Flink job runs (etl/core),
one runner's state at a time. It reports, per incident kind, how many
incidents were caught and how fast, and how much normal traffic was flagged,
split into runners that had an incident (containment) and those that did not.

Rules only: no model is loaded. This is the quick check after changing a
rule, a threshold or the simulator -- `make evaluate` measures the live stack.
Needs `pip install fastavro`. tests/unit/test_simulation.py runs a short replay
as a regression test.
"""

import argparse
import collections
import datetime
import io
import itertools
import json
import os
import random
import sys
import types

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
for path in (ROOT, os.path.join(ROOT, "etl"), os.path.join(ROOT, "producer")):
    sys.path.insert(0, path)

import fastavro  # noqa: E402

try:
    import kafka  # noqa: F401
except ImportError:  # the producer imports it, the replay never sends anything
    sys.modules["kafka"] = types.SimpleNamespace(KafkaProducer=None)

import build_log_producer as sim  # noqa: E402
from core.processor import SourceState  # noqa: E402
from core.records import Decoder, enrich, normalize, reject_reason  # noqa: E402
from schemas.registry import frame, load_local_schema  # noqa: E402

SCHEMA_ID = 1


def replay(seconds=900, seed=7, incident_chance=0.01, rate=None):
    """Run the simulator through the per-event path. Returns the results as a
    dict: events, rejected, incidents (per kind: started, caught, events,
    quarantined, flagged, first_flags), normal (action counts) and
    uninvolved (flags on runners that had no incident)."""
    schema = load_local_schema()
    parsed = fastavro.parse_schema(json.loads(schema))
    decoder = Decoder({SCHEMA_ID: schema})
    nullable = [f["name"] for f in json.loads(schema)["fields"] if isinstance(f["type"], list)]

    random.seed(seed)
    if rate:
        sim.LOGS_PER_SECOND = rate
        sim.HOSTS_SCALE = max(1, round(rate / 100))
    # The farm is built when the producer is imported, before the seed is
    # set: rebuild it so a seed reproduces the run.
    sim.NETWORK = sim.build_network(sim.HOSTS_SCALE)
    sim.NETWORK_CUM_WEIGHTS = list(itertools.accumulate(h.weight for h in sim.NETWORK))
    sim.INCIDENT_START_CHANCE = incident_chance
    start = datetime.datetime(2026, 10, 1, 12, 0, 0, tzinfo=datetime.timezone.utc)
    budget = int(sim.LOGS_PER_SECOND * sim.MAX_INCIDENT_SHARE)

    states, active, incidents, incident_of = {}, [], [], {}
    affected = set()
    per_incident = collections.defaultdict(lambda: {"scenario": None, "events": 0, "quarantined": 0,
                                                    "flagged": 0, "first_flag": None})
    normal, uninvolved = collections.Counter(), collections.Counter()
    rejected = total = 0

    for second in range(seconds):
        new = sim.maybe_start_incident(active)
        if new:
            new.index = len(incidents)
            incidents.append(new)
            active.append(new)
            affected.add(new.runner_ip)
        batch = []
        for incident in list(active):
            logs = incident.tick()
            for log in logs:
                incident_of[log["event_id"]] = incident.index
            batch.extend(logs)
            if incident.remaining <= 0:
                active.remove(incident)
        batch = batch[:budget]
        while len(batch) < sim.LOGS_PER_SECOND:
            batch.append(sim.generate_normal())
        random.shuffle(batch)

        for i, log in enumerate(batch):
            log["timestamp"] = (start + datetime.timedelta(seconds=second + i / len(batch))).isoformat()
            for name in nullable:
                log.setdefault(name, None)
            buffer = io.BytesIO()
            fastavro.schemaless_writer(buffer, parsed, log)
            event, wire_error, _ = decoder.decode(frame(SCHEMA_ID, buffer.getvalue()))
            if reject_reason(event, wire_error):
                rejected += 1
                continue
            event = enrich(normalize(event))
            row = states.setdefault(event["runner_ip"], SourceState()).process(event)
            if row is None:
                continue
            total += 1
            action = row["recommended_action"]
            if log["scenario"] == "normal":
                normal[action] += 1
                if event["runner_ip"] not in affected and action != "ok":
                    uninvolved[(action, row["rule_hits"])] += 1
                continue
            stats = per_incident[incident_of[log["event_id"]]]
            stats["scenario"] = log["scenario"]
            stats["events"] += 1
            stats["quarantined"] += action == "quarantine"
            if action != "ok":
                stats["flagged"] += 1
                if stats["first_flag"] is None:
                    stats["first_flag"] = stats["events"]

    kinds = collections.defaultdict(lambda: {"incidents": 0, "caught": 0, "events": 0, "quarantined": 0,
                                             "flagged": 0, "first_flags": []})
    for incident in incidents:
        kinds[incident.kind]["incidents"] += 0   # a kind that started but emitted nothing still shows
    for stats in per_incident.values():
        kind = kinds[stats["scenario"]]
        kind["incidents"] += 1
        kind["events"] += stats["events"]
        kind["quarantined"] += stats["quarantined"]
        kind["flagged"] += stats["flagged"]
        if stats["first_flag"] is not None:
            kind["caught"] += 1
            kind["first_flags"].append(stats["first_flag"])
    return {"events": total, "rejected": rejected, "started": len(incidents), "kinds": dict(kinds),
            "normal": normal, "uninvolved": uninvolved}


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    parser.add_argument("--seconds", type=int, default=900)
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--incident-chance", type=float, default=0.01,
                        help="chance per second that each incident kind starts (the producer uses 0.003)")
    args = parser.parse_args()
    result = replay(args.seconds, args.seed, args.incident_chance)

    print(f"{result['events']:,} events decided, {result['rejected']} rejected, "
          f"{result['started']} incidents started\n")
    print(f"{'incident':<22}{'caught':>10}{'events':>9}{'quarantined':>13}{'flagged':>9}   first flag at event #")
    for name, kind in sorted(result["kinds"].items()):
        first = f"{min(kind['first_flags'])}-{max(kind['first_flags'])}" if kind["first_flags"] else "-"
        print(f"{name:<22}{kind['caught']:>5}/{kind['incidents']:<4}{kind['events']:>9,}"
              f"{kind['quarantined'] / kind['events']:>13.1%}{kind['flagged'] / kind['events']:>9.1%}   {first}")
    normal, uninvolved = result["normal"], result["uninvolved"]
    n = sum(normal.values())
    print(f"\nnormal events: {n:,}; quarantined {normal['quarantine']:,} and alerted {normal['alert']:,}, "
          f"nearly all on runners that had an incident (containment)")
    flagged = sum(uninvolved.values())
    print(f"flagged on runners with no incident: {flagged} ({flagged / max(n, 1):.4%})")
    for (action, rules), count in uninvolved.most_common(5):
        print(f"  {count:>4}  {action}  {rules}")


if __name__ == "__main__":
    main()
