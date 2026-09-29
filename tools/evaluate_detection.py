"""
Measure detection against ground truth.

The producer stamps every event with `scenario` -- "normal" or the attack
name. The pipeline never reads that field. This tool reads it back out of
Kafka, joins it to the pipeline's decision in ClickHouse by event_id, and
reports:

  - per scenario, how often the pipeline said allow / alert / block
  - precision: of what was blocked or flagged, how much was an attack
  - false positives, split into CONTAINMENT (a compromised host's ordinary
    traffic, blocked along with its attack) and uninvolved hosts
  - the ML model's own alerts (flagged with no rule behind them): how many
    were attacks
  - per attack (one scenario from one source, split on a 60 s pause):
    whether it was caught, and how long it ran before the first alert --
    the number a per-event live path exists for
  - coverage: events in Kafka with no decision, rejected (and why) or
    missing

    python tools/evaluate_detection.py --minutes 15          # table
    python tools/evaluate_detection.py --minutes 15 --json   # for machines

The window is the last N minutes of messages in Kafka, by broker append
time, up to the moment the tool starts. The pipeline is live, so the newest
events are still in flight then: the tool polls ClickHouse until every event
is decided or a poll finds nothing new (--max-wait caps it).

Also run on a schedule by Airflow (orchestration/dags/watchtower_detection_quality.py),
which keeps every report in watchtower.detection_quality.

Only meaningful against the SYNTHETIC producer: real logs have no ground
truth. On real traffic, precision comes from analysts triaging alerts.
"""

import argparse
import base64
import collections
import io
import json
import os
import statistics
import sys
import time
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

import fastavro  # noqa: E402
from kafka import KafkaConsumer, TopicPartition  # noqa: E402

from schemas.registry import DEFAULT_SUBJECT, SchemaRegistry, unframe  # noqa: E402

# An event is stamped by the producer just before it is sent, so its
# `timestamp` precedes its Kafka append time by milliseconds. The slack
# only has to cover that and host/VM clock skew.
SLACK_MS = 60_000

# A pause longer than this ends an attack: the next events of the same kind
# from the same source are a new attack.
ATTACK_GAP_MS = 60_000

# The rules keep state per source_ip, and an attack's evidence stays in the
# 5-minute windows after it stops. Normal traffic from that source, during
# the attack or up to this long after, is blocked WITH it: a compromised
# workstation stopped as a whole. That is containment, not a false positive
# on an uninvolved host. An attack from a source that attacked within this
# long before is caught on its first event -- the source is already known --
# so it is left out of the time-to-detect median.
CONTAINMENT_MS = 5 * 60_000


def ground_truth(bootstrap, topic, registry_url, since_ms):
    """Every message appended to `topic` since `since_ms`, up to its end now.

    Returns ({event_id: (scenario, partition, offset)}, number of messages
    that did not decode).
    """
    schemas = {
        schema_id: fastavro.parse_schema(json.loads(text))
        for schema_id, text in SchemaRegistry(registry_url).all_versions(DEFAULT_SUBJECT).items()
    }

    consumer = KafkaConsumer(bootstrap_servers=bootstrap, enable_auto_commit=False)
    partitions = [TopicPartition(topic, p) for p in consumer.partitions_for_topic(topic)]
    consumer.assign(partitions)

    # Snapshot where each partition ends NOW and read up to there. Waiting for
    # the topic to go quiet never ends: the producer keeps writing. Start
    # at the window, not the beginning: the topic keeps a day, ~86M
    # messages at 1,000/s.
    end = consumer.end_offsets(partitions)
    start = consumer.offsets_for_times({tp: since_ms for tp in partitions})
    for tp in partitions:
        consumer.seek(tp, start[tp].offset if start[tp] else end[tp])
    remaining = {tp for tp in partitions if consumer.position(tp) < end[tp]}

    truth, undecodable = {}, 0
    while remaining:
        for tp, messages in consumer.poll(timeout_ms=2000, max_records=5000).items():
            for message in messages:
                if message.offset >= end[tp]:
                    remaining.discard(tp)
                    break
                try:
                    schema_id, payload = unframe(message.value)
                    record = fastavro.schemaless_reader(io.BytesIO(payload), schemas[schema_id])
                except Exception:
                    undecodable += 1
                    continue
                truth[record["event_id"]] = (record.get("scenario") or "unknown", tp.partition, message.offset)
            if consumer.position(tp) >= end[tp]:
                remaining.discard(tp)
    consumer.close()
    return truth, undecodable


def query(clickhouse_url, password, sql):
    request = urllib.request.Request(
        f"{clickhouse_url}/?" + urllib.parse.urlencode({"query": sql + " FORMAT TSV"}),
        headers={"Authorization": "Basic " + base64.b64encode(f"watchtower:{password}".encode()).decode()},
    )
    rows = urllib.request.urlopen(request, timeout=120).read().decode().splitlines()
    return [line.split("\t") for line in rows if line]


def decisions(clickhouse_url, password, since_ms):
    """{event_id: (action, rule_hits, source_ip, timestamp_ms, copies)}.

    At-least-once delivery can store an event twice until ReplacingMergeTree
    merges the copies. argMax keeps the newest, as the merge will, so each
    event counts once; `copies` shows what the merge has yet to fold.
    """
    rows = query(clickhouse_url, password, (
        "SELECT event_id, argMax(recommended_action, ingested_at), argMax(rule_hits, ingested_at), "
        "any(source_ip), min(toUnixTimestamp64Milli(timestamp)), count() "
        "FROM watchtower.security_events "
        f"WHERE timestamp >= fromUnixTimestamp64Milli(toInt64({since_ms - SLACK_MS})) "
        "GROUP BY event_id"
    ))
    return {r[0]: (r[1], r[2], r[3], int(r[4]), int(r[5])) for r in rows}


def settled_decisions(clickhouse_url, password, since_ms, truth, settle, max_wait):
    """Decisions for the window, once they stop arriving.

    Polls every `settle` seconds while events are still undecided and the
    last poll found more of them decided. What is missing when a poll finds
    nothing new is rejected or lost, not late.
    """
    deadline = time.monotonic() + max_wait
    time.sleep(settle)
    decided = decisions(clickhouse_url, password, since_ms)
    missing = sum(1 for event_id in truth if event_id not in decided)
    while missing and time.monotonic() < deadline:
        time.sleep(settle)
        decided = decisions(clickhouse_url, password, since_ms)
        still = sum(1 for event_id in truth if event_id not in decided)
        if still >= missing:
            break
        missing = still
    return decided


def rejected(clickhouse_url, password, topic, since_ms):
    """{(partition, offset): reject_reason} for the window's refused messages."""
    rows = query(clickhouse_url, password, (
        "SELECT kafka_partition, kafka_offset, any(reject_reason) FROM watchtower.rejected_events "
        f"WHERE kafka_topic = '{topic}' "
        f"AND kafka_timestamp >= fromUnixTimestamp64Milli(toInt64({since_ms - SLACK_MS})) "
        "GROUP BY kafka_partition, kafka_offset"
    ))
    return {(int(r[0]), int(r[1])): r[2] for r in rows}


def attacks(joined, since_ms):
    """Split attack events into attacks: (scenario, source_ip), a new one
    after a pause of ATTACK_GAP_MS. In order of start."""
    by_source = collections.defaultdict(list)
    for scenario, action, _, source_ip, ts in joined:
        if scenario != "normal":
            by_source[(scenario, source_ip)].append((ts, action))

    found = []
    for (scenario, source_ip), events in by_source.items():
        events.sort()
        runs, current = [], [events[0]]
        for event in events[1:]:
            if event[0] - current[-1][0] > ATTACK_GAP_MS:
                runs.append(current)
                current = []
            current.append(event)
        runs.append(current)
        for run in runs:
            first = next((i for i, (_, action) in enumerate(run) if action != "allow"), None)
            found.append({
                "scenario": scenario,
                "source_ip": source_ip,
                "start_ms": run[0][0],
                "end_ms": run[-1][0],
                "events": len(run),
                "flagged": sum(1 for _, action in run if action != "allow"),
                "first_flag_events": first,
                "first_flag_s": None if first is None else (run[first][0] - run[0][0]) / 1000,
                # Running when the window opened: features built up before
                # it, so its time to detect is understated.
                "started_before_window": run[0][0] - since_ms < 2_000,
            })
    found.sort(key=lambda a: a["start_ms"])

    # Known source: it attacked (any kind) within CONTAINMENT_MS before.
    for a in found:
        a["known_source"] = any(
            b is not a and b["source_ip"] == a["source_ip"]
            and b["start_ms"] < a["start_ms"] <= b["end_ms"] + CONTAINMENT_MS
            for b in found
        )
    return sorted(found, key=lambda a: (a["scenario"], a["start_ms"]))


def contained(source_ip, ts, found):
    """Is this event inside an attack from its source, or its aftermath?"""
    return any(
        a["source_ip"] == source_ip
        and (a["started_before_window"] or a["start_ms"] <= ts)
        and ts <= a["end_ms"] + CONTAINMENT_MS
        for a in found
    )


def ratio(part, whole):
    return part / whole if whole else None


def summarize(truth, undecodable, decided, refused, since_ms, minutes):
    """The report, from what was read. No I/O: tests feed it directly."""
    joined, missing, reasons, copies = [], 0, collections.Counter(), 0
    for event_id, (scenario, partition, offset) in truth.items():
        row = decided.get(event_id)
        if row is None:
            reason = refused.get((partition, offset))
            if reason is None:
                missing += 1
            else:
                reasons[reason] += 1
            continue
        action, hits, source_ip, ts, n = row
        copies += n - 1
        joined.append((scenario, action, hits, source_ip, ts))

    per = collections.defaultdict(collections.Counter)
    rules = collections.defaultdict(collections.Counter)
    for scenario, action, hits, _, _ in joined:
        per[scenario][action] += 1
        for hit in filter(None, hits.split(",")):
            rules[scenario][hit] += 1

    found = attacks(joined, since_ms)
    normal_blocked = [(ip, ts) for s, action, _, ip, ts in joined if s == "normal" and action == "block"]
    blocked_contained = sum(1 for ip, ts in normal_blocked if contained(ip, ts, found))

    attack = collections.Counter()
    for scenario, c in per.items():
        if scenario != "normal":
            attack.update(c)
    normal = per.get("normal", collections.Counter())
    a, n = sum(attack.values()), sum(normal.values())
    blocked = attack["block"] + normal["block"]
    flagged = blocked + attack["alert"] + normal["alert"]
    # Flagged with no rule behind them: the ML model's decision alone.
    model_only = [s for s, action, hits, _, _ in joined if action != "allow" and not hits]
    model_only_attacks = sum(1 for s in model_only if s != "normal")
    timed = [x["first_flag_s"] for x in found if x["first_flag_events"] is not None
             and not x["started_before_window"] and not x["known_source"]]
    total = len(truth) + undecodable

    return {
        "window": {"minutes": minutes, "since_ms": since_ms, "events": len(truth)},
        "scenarios": {
            scenario: {"events": sum(c.values()), "block": c["block"], "alert": c["alert"],
                       "allow": c["allow"], "top_rules": rules[scenario].most_common(3)}
            for scenario, c in per.items()
        },
        "attacks": found,
        "coverage": {"decoded": len(truth), "undecodable": undecodable, "decided": len(joined),
                     "rejected": dict(reasons), "missing": missing, "duplicates": copies},
        "summary": {
            "attack_events": a,
            "attack_blocked": ratio(attack["block"], a),
            "attack_flagged": ratio(attack["block"] + attack["alert"], a),
            "normal_events": n,
            "normal_blocked": normal["block"],
            "normal_blocked_contained": blocked_contained,
            "normal_blocked_uninvolved": normal["block"] - blocked_contained,
            "normal_alerted": normal["alert"],
            "precision_block": ratio(attack["block"], blocked),
            "precision_flag": ratio(attack["block"] + attack["alert"], flagged),
            "precision_block_with_containment": ratio(attack["block"] + blocked_contained, blocked),
            "attacks_seen": len(found),
            "attacks_caught": sum(1 for x in found if x["first_flag_events"] is not None),
            "median_time_to_flag_s": statistics.median(timed) if timed else None,
            "coverage": ratio(len(joined), total),
            "model_only_flags": len(model_only),
            "model_only_attacks": model_only_attacks,
            "model_only_precision": ratio(model_only_attacks, len(model_only)),
        },
    }


def evaluate(kafka, topic, registry, clickhouse, password, minutes, settle=5.0, max_wait=120.0):
    since_ms = int(time.time() * 1000) - minutes * 60_000
    truth, undecodable = ground_truth(kafka, topic, registry, since_ms)
    decided = settled_decisions(clickhouse, password, since_ms, truth, settle, max_wait)
    refused = rejected(clickhouse, password, topic, since_ms)
    return summarize(truth, undecodable, decided, refused, since_ms, minutes)


def pct(value, digits=1):
    return "-" if value is None else f"{value:.{digits}%}"


def print_report(r):
    s, cov = r["summary"], r["coverage"]
    print(f"window: last {r['window']['minutes']} min, {r['window']['events']:,} events\n")
    print(f"{'scenario':<22}{'events':>8}{'block':>9}{'alert':>9}{'allow':>9}   top rules")
    print("-" * 96)
    for scenario in sorted(r["scenarios"], key=lambda x: (x != "normal", x)):
        c = r["scenarios"][scenario]
        n = c["events"]
        top = ", ".join(f"{rule}({k})" for rule, k in c["top_rules"]) or "-"
        print(f"{scenario:<22}{n:>8}{c['block']/n:>9.1%}{c['alert']/n:>9.1%}{c['allow']/n:>9.1%}   {top}")
    print("-" * 96)
    if s["attack_events"]:
        print(f"attack events stopped (block)        : {pct(s['attack_blocked'])}")
        print(f"attack events flagged (block+alert)  : {pct(s['attack_flagged'])}")
    if s["normal_events"]:
        n = s["normal_events"]
        print(f"normal events blocked                : {s['normal_blocked']/n:.3%}  ({s['normal_blocked']} of {n})")
        print(f"  on a host during/after its attack  : {s['normal_blocked_contained']}   (containment)")
        print(f"  on uninvolved hosts                : {s['normal_blocked_uninvolved']}   "
              f"({s['normal_blocked_uninvolved']/n:.4%})")
        print(f"normal events alerted                : {s['normal_alerted']/n:.3%}  ({s['normal_alerted']} of {n})")
    print(f"precision of block (attack share)    : {pct(s['precision_block'])}"
          f"   counting containment: {pct(s['precision_block_with_containment'])}")
    print(f"precision of block+alert             : {pct(s['precision_flag'])}")
    print(f"flagged by the ML model alone        : {s['model_only_flags']}, of which attacks "
          f"{s['model_only_attacks']} ({pct(s['model_only_precision'])})")

    if r["attacks"]:
        print(f"\n{'attack':<22}{'source':<16}{'events':>7}{'flagged':>9}   first flag after")
        print("-" * 96)
        for x in r["attacks"]:
            if x["first_flag_events"] is None:
                after = "MISSED"
            else:
                after = f"{x['first_flag_events']} events, {x['first_flag_s']:.1f} s"
            notes = ("  *" if x["started_before_window"] else "") + ("  (known source)" if x["known_source"] else "")
            print(f"{x['scenario']:<22}{x['source_ip']:<16}{x['events']:>7}"
                  f"{pct(x['flagged'] / x['events']):>9}   {after}{notes}")
        print("-" * 96)
        print("* running when the window opened; known source: it attacked in the 5 min before")
        median = s["median_time_to_flag_s"]
        print(f"attacks caught                       : {s['attacks_caught']}/{s['attacks_seen']}")
        print(f"median time to first flag (new source): {'-' if median is None else f'{median:.1f} s'}")

    total = cov["decoded"] + cov["undecodable"]
    print("\ncoverage")
    extra = f"  (+{cov['undecodable']} undecodable)" if cov["undecodable"] else ""
    print(f"  in Kafka, decoded                  : {cov['decoded']:,}{extra}")
    print(f"  decided                            : {cov['decided']:,}  ({pct(s['coverage'])})")
    for reason, count in sorted(cov["rejected"].items(), key=lambda kv: -kv[1]):
        print(f"  rejected: {reason:<25}: {count:,}")
    print(f"  no decision, not rejected          : {cov['missing']:,}  ({pct(ratio(cov['missing'], total))})")
    print(f"  duplicate rows awaiting merge      : {cov['duplicates']:,}")


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    parser.add_argument("--kafka", default="localhost:9092")
    parser.add_argument("--topic", default="security-logs")
    parser.add_argument("--registry", default="http://localhost:8081")
    parser.add_argument("--clickhouse", default="http://localhost:8123")
    parser.add_argument("--password-file", default="secrets/clickhouse_password")
    parser.add_argument("--minutes", type=int, default=15)
    parser.add_argument("--settle", type=float, default=5.0,
                        help="seconds between polls for the last events to reach ClickHouse")
    parser.add_argument("--max-wait", type=float, default=120.0,
                        help="stop polling after this many seconds")
    parser.add_argument("--json", action="store_true", help="print the report as JSON")
    args = parser.parse_args()

    password = open(args.password_file).read().strip()
    report = evaluate(args.kafka, args.topic, args.registry, args.clickhouse, password,
                      args.minutes, args.settle, args.max_wait)
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print_report(report)


if __name__ == "__main__":
    main()
