"""
Measure detection against ground truth.

The producer stamps every event with `scenario` -- "normal" or the attack
name. The pipeline never reads that field. This tool reads it back out of
Kafka, joins it to the pipeline's decision in ClickHouse by event_id, and
reports, per scenario, how often the pipeline said allow / alert / block.

    python tools/evaluate_detection.py --minutes 15

Only meaningful against the SYNTHETIC producer: real logs have no ground
truth. On real traffic, precision comes from analysts triaging alerts.
"""

import argparse
import base64
import collections
import io
import json
import os
import sys
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

import fastavro  # noqa: E402
from kafka import KafkaConsumer  # noqa: E402

from schemas.registry import DEFAULT_SUBJECT, SchemaRegistry, unframe  # noqa: E402


def ground_truth(bootstrap, topic, registry_url):
    """{event_id: scenario} for every decodable message in the topic."""
    schemas = {
        schema_id: fastavro.parse_schema(json.loads(text))
        for schema_id, text in SchemaRegistry(registry_url).all_versions(DEFAULT_SUBJECT).items()
    }
    from kafka import TopicPartition

    consumer = KafkaConsumer(bootstrap_servers=bootstrap, enable_auto_commit=False)
    partitions = [TopicPartition(topic, p) for p in consumer.partitions_for_topic(topic)]
    consumer.assign(partitions)
    consumer.seek_to_beginning(*partitions)

    # Snapshot where each partition ends NOW and read up to there. Waiting for
    # the topic to go quiet never ends: the producer writes 100 events/sec.
    end = consumer.end_offsets(partitions)
    remaining = {tp for tp in partitions if end[tp] > 0}

    truth = {}
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
                    continue  # the rejected path is evaluated separately
                truth[record["event_id"]] = record.get("scenario") or "unknown"
            if consumer.position(tp) >= end[tp]:
                remaining.discard(tp)
    consumer.close()
    return truth


def decisions(clickhouse_url, password, minutes):
    query = (
        "SELECT event_id, recommended_action, rule_hits FROM watchtower.security_events "
        f"WHERE timestamp > now() - INTERVAL {int(minutes)} MINUTE FORMAT TSV"
    )
    request = urllib.request.Request(
        f"{clickhouse_url}/?" + urllib.parse.urlencode({"query": query}),
        headers={"Authorization": "Basic " + base64.b64encode(f"watchtower:{password}".encode()).decode()},
    )
    rows = urllib.request.urlopen(request, timeout=60).read().decode().splitlines()
    return [line.split("\t") for line in rows if line]


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    parser.add_argument("--kafka", default="localhost:9092")
    parser.add_argument("--topic", default="security-logs")
    parser.add_argument("--registry", default="http://localhost:8081")
    parser.add_argument("--clickhouse", default="http://localhost:8123")
    parser.add_argument("--password-file", default="secrets/clickhouse_password")
    parser.add_argument("--minutes", type=int, default=15)
    args = parser.parse_args()

    truth = ground_truth(args.kafka, args.topic, args.registry)
    password = open(args.password_file).read().strip()
    rows = decisions(args.clickhouse, password, args.minutes)

    per = collections.defaultdict(collections.Counter)
    rules = collections.defaultdict(collections.Counter)
    for event_id, action, hits in rows:
        scenario = truth.get(event_id)
        if scenario is None:
            continue
        per[scenario][action] += 1
        for hit in filter(None, hits.split(",")):
            rules[scenario][hit] += 1

    print(f"{'scenario':<22}{'events':>8}{'block':>9}{'alert':>9}{'allow':>9}   top rules")
    print("-" * 96)
    order = sorted(per, key=lambda s: (s != "normal", s))
    for scenario in order:
        c = per[scenario]
        n = sum(c.values())
        top = ", ".join(f"{r}({k})" for r, k in rules[scenario].most_common(3)) or "-"
        print(f"{scenario:<22}{n:>8}{c['block']/n:>9.1%}{c['alert']/n:>9.1%}{c['allow']/n:>9.1%}   {top}")

    attack = collections.Counter()
    for scenario, c in per.items():
        if scenario != "normal":
            attack.update(c)
    normal = per.get("normal", collections.Counter())
    if attack:
        a = sum(attack.values())
        print("-" * 96)
        print(f"attack events stopped (block)        : {attack['block']/a:.1%}")
        print(f"attack events flagged (block+alert)  : {(attack['block']+attack['alert'])/a:.1%}")
    if normal:
        n = sum(normal.values())
        print(f"normal events wrongly blocked        : {normal['block']/n:.3%}  ({normal['block']} of {n})")
        print(f"normal events alerted                : {normal['alert']/n:.3%}  ({normal['alert']} of {n})")


if __name__ == "__main__":
    main()
