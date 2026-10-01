"""
Measure detection against ground truth.

The producer stamps every event with `scenario` -- "normal" or the incident
name. The pipeline never reads that field. This tool reads it back out of
Kafka, joins it to the pipeline's decision in ClickHouse by event_id, and
reports:

  - per scenario, how often the pipeline said ok / alert / quarantine
  - precision: of what was quarantined or flagged, how much was an incident
  - false positives, split into CONTAINMENT (a faulty runner's ordinary
    traffic, quarantined along with its incident) and uninvolved runners
  - the ML model's own alerts (flagged with no rule behind them): how many
    were incidents
  - per incident (one scenario on one runner, split on a 60 s pause):
    whether it was caught, and how long it ran before the first alert --
    the number a per-event live path exists for
  - coverage: events in Kafka with no decision, rejected (and why) or
    missing

    python tools/evaluate_detection.py --minutes 15          # table
    python tools/evaluate_detection.py --minutes 15 --json   # for machines

The window is the last N minutes of messages in Kafka, by broker append
time, up to the moment the tool starts. The tool also reads 5 minutes before
it (--lead-in-minutes) so a runner whose incident ended just before the window,
but whose rolling windows still carry it, is not mistaken for a false positive;
only events inside the window are counted. The pipeline is live, so the newest
events are still in flight then: the tool polls ClickHouse until every event
is decided or a poll finds nothing new (--max-wait caps it).

Also run on a schedule by Airflow (orchestration/dags/watchtower_detection_quality.py),
which keeps every report in watchtower.detection_quality.

Only meaningful against the SYNTHETIC producer: real logs have no ground
truth. On real traffic, precision comes from engineers triaging alerts.
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

# A pause longer than this ends an incident: the next events of the same kind
# from the same source are a new incident.
INCIDENT_GAP_MS = 60_000

# The rules keep state per runner_ip, and an incident's evidence stays in the
# 5-minute windows after it stops. Normal traffic from that source, during
# the incident or up to this long after, is quarantined WITH it: a faulty
# runner stopped as a whole. That is containment, not a false positive
# on an uninvolved host. An incident from a source that hit within this
# long before is caught on its first event -- the source is already known --
# so it is left out of the time-to-detect median.
CONTAINMENT_MS = 5 * 60_000

# The tool also reads this much BEFORE the window, to see incidents that ended
# just before it: a runner's windows still hold their evidence, and without
# them its normal events inside the window look like false positives on an
# uninvolved runner. Only events inside the window are counted.
LEAD_IN_MS = CONTAINMENT_MS


def ground_truth(bootstrap, topic, registry_url, since_ms, lead_in_ms=0):
    """Every message appended to `topic` since `since_ms - lead_in_ms`, up to
    its end now.

    Returns ({event_id: (scenario, partition, offset)}, number of window
    messages that did not decode, {partition: first offset of the window}).
    The lead-in is read so incidents just before the window are known; the
    offsets say which messages belong to the window itself.
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
    start = consumer.offsets_for_times({tp: since_ms - lead_in_ms for tp in partitions})
    window = consumer.offsets_for_times({tp: since_ms for tp in partitions})
    window_start = {tp.partition: window[tp].offset if window[tp] else end[tp] for tp in partitions}
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
                    undecodable += message.offset >= window_start[tp.partition]
                    continue
                truth[record["event_id"]] = (record.get("scenario") or "unknown", tp.partition, message.offset)
            if consumer.position(tp) >= end[tp]:
                remaining.discard(tp)
    consumer.close()
    return truth, undecodable, window_start


def query(clickhouse_url, password, sql):
    request = urllib.request.Request(
        f"{clickhouse_url}/?" + urllib.parse.urlencode({"query": sql + " FORMAT TSV"}),
        headers={"Authorization": "Basic " + base64.b64encode(f"watchtower:{password}".encode()).decode()},
    )
    rows = urllib.request.urlopen(request, timeout=120).read().decode().splitlines()
    return [line.split("\t") for line in rows if line]


def decisions(clickhouse_url, password, since_ms):
    """{event_id: (action, rule_hits, runner_ip, timestamp_ms, copies)}.

    At-least-once delivery can store an event twice until ReplacingMergeTree
    merges the copies. argMax keeps the newest, as the merge will, so each
    event counts once; `copies` shows what the merge has yet to fold.
    """
    rows = query(clickhouse_url, password, (
        "SELECT event_id, argMax(recommended_action, ingested_at), argMax(rule_hits, ingested_at), "
        "any(runner_ip), min(toUnixTimestamp64Milli(timestamp)), count() "
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


def incidents(joined, since_ms):
    """Split incident events into incidents: (scenario, runner_ip), a new one
    after a pause of INCIDENT_GAP_MS. In order of start. `since_ms` is where
    the events begin (the lead-in's start, if there is one): an incident
    already running then has an understated time to detect."""
    by_source = collections.defaultdict(list)
    for scenario, action, _, runner_ip, ts in joined:
        if scenario != "normal":
            by_source[(scenario, runner_ip)].append((ts, action))

    found = []
    for (scenario, runner_ip), events in by_source.items():
        events.sort()
        runs, current = [], [events[0]]
        for event in events[1:]:
            if event[0] - current[-1][0] > INCIDENT_GAP_MS:
                runs.append(current)
                current = []
            current.append(event)
        runs.append(current)
        for run in runs:
            first = next((i for i, (_, action) in enumerate(run) if action != "ok"), None)
            found.append({
                "scenario": scenario,
                "runner_ip": runner_ip,
                "start_ms": run[0][0],
                "end_ms": run[-1][0],
                "events": len(run),
                "flagged": sum(1 for _, action in run if action != "ok"),
                "first_flag_events": first,
                "first_flag_s": None if first is None else (run[first][0] - run[0][0]) / 1000,
                # Running when the window opened: features built up before
                # it, so its time to detect is understated.
                "started_before_window": run[0][0] - since_ms < 2_000,
            })
    found.sort(key=lambda a: a["start_ms"])

    # Known source: it hit (any kind) within CONTAINMENT_MS before.
    for a in found:
        a["known_source"] = any(
            b is not a and b["runner_ip"] == a["runner_ip"]
            and b["start_ms"] < a["start_ms"] <= b["end_ms"] + CONTAINMENT_MS
            for b in found
        )
    return sorted(found, key=lambda a: (a["scenario"], a["start_ms"]))


def contained(runner_ip, ts, found):
    """Is this event inside an incident from its source, or its aftermath?"""
    return any(
        a["runner_ip"] == runner_ip
        and (a["started_before_window"] or a["start_ms"] <= ts)
        and ts <= a["end_ms"] + CONTAINMENT_MS
        for a in found
    )


def ratio(part, whole):
    return part / whole if whole else None


def summarize(truth, undecodable, decided, refused, since_ms, minutes,
              window_start=None, lead_in_ms=0):
    """The report, from what was read. No I/O: tests feed it directly.

    `truth` may start `lead_in_ms` before the window (`since_ms`);
    `window_start` is {partition: first offset of the window}. Lead-in events
    only tell which runners already had an incident -- they are not counted.
    Without a window_start everything is the window.
    """
    window_start = window_start or {}
    joined, joined_all, missing, reasons, copies = [], [], 0, collections.Counter(), 0
    for event_id, (scenario, partition, offset) in truth.items():
        in_window = offset >= window_start.get(partition, 0)
        row = decided.get(event_id)
        if row is None:
            if not in_window:
                continue
            reason = refused.get((partition, offset))
            if reason is None:
                missing += 1
            else:
                reasons[reason] += 1
            continue
        action, hits, runner_ip, ts, n = row
        joined_all.append((scenario, action, hits, runner_ip, ts))
        if in_window:
            copies += n - 1
            joined.append((scenario, action, hits, runner_ip, ts))

    per = collections.defaultdict(collections.Counter)
    rules = collections.defaultdict(collections.Counter)
    for scenario, action, hits, _, _ in joined:
        per[scenario][action] += 1
        for hit in filter(None, hits.split(",")):
            rules[scenario][hit] += 1

    # Incidents are found in everything read, the lead-in included, so a
    # runner that had one just before the window is known; the report lists
    # those that touch the window.
    known = incidents(joined_all, since_ms - lead_in_ms)
    found = [x for x in known if x["end_ms"] >= since_ms]
    normal_quarantined = [(ip, ts) for s, action, _, ip, ts in joined if s == "normal" and action == "quarantine"]
    quarantined_contained = sum(1 for ip, ts in normal_quarantined if contained(ip, ts, known))

    incident = collections.Counter()
    for scenario, c in per.items():
        if scenario != "normal":
            incident.update(c)
    normal = per.get("normal", collections.Counter())
    a, n = sum(incident.values()), sum(normal.values())
    quarantined = incident["quarantine"] + normal["quarantine"]
    flagged = quarantined + incident["alert"] + normal["alert"]
    # Flagged with no rule behind them: the ML model's decision alone.
    model_only = [s for s, action, hits, _, _ in joined if action != "ok" and not hits]
    model_only_incidents = sum(1 for s in model_only if s != "normal")
    timed = [x["first_flag_s"] for x in found if x["first_flag_events"] is not None
             and not x["started_before_window"] and not x["known_source"]]
    total = len(joined) + missing + sum(reasons.values()) + undecodable

    return {
        "window": {"minutes": minutes, "since_ms": since_ms, "lead_in_ms": lead_in_ms,
                   "events": len(joined) + missing + sum(reasons.values())},
        "scenarios": {
            scenario: {"events": sum(c.values()), "quarantine": c["quarantine"], "alert": c["alert"],
                       "ok": c["ok"], "top_rules": rules[scenario].most_common(3)}
            for scenario, c in per.items()
        },
        "incidents": found,
        "coverage": {"decoded": len(joined) + missing + sum(reasons.values()), "undecodable": undecodable, "decided": len(joined),
                     "rejected": dict(reasons), "missing": missing, "duplicates": copies},
        "summary": {
            "incident_events": a,
            "incident_quarantined": ratio(incident["quarantine"], a),
            "incident_flagged": ratio(incident["quarantine"] + incident["alert"], a),
            "normal_events": n,
            "normal_quarantined": normal["quarantine"],
            "normal_quarantined_contained": quarantined_contained,
            "normal_quarantined_uninvolved": normal["quarantine"] - quarantined_contained,
            "normal_alerted": normal["alert"],
            "precision_quarantine": ratio(incident["quarantine"], quarantined),
            "precision_flag": ratio(incident["quarantine"] + incident["alert"], flagged),
            "precision_quarantine_with_containment": ratio(incident["quarantine"] + quarantined_contained, quarantined),
            "incidents_seen": len(found),
            "incidents_caught": sum(1 for x in found if x["first_flag_events"] is not None),
            "median_time_to_flag_s": statistics.median(timed) if timed else None,
            "coverage": ratio(len(joined), total),
            "model_only_flags": len(model_only),
            "model_only_incidents": model_only_incidents,
            "model_only_precision": ratio(model_only_incidents, len(model_only)),
        },
    }


def evaluate(kafka, topic, registry, clickhouse, password, minutes, settle=5.0, max_wait=120.0,
             lead_in_ms=LEAD_IN_MS):
    since_ms = int(time.time() * 1000) - minutes * 60_000
    read_from = since_ms - lead_in_ms
    truth, undecodable, window_start = ground_truth(kafka, topic, registry, since_ms, lead_in_ms)
    decided = settled_decisions(clickhouse, password, read_from, truth, settle, max_wait)
    refused = rejected(clickhouse, password, topic, since_ms)
    return summarize(truth, undecodable, decided, refused, since_ms, minutes, window_start, lead_in_ms)


def pct(value, digits=1):
    return "-" if value is None else f"{value:.{digits}%}"


def print_report(r):
    s, cov = r["summary"], r["coverage"]
    print(f"window: last {r['window']['minutes']} min, {r['window']['events']:,} events\n")
    print(f"{'scenario':<22}{'events':>8}{'quarantine':>12}{'alert':>9}{'ok':>9}   top rules")
    print("-" * 99)
    for scenario in sorted(r["scenarios"], key=lambda x: (x != "normal", x)):
        c = r["scenarios"][scenario]
        n = c["events"]
        top = ", ".join(f"{rule}({k})" for rule, k in c["top_rules"]) or "-"
        print(f"{scenario:<22}{n:>8}{c['quarantine']/n:>12.1%}{c['alert']/n:>9.1%}{c['ok']/n:>9.1%}   {top}")
    print("-" * 99)
    if s["incident_events"]:
        print(f"incident events stopped (quarantine)   : {pct(s['incident_quarantined'])}")
        print(f"incident events flagged (quarantine+alert): {pct(s['incident_flagged'])}")
    if s["normal_events"]:
        n = s["normal_events"]
        print(f"normal events quarantined                : {s['normal_quarantined']/n:.3%}  ({s['normal_quarantined']} of {n})")
        print(f"  on a runner during/after its incident: {s['normal_quarantined_contained']}   (containment)")
        print(f"  on uninvolved runners             : {s['normal_quarantined_uninvolved']}   "
              f"({s['normal_quarantined_uninvolved']/n:.4%})")
        print(f"normal events alerted                : {s['normal_alerted']/n:.3%}  ({s['normal_alerted']} of {n})")
    print(f"precision of quarantine (incident share): {pct(s['precision_quarantine'])}"
          f"   counting containment: {pct(s['precision_quarantine_with_containment'])}")
    print(f"precision of quarantine+alert      : {pct(s['precision_flag'])}")
    print(f"flagged by the ML model alone        : {s['model_only_flags']}, of which incidents "
          f"{s['model_only_incidents']} ({pct(s['model_only_precision'])})")

    if r["incidents"]:
        print(f"\n{'incident':<22}{'source':<16}{'events':>7}{'flagged':>9}   first flag after")
        print("-" * 99)
        for x in r["incidents"]:
            if x["first_flag_events"] is None:
                after = "MISSED"
            else:
                after = f"{x['first_flag_events']} events, {x['first_flag_s']:.1f} s"
            notes = ("  *" if x["started_before_window"] else "") + ("  (known source)" if x["known_source"] else "")
            print(f"{x['scenario']:<22}{x['runner_ip']:<16}{x['events']:>7}"
                  f"{pct(x['flagged'] / x['events']):>9}   {after}{notes}")
        print("-" * 99)
        print("* running when the window opened; known source: it hit in the 5 min before")
        median = s["median_time_to_flag_s"]
        print(f"incidents caught                       : {s['incidents_caught']}/{s['incidents_seen']}")
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
    parser.add_argument("--lead-in-minutes", type=float, default=LEAD_IN_MS / 60_000,
                        help="also read this long before the window, to know which runners had an "
                             "incident just before it (0 = off: the window's first minutes then "
                             "overstate false positives)")
    parser.add_argument("--json", action="store_true", help="print the report as JSON")
    args = parser.parse_args()

    password = open(args.password_file).read().strip()
    report = evaluate(args.kafka, args.topic, args.registry, args.clickhouse, password,
                      args.minutes, args.settle, args.max_wait, int(args.lead_in_minutes * 60_000))
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print_report(report)


if __name__ == "__main__":
    main()
