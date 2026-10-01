"""Accuracy against ground truth, on every event, as it happens.

The producer stamps each event with `scenario` -- "normal" or the attack's
name -- and the pipeline never reads it. This collector reads security-logs
as a bystander (no consumer group, from the end), holds each event's truth
for a few seconds, looks up what the pipeline decided, and counts:

  detectors  rules alone (rule_score), the model alone (ml_score) and the
             final decision, each against the truth: flagged or allowed,
             attack or normal. Precision, recall and false-alarm rate of
             each, over any window, are ratios of these counters.
  scenarios  the final action per scenario: which attacks are stopped.
  the model  its own alerts (flagged with no rule behind them) and the
             decisions it raised above the rules', attack or normal.
  hosts      normal events blocked on a host that was attacking
             (containment) or not (a false positive on an uninvolved host).
  attacks    one scenario from one source, split on a 60 s pause: caught
             or missed, and the time from its first event to its first flag.
  coverage   events never decided: refused (rejected_events) or missing.

The definitions are tools/evaluate_detection.py's, which measures a window
after the fact; this measures continuously. Synthetic traffic only: real
logs carry no scenario and are counted as unlabelled.
"""

import collections
import heapq
import io
import itertools
import json
import time
import uuid
from datetime import datetime

import fastavro

from core.rules import SUSPICIOUS_THRESHOLD, action_for
from monitor.exposition import counter, gauge, histogram
from schemas.registry import SchemaRegistry, unframe
from tools.evaluate_detection import ATTACK_GAP_MS, CONTAINMENT_MS, SLACK_MS

# An event is stored ~0.2-0.4 s after it is produced (docs/capacity-report.md).
# Looked up after the first delay; still undecided, again after each next
# one (20, 60, 120 s in all); then counted refused or missing.
DELAYS_S = (10, 10, 40, 60)
CHUNK = 1000                # event ids per lookup
POLL_MS = 1000
RANK = {"allow": 0, "alert": 1, "block": 2}
TIME_TO_FLAG_S = (0.25, 0.5, 1, 2, 5, 10, 30, 60)

Event = collections.namedtuple("Event", "id scenario source ts partition offset kafka_ts")

DECISIONS = """
SELECT toString(event_id) AS id,
       argMax(recommended_action, ingested_at) AS action,
       argMax(rule_score, ingested_at) AS rule_score,
       argMax(ml_score, ingested_at) AS ml_score,
       argMax(ml_model, ingested_at) AS model,
       count() AS copies
FROM watchtower.security_events
WHERE timestamp BETWEEN fromUnixTimestamp64Milli({lo:Int64}) AND fromUnixTimestamp64Milli({hi:Int64})
  AND event_id IN {ids:Array(UUID)}
GROUP BY event_id"""

REFUSED = """
SELECT kafka_partition AS partition, kafka_offset AS offset, any(reject_reason) AS reason
FROM watchtower.rejected_events
WHERE kafka_topic = {topic:String}
  AND kafka_timestamp >= fromUnixTimestamp64Milli({since:Int64})
  AND kafka_partition IN {partitions:Array(Int32)}
  AND kafka_offset IN {offsets:Array(Int64)}
GROUP BY partition, offset"""


def millis(text):
    """An ISO-8601 timestamp as epoch milliseconds, or None."""
    try:
        return int(datetime.fromisoformat(text).timestamp() * 1000)
    except (TypeError, ValueError):
        return None


class Run:
    """One attack in progress: a scenario from one source."""
    __slots__ = ("start", "last", "first_flag", "known", "partial")

    def __init__(self, ts, known, partial):
        self.start = self.last = ts
        self.first_flag = None
        self.known = known          # the source attacked within CONTAINMENT_MS before
        self.partial = partial      # already running when the monitor started


class Tally:
    """The counting, without Kafka or ClickHouse: tests feed it directly."""

    def __init__(self):
        self.scenarios = collections.Counter()      # (scenario, action)
        self.detectors = collections.Counter()      # (detector, truth, verdict)
        for detector, truth, verdict in itertools.product(
                ("rules", "model", "final"), ("attack", "normal"), ("flagged", "allowed")):
            self.detectors[(detector, truth, verdict)] = 0
        self.model_only = collections.Counter({"attack": 0, "normal": 0})
        self.raised = collections.Counter({"attack": 0, "normal": 0})
        self.normal_blocked = collections.Counter({"attacking": 0, "uninvolved": 0})
        self.undecided = collections.Counter({"missing": 0})
        self.attacks = collections.Counter()        # (scenario, outcome)
        self.time_to_flag = {known: [0] * (len(TIME_TO_FLAG_S) + 1) for known in ("false", "true")}
        self.time_to_flag_sum = {"false": 0.0, "true": 0.0}
        self.copies = 0
        self.runs = {}              # (scenario, source) -> Run
        self.last_attack = {}       # source -> ts of its newest attack event
        self.first_ts = None
        self.newest = 0

    def decided(self, event, action, rule_score, ml_score, model, copies=1):
        attack = event.scenario != "normal"
        truth = "attack" if attack else "normal"
        self.copies += copies - 1
        self.newest = max(self.newest, event.ts)
        if self.first_ts is None:
            self.first_ts = event.ts
        self.scenarios[(event.scenario, action)] += 1

        verdicts = {"rules": rule_score >= SUSPICIOUS_THRESHOLD, "final": action != "allow"}
        if model:
            verdicts["model"] = ml_score >= SUSPICIOUS_THRESHOLD
        for detector, flagged in verdicts.items():
            self.detectors[(detector, truth, "flagged" if flagged else "allowed")] += 1
        # Flagged with no rule behind it: the model's decision alone.
        if action != "allow" and rule_score < SUSPICIOUS_THRESHOLD:
            self.model_only[truth] += 1
        if RANK.get(action, 0) > RANK[action_for(rule_score)]:
            self.raised[truth] += 1

        if attack:
            self._attack_event(event, action != "allow")
        elif action == "block":
            last = self.last_attack.get(event.source)
            contained = last is not None and event.ts - last <= CONTAINMENT_MS
            self.normal_blocked["attacking" if contained else "uninvolved"] += 1

    def _attack_event(self, event, flagged):
        key = (event.scenario, event.source)
        run = self.runs.get(key)
        if run is not None and event.ts - run.last > ATTACK_GAP_MS:
            self._close(key, run)
            run = None
        if run is None:
            last = self.last_attack.get(event.source)
            run = self.runs[key] = Run(
                event.ts,
                known=last is not None and event.ts - last <= CONTAINMENT_MS,
                # Its first events came before the monitor did: the time to
                # its first flag would be understated.
                partial=event.ts - self.first_ts < 5_000,
            )
        run.last = max(run.last, event.ts)
        self.last_attack[event.source] = max(self.last_attack.get(event.source, 0), event.ts)
        if flagged and run.first_flag is None:
            run.first_flag = event.ts
            if not run.partial:
                self._observe((event.ts - run.start) / 1000, "true" if run.known else "false")

    def _observe(self, seconds, known):
        bucket = next((i for i, bound in enumerate(TIME_TO_FLAG_S) if seconds <= bound), len(TIME_TO_FLAG_S))
        self.time_to_flag[known][bucket] += 1
        self.time_to_flag_sum[known] += seconds

    def _close(self, key, run):
        self.attacks[(key[0], "caught" if run.first_flag is not None else "missed")] += 1
        del self.runs[key]

    def close_quiet(self):
        """End the attacks that paused longer than ATTACK_GAP_MS; forget
        sources whose last attack is out of containment range."""
        for key, run in list(self.runs.items()):
            if self.newest - run.last > ATTACK_GAP_MS:
                self._close(key, run)
        for source, ts in list(self.last_attack.items()):
            if self.newest - ts > CONTAINMENT_MS:
                del self.last_attack[source]

    def families(self):
        f = []
        scen = counter("watchtower_truth_decisions_total",
                       "Events judged against ground truth, by scenario and the pipeline's final action.")
        for (scenario, action), n in sorted(self.scenarios.items()):
            scen.add(n, scenario=scenario, action=action)
        f.append(scen)

        det = counter("watchtower_detector_events_total",
                      "Per detector (rules alone, the model alone, the final decision): events by "
                      "ground truth and verdict. Precision, recall and false-alarm rate are ratios of these.")
        for (detector, truth, verdict), n in sorted(self.detectors.items()):
            det.add(n, detector=detector, truth=truth, verdict=verdict)
        f.append(det)

        mo = counter("watchtower_model_only_flags_total",
                     "Events flagged with no rule behind them -- the model's own alerts -- by ground truth.")
        for truth, n in sorted(self.model_only.items()):
            mo.add(n, truth=truth)
        f.append(mo)

        raised = counter("watchtower_model_raised_total",
                         "Decisions the model raised above the rules' (allow to alert, alert to block), by ground truth.")
        for truth, n in sorted(self.raised.items()):
            raised.add(n, truth=truth)
        f.append(raised)

        nb = counter("watchtower_normal_blocked_total",
                     "Normal events blocked: on a host attacking within the last 5 minutes (containment) "
                     "or on an uninvolved one (a false positive).")
        for host, n in sorted(self.normal_blocked.items()):
            nb.add(n, host=host)
        f.append(nb)

        und = counter("watchtower_truth_undecided_total",
                      "Events with no decision 120 s after they were read: refused (with the reason) or missing.")
        for reason, n in sorted(self.undecided.items()):
            und.add(n, reason=reason)
        f.append(und)

        f.append(counter("watchtower_truth_duplicate_rows_total",
                         "Extra stored copies of judged events (at-least-once delivery, before merges fold them).")
                 .add(self.copies))

        att = counter("watchtower_attacks_total",
                      "Attacks (a scenario from one source, split on a 60 s pause) that ended, caught or missed.")
        for (scenario, outcome), n in sorted(self.attacks.items()):
            att.add(n, scenario=scenario, outcome=outcome)
        f.append(att)
        f.append(gauge("watchtower_attacks_open", "Attacks in progress.").add(len(self.runs)))

        ttf = None
        for known in ("false", "true"):
            counts = self.time_to_flag[known]
            cumulative = list(itertools.accumulate(counts[:-1]))
            h = histogram("watchtower_attack_time_to_flag_seconds",
                          "From an attack's first event to its first flag. known_source: the source "
                          "attacked in the 5 minutes before, so it was already under suspicion.",
                          TIME_TO_FLAG_S, cumulative, self.time_to_flag_sum[known], sum(counts),
                          known_source=known)
            if ttf is None:
                ttf = h
            else:
                ttf.samples.extend(h.samples)
        f.append(ttf)
        return f


class GroundTruth:
    name = "truth"
    interval = 0.2              # a pass polls Kafka for up to POLL_MS itself

    def __init__(self, ch, bootstrap, topic, registry_url, subject):
        self.ch, self.bootstrap, self.topic = ch, bootstrap, topic
        self.registry_url, self.subject = registry_url, subject
        self.tally = Tally()
        self.messages = collections.Counter({"labelled": 0, "unlabelled": 0, "undecodable": 0,
                                             "invalid_id": 0})
        self.pending = []           # heap of (due, seq, attempt, [Event])
        self.seq = itertools.count()
        self.consumer = None
        self.schemas = {}

    # --- Kafka --------------------------------------------------------------

    def _connect(self):
        from kafka import KafkaConsumer, TopicPartition

        consumer = KafkaConsumer(bootstrap_servers=self.bootstrap, enable_auto_commit=False,
                                 request_timeout_ms=30_000)
        partitions = [TopicPartition(self.topic, p) for p in sorted(consumer.partitions_for_topic(self.topic))]
        consumer.assign(partitions)
        consumer.seek_to_end(*partitions)
        self.consumer = consumer

    def _schema(self, schema_id):
        if schema_id not in self.schemas:
            self.schemas = {i: fastavro.parse_schema(json.loads(text)) for i, text in
                            SchemaRegistry(self.registry_url).all_versions(self.subject).items()}
        return self.schemas[schema_id]

    def _read(self):
        if self.consumer is None:
            self._connect()
        try:
            polled = self.consumer.poll(timeout_ms=POLL_MS, max_records=5000)
        except Exception:
            self.consumer.close()
            self.consumer = None
            raise
        events = []
        for tp, messages in polled.items():
            for message in messages:
                try:
                    schema_id, payload = unframe(message.value)
                    record = fastavro.schemaless_reader(io.BytesIO(payload), self._schema(schema_id))
                except Exception:
                    self.messages["undecodable"] += 1
                    continue
                if not record.get("scenario"):
                    self.messages["unlabelled"] += 1
                    continue
                try:
                    event_id = str(uuid.UUID(record["event_id"]))
                except (KeyError, TypeError, ValueError):
                    self.messages["invalid_id"] += 1    # refused by the pipeline, unjoinable here
                    continue
                self.messages["labelled"] += 1
                events.append(Event(event_id, record["scenario"], record.get("source_ip") or "",
                                    millis(record.get("timestamp")) or message.timestamp,
                                    tp.partition, message.offset, message.timestamp))
        if events:
            heapq.heappush(self.pending, (time.monotonic() + DELAYS_S[0], next(self.seq), 0, events))

    # --- ClickHouse ---------------------------------------------------------

    def _decisions(self, events):
        found = {}
        for i in range(0, len(events), CHUNK):
            chunk = events[i:i + CHUNK]
            ts = [e.ts for e in chunk]
            for row in self.ch.rows(DECISIONS, ids=[e.id for e in chunk],
                                    lo=min(ts) - SLACK_MS, hi=max(ts) + SLACK_MS):
                found[row["id"]] = row
        return found

    def _refused(self, events):
        rows = self.ch.rows(REFUSED, topic=self.topic,
                            since=min(e.kafka_ts for e in events) - SLACK_MS,
                            partitions=sorted({e.partition for e in events}),
                            offsets=sorted({e.offset for e in events}))
        return {(int(r["partition"]), int(r["offset"])): r["reason"] for r in rows}

    def _judge(self, attempt, events):
        found = self._decisions(events)
        waiting = []
        for event in events:
            row = found.get(event.id)
            if row is None:
                waiting.append(event)
                continue
            self.tally.decided(event, row["action"], float(row["rule_score"]), float(row["ml_score"]),
                               row["model"], int(row["copies"]))
        if not waiting:
            return
        if attempt + 1 < len(DELAYS_S):
            heapq.heappush(self.pending, (time.monotonic() + DELAYS_S[attempt + 1], next(self.seq),
                                          attempt + 1, waiting))
            return
        refused = self._refused(waiting)
        for event in waiting:
            self.tally.undecided[refused.get((event.partition, event.offset), "missing")] += 1

    # --- a pass -------------------------------------------------------------

    def collect(self):
        self._read()
        now = time.monotonic()
        try:
            while self.pending and self.pending[0][0] <= now:
                due, seq, attempt, events = heapq.heappop(self.pending)
                try:
                    self._judge(attempt, events)
                except Exception:
                    # Kept, not lost: tried again on a later pass.
                    heapq.heappush(self.pending, (now + 5, seq, attempt, events))
                    raise
        finally:
            self.tally.close_quiet()
        return self.families()

    def after_error(self):
        return self.families()

    def families(self):
        msgs = counter("watchtower_truth_messages_total",
                       "Messages the monitor read from security-logs, by what it could do with them.")
        for result, n in sorted(self.messages.items()):
            msgs.add(n, result=result)
        pending = gauge("watchtower_truth_pending_events", "Events read, waiting for their decision.")
        pending.add(sum(len(events) for _, _, _, events in self.pending))
        return [msgs, pending, *self.tally.families()]
