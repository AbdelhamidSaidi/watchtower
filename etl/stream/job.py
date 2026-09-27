"""
Watchtower streaming job: every event decided the moment it arrives.

    Kafka security-logs
      -> parse+validate+normalize+enrich   (per event, no state)
           \\-> rejected  -> Kafka security-logs-rejected -> rejected_events
      -> keyBy(source_ip)
      -> dedup + rolling features + rules  (per event, keyed state)
      -> Kafka security-events-scored -> ClickHouse Kafka engine -> security_events

NO MICRO-BATCHES. The Spark pipeline collected events for a trigger
interval and processed them together, so an event waited up to a whole
interval before anything looked at it. Here each event goes through the
job on its own; what remains are small, bounded buffers, each set here or
in config.py:

    network buffers      BUFFER_TIMEOUT_MS  (Flink default 100 ms)
    JVM -> Python        PYTHON_BUNDLE_MS   (Flink default 1,000 ms)
    ClickHouse inserts   kafka_flush_interval_ms in 03_streaming_ingest.sql

The logic is etl/core -- the same functions tests/unit/test_parity.py
proves equal to the Spark path.

DELIVERY. At-least-once end to end: Kafka offsets are checkpointed with
the keyed state, the Kafka sink flushes on every checkpoint, and
ClickHouse's consumer commits after inserting. A replay after a failure
can repeat rows; security_events is a ReplacingMergeTree, so they
collapse. Checkpoints are AT_LEAST_ONCE (no barrier alignment), so a
checkpoint never holds events back.

WHY THE SINK IS KAFKA, NOT A DIRECT CLICKHOUSE INSERT. ClickHouse wants
inserts in blocks, not per event. Its Kafka engine does that batching on
its side, commits only what it inserted, and keeps a ClickHouse outage
from back-pressuring detection.

LLM. Not on this path: a remote call per grey-zone event would stall its
source's stream. Rules decide in-stream (see core/rules.py).

Run: the image's entrypoint does it (docker-compose.yml, or the
FlinkDeployment in deploy/k8s). Locally:

    flink run -py /opt/watchtower/etl/stream/job.py
"""

import json
import os
import sys
import time
import zlib
from datetime import datetime, timezone

for path in ("/opt/watchtower/etl", "/opt/watchtower"):
    if path not in sys.path:
        sys.path.append(path)

from pyflink.common import Configuration, Types  # noqa: E402
from pyflink.common.serialization import SimpleStringSchema  # noqa: E402
from pyflink.datastream import (  # noqa: E402
    CheckpointingMode,
    OutputTag,
    StreamExecutionEnvironment,
)
from pyflink.datastream.connectors.base import DeliveryGuarantee  # noqa: E402
from pyflink.datastream.connectors.kafka import (  # noqa: E402
    KafkaRecordSerializationSchema,
    KafkaSink,
)
from pyflink.datastream.functions import KeyedProcessFunction, ProcessFunction  # noqa: E402
from pyflink.datastream.state import MapStateDescriptor, ValueStateDescriptor  # noqa: E402
from pyflink.table import StreamTableEnvironment  # noqa: E402

import config  # noqa: E402
from core import dq  # noqa: E402
from core.latency import LatencyWindow  # noqa: E402
from core.processor import SourceState  # noqa: E402
from core.records import Decoder, enrich, normalize, reject_reason, rejected_row  # noqa: E402
from core.window import new_summary  # noqa: E402

REJECTED = OutputTag("rejected", Types.STRING())

# How often the latency percentiles are recomputed and pushed.
METRICS_PUSH_MS = 1000


class BatchedCounter:
    """A Flink counter incremented in Python and pushed once per
    METRICS_PUSH_MS. counter.inc() is a Python -> JVM call (~13 us in
    thread mode); two per event were 26 us of the operator's ~158."""

    def __init__(self, group, name):
        self._counter = group.counter(name)
        self._pending = 0

    def inc(self, n=1):
        self._pending += n

    def flush(self):
        if self._pending:
            self._counter.inc(self._pending)
            self._pending = 0


class IssueCounters:
    """Data-quality counters between the steps (core/dq.py), batched like
    the rest: `dq_<step>_<issue>`. Every known issue is registered up front
    so it exports 0 until it happens -- a rate of an absent series is
    nothing, a rate of 0 is "fine"."""

    def __init__(self, group, steps):
        self.group = group
        self.counters = {}
        for step in steps:
            for issue in dq.ISSUES.get(step, ()):
                self._counter(step, issue)

    def _counter(self, step, issue):
        key = f"dq_{step}_{issue}"
        counter = self.counters.get(key)
        if counter is None:
            counter = self.counters[key] = BatchedCounter(self.group, key)
        return counter

    def count(self, step, issues):
        for issue in issues:
            self._counter(step, issue).inc()

    def flush(self):
        for counter in self.counters.values():
            counter.flush()


class PushedGauge:
    """A gauge whose value Python PUSHES into a Flink counter.

    Never use PyFlink's gauge() here. In thread mode a gauge is a Java
    wrapper that calls back into the embedded Python interpreter from
    whichever thread reads it -- the Prometheus reporter's HTTP thread,
    while the task thread is running Python. That crashed the TaskManager
    (SIGSEGV in _PyEval_EvalFrameDefault, thread "prometheus-http-1-4").
    A counter is written from the task thread and only read by Java.
    """

    def __init__(self, group, name):
        self._counter = group.counter(name)
        self._value = 0

    def set(self, value):
        value = int(value)
        delta = value - self._value
        if delta > 0:
            self._counter.inc(delta)
        elif delta < 0:
            self._counter.dec(-delta)
        self._value = value

# A source quiet for this long (processing time) is forgotten: its window
# spans 5 minutes and its dedup memory 10, so 15 loses nothing.
#
# NOT a state TTL on the window. A TTL expires each entry on its own, 15
# minutes after IT was written -- and a window record can be older than
# that while the summary pointing at it is fresh (after an outage, a
# backlog replays hours of event time in minutes of wall time, and the
# reverse). A record vanished under a live summary and the job crashed on
# it. So the window's parts live and die together: a processing-time timer
# clears ALL of a source's state at once when it has been idle.
IDLE_MS = int(os.getenv("WATCHTOWER_SOURCE_IDLE_MS", str(15 * 60 * 1000)))
TIMER_BUCKET_MS = 60 * 1000



class FlinkWindowStore:
    """RollingWindow's storage (see core/window.MemoryStore) over Flink
    keyed state, scoped to the current source_ip by Flink itself.

    Every read or write here is a Python -> JVM call (~4 us in thread
    mode), and state calls were the largest single cost per event (~70 of
    ~190 us). So:

      * one small SUMMARY value per source holds the running sums, the
        window positions, the record at each window head, and -- while
        they are small -- the distinct user/port/path counts;
      * window RECORDS are a map (one entry per event: written once, read
        once when it leaves a window);
      * a count dict that grows past INLINE_COUNTS entries (a scanner
        hitting hundreds of paths) moves to its own map state, so the
        summary never becomes the whole-window blob that the first version
        re-serialised on every event.

    16.5 state calls per event became ~8.
    """

    INLINE_COUNTS = 64

    def __init__(self, summary, records, counts):
        self._summary, self._records, self._counts = summary, records, counts
        self.summary = None

    def load(self):
        summary = self._summary.value()
        if summary is None:
            summary = new_summary()
            summary["counts"] = {kind: {} for kind in self._counts}
            summary["spilled"] = set()
        else:
            if "counts" not in summary:            # older layout: counts in map state
                summary["counts"] = {kind: {} for kind in self._counts}
                summary["spilled"] = set(self._counts)
            if "head1_record" not in summary:      # older layout: heads not cached
                for head in ("head1", "head5"):
                    summary[f"{head}_record"] = (
                        self._records.get(summary[head]) if summary[head] < summary["tail"] else None
                    )
        self.summary = summary

    def save(self):
        self._summary.update(self.summary)

    def clear(self):
        self._summary.clear()
        self._records.clear()
        for counts in self._counts.values():
            counts.clear()

    def get_record(self, i):
        return self._records.get(i)

    def put_record(self, i, record):
        self._records.put(i, record)

    def drop_record(self, i):
        self._records.remove(i)

    def get_count(self, kind, key):
        if kind in self.summary["spilled"]:
            return self._counts[kind].get(key) or 0
        return self.summary["counts"][kind].get(key, 0)

    def set_count(self, kind, key, n):
        if kind in self.summary["spilled"]:
            if n:
                self._counts[kind].put(key, n)
            else:
                self._counts[kind].remove(key)
            return
        inline = self.summary["counts"][kind]
        if n:
            inline[key] = n
        else:
            inline.pop(key, None)
        if len(inline) > self.INLINE_COUNTS:
            for k, v in inline.items():
                self._counts[kind].put(k, v)
            self.summary["counts"][kind] = {}
            self.summary["spilled"].add(kind)


class RecentIds:
    """Dedup memory for one source: the ids of its last DEDUP_RECENT events,
    as 64-bit hashes in a ring INSIDE the summary state.

    It replaces a TTL'd MapState of every id seen in 10 minutes, whose
    contains() + put() were ~46 us of every event -- the largest single
    cost in the operator. The ring is 8 bytes per id (8 KB at 1,024),
    searched in C, and costs no state call.

    What changes is the horizon: "the source's last 1,024 events" instead
    of "the last 10 minutes" -- ~10 minutes for an ordinary host, ~25 s for
    a source sending 40 events/s. That still catches what dedup is for:
    Kafka producer retries, which arrive within seconds. Flink's own
    restarts create no duplicates -- windows and Kafka offsets are restored
    from the same checkpoint.
    """

    SIZE = int(os.getenv("WATCHTOWER_DEDUP_RECENT", "1024"))

    def __init__(self, store):
        self.store = store

    @staticmethod
    def _hash(event_id):
        # event_ids are UUIDs (validated upstream): the first 64 bits are
        # as good a hash as any, and free to compute.
        return bytes.fromhex(event_id[:8] + event_id[9:13] + event_id[14:18])

    def __contains__(self, event_id):
        ring = self.store.summary.get("recent_ids")
        if not ring:
            return False
        needle = self._hash(event_id)
        at = ring.find(needle)
        while at != -1 and at % 8:          # only 8-byte-aligned hits count
            at = ring.find(needle, at + 1)
        return at != -1

    def remember(self, event_id, ts_ms):
        summary = self.store.summary
        ring = summary.get("recent_ids")
        if ring is None:
            ring = summary["recent_ids"] = bytearray()
        slot = summary.get("recent_next", 0)
        if len(ring) < self.SIZE * 8:
            ring += self._hash(event_id)
        else:
            ring[slot * 8:slot * 8 + 8] = self._hash(event_id)
        summary["recent_next"] = (slot + 1) % self.SIZE


def _as_utc(value):
    """The Kafka record timestamp as an aware UTC datetime.

    From the Kafka table it is TIMESTAMP_LTZ, and what Python receives
    depends on the execution mode: a java.time.Instant proxy in thread mode
    (PEMJA), PyFlink's own Instant in process mode -- never a datetime.
    tests/flink runs the real table conversion so a new shape fails there.
    """
    if hasattr(value, "toEpochMilli"):        # java.time.Instant (thread mode)
        ms = value.toEpochMilli()
    elif hasattr(value, "to_epoch_milli"):    # pyflink Instant (process mode)
        ms = value.to_epoch_milli()
    elif isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    else:
        raise TypeError(f"unexpected Kafka timestamp type: {type(value).__name__}")
    return datetime.fromtimestamp(ms / 1000, tz=timezone.utc)


class ParseValidate(ProcessFunction):
    """Kafka message -> normalized, enriched event; or a dead-letter row."""

    def __init__(self, versions):
        self.versions = versions

    def open(self, runtime_context):
        self.decoder = Decoder(self.versions)
        group = runtime_context.get_metrics_group().add_group("watchtower")
        self.rejected = group.counter("rejected_events")
        # Rejects by reason (dq_validate_<reason>, created as reasons appear)
        # and doubtful events that got through, after normalize and enrich.
        self.dq = IssueCounters(group, ("normalize", "enrich"))
        self.pushed_at = 0

    def process_element(self, row, ctx):
        raw, topic, partition, offset, kafka_ts = row[0], row[1], row[2], row[3], row[4]
        event, wire_error, schema_id = self.decoder.decode(raw)
        event = event or {}
        reason = reject_reason(event, wire_error)
        now_ms = int(time.time() * 1000)
        if reason:
            self.rejected.inc()
            self.dq.count("validate", (reason,))
            self._push_metrics(now_ms)
            yield REJECTED, json.dumps(
                rejected_row(reason, schema_id, raw, topic, partition, offset, _as_utc(kafka_ts))
            )
            return
        raw_severity = event.get("severity")
        event = normalize(event)
        self.dq.count("normalize", dq.after_normalize(raw_severity, event))
        event = enrich(event)
        self.dq.count("enrich", dq.after_enrich(event, now_ms, int(event["_ts"].timestamp() * 1000)))
        self._push_metrics(now_ms)
        # Kafka append time, for the pipeline-only latency metric below.
        event["_kafka_ms"] = int(_as_utc(kafka_ts).timestamp() * 1000)
        yield event

    def _push_metrics(self, now_ms):
        if now_ms - self.pushed_at >= METRICS_PUSH_MS:
            self.pushed_at = now_ms
            self.dq.flush()

    def close(self):
        self.dq.flush()


def _idle_check_at(now_ms, key):
    """When to check whether this source went idle: IDLE_MS from now,
    rounded UP to this source's own offset within the minute."""
    offset = zlib.crc32(str(key).encode()) % TIMER_BUCKET_MS
    return ((now_ms + IDLE_MS - offset) // TIMER_BUCKET_MS + 1) * TIMER_BUCKET_MS + offset


def _wall_clock_ms(ctx):
    # Processing time IS the wall clock; reading it through the timer
    # service is a JVM call (~7 us). Tests swap in their own clock.
    return int(time.time() * 1000)


class DetectPerSource(KeyedProcessFunction):
    clock = staticmethod(_wall_clock_ms)

    """Dedup, rolling features and rules, with one SourceState per source_ip."""

    def open(self, runtime_context):
        def value(name):
            return runtime_context.get_state(ValueStateDescriptor(name, Types.PICKLED_BYTE_ARRAY()))

        def mapping(name, key_type, value_type):
            return runtime_context.get_map_state(MapStateDescriptor(name, key_type, value_type))

        self.store = FlinkWindowStore(
            value("window_summary"),
            mapping("window_records", Types.LONG(), Types.PICKLED_BYTE_ARRAY()),
            {
                "users": mapping("window_users", Types.STRING(), Types.INT()),
                "ports": mapping("window_ports", Types.INT(), Types.INT()),
                "paths": mapping("window_paths", Types.STRING(), Types.INT()),
            },
        )
        # Dedup by processing time: what it guards against is Kafka
        # redelivery and job replays, which happen within minutes of the
        # original, whatever the event's own timestamp says.
        self.source = SourceState(self.store, RecentIds(self.store))

        group = runtime_context.get_metrics_group().add_group("watchtower")
        self.scored = BatchedCounter(group, "scored_events")
        self.duplicates = BatchedCounter(group, "duplicate_events")
        self.forgotten = BatchedCounter(group, "idle_sources_cleared")
        self.actions = {a: BatchedCounter(group, f"action_{a}") for a in ("allow", "alert", "block")}
        self.dq = IssueCounters(group, ("features", "rules"))
        self.counters = [self.scored, self.duplicates, self.forgotten, *self.actions.values(), self.dq]
        # Two latencies, as rolling p50/p95/max over the last 2,000 events:
        #   event_age      event timestamp -> scored: includes the source's
        #                  own delay before Kafka (producer clock vs ours --
        #                  meaningful only while both are NTP-synced)
        #   kafka_to_scored  Kafka append -> scored: this job alone
        # ClickHouse's insert comes after both; `ingested_at - timestamp`
        # in security_events is the full end-to-end figure.
        self.latency = {"event_age": LatencyWindow(), "kafka_to_scored": LatencyWindow()}
        self.latency_gauges = [
            (window, PushedGauge(group, f"{name}_p50_ms"), PushedGauge(group, f"{name}_p95_ms"),
             PushedGauge(group, f"{name}_max_ms"))
            for name, window in self.latency.items()
        ]
        self.pushed_at = 0

    def _push_metrics(self, now_ms):
        if now_ms - self.pushed_at < METRICS_PUSH_MS:
            return
        self.pushed_at = now_ms
        for counter in self.counters:
            counter.flush()
        for window, p50, p95, top in self.latency_gauges:
            p50.set(window.quantile(0.50))
            p95.set(window.quantile(0.95))
            top.set(window.max())

    def process_element(self, event, ctx):
        self.store.load()
        row = self.source.process(event)
        if row is None:
            self.duplicates.inc()
            return
        now = self.clock(ctx)
        summary = self.store.summary
        summary["touched_ms"] = now
        # One idle check per source per minute, each source at its own
        # offset in the minute (so ~1,800 timers never land on the same
        # millisecond). Registered only when the target minute changes: the
        # summary remembers the one already set, which spares the ~20 us
        # timer-service call on almost every event.
        check_at = _idle_check_at(now, event["source_ip"])
        if summary.get("idle_check_at") != check_at:
            ctx.timer_service().register_processing_time_timer(check_at)
            summary["idle_check_at"] = check_at
        self.store.save()
        self.scored.inc()
        self.actions[row["recommended_action"]].inc()
        self.dq.count("features", dq.after_features(row))
        self.dq.count("rules", dq.after_rules(row))
        now_ms = int(time.time() * 1000)
        self.latency["event_age"].add(now_ms - int(event["_ts"].timestamp() * 1000))
        self.latency["kafka_to_scored"].add(now_ms - event["_kafka_ms"])
        self._push_metrics(now_ms)
        yield json.dumps(row)

    def close(self):
        for counter in self.counters:
            counter.flush()

    def on_timer(self, timestamp, ctx):
        """Forget the source if nothing arrived for IDLE_MS -- all of it."""
        self.store.load()
        touched = self.store.summary.get("touched_ms")
        if touched is None or touched <= timestamp - IDLE_MS:
            self.store.clear()
            self.forgotten.inc()
        return iter(())


def build(raw, versions, detect_parallelism=None):
    """The job's logic on any stream of (value, topic, partition, offset,
    kafka_ts) rows. Returns (scored, rejected) JSON streams. The Kafka
    source and sinks live in main(); tests feed a collection instead.

    ORDER. Features assume one source's events arrive in event-time order.
    That holds because the producer keys Kafka messages by source_ip (one
    source = one partition = one source subtask), and parsing runs chained
    to the source at the same parallelism -- so every event of a source
    reaches the keyed operator through one path. Parsing at a different
    parallelism than the source would insert a rebalance and break it.
    """
    # No uid() on the Python operators: PyFlink fuses consecutive Python
    # functions into one operator, which then carries the same uid twice
    # and the job is rejected. Flink's generated ids are stable as long as
    # the graph is, which is what checkpoint restore needs.
    parsed = raw.process(ParseValidate(versions)).name("parse-validate-enrich")
    scored = (
        parsed.key_by(lambda event: event["source_ip"], key_type=Types.STRING())
        .process(DetectPerSource(), output_type=Types.STRING())
        .name("dedup-features-rules")
    )
    if detect_parallelism:
        scored = scored.set_parallelism(detect_parallelism)
    return scored, parsed.get_side_output(REJECTED)


def kafka_sink(topic):
    return (
        KafkaSink.builder()
        .set_bootstrap_servers(config.KAFKA_BOOTSTRAP_SERVERS)
        .set_record_serializer(
            KafkaRecordSerializationSchema.builder()
            .set_topic(topic)
            .set_value_serialization_schema(SimpleStringSchema())
            .build()
        )
        # Flushed on every checkpoint; nothing is held until then.
        .set_delivery_guarantee(DeliveryGuarantee.AT_LEAST_ONCE)
        .set_property("linger.ms", "5")
        .set_property("compression.type", "lz4")
        .build()
    )


def kafka_source_table(t_env):
    """The raw topic, bytes untouched, with the coordinates a dead-letter
    row needs. `raw` format: decoding is ParseValidate's job, per message,
    with the schema version its header names."""
    t_env.execute_sql(f"""
        CREATE TABLE security_logs (
            `value`     BYTES,
            `topic`     STRING METADATA VIRTUAL,
            `partition` INT METADATA VIRTUAL,
            `offset`    BIGINT METADATA VIRTUAL,
            `kafka_ts`  TIMESTAMP_LTZ(3) METADATA FROM 'timestamp' VIRTUAL
        ) WITH (
            'connector' = 'kafka',
            'topic' = '{config.KAFKA_TOPIC}',
            'properties.bootstrap.servers' = '{config.KAFKA_BOOTSTRAP_SERVERS}',
            'properties.group.id' = '{config.CONSUMER_GROUP}',
            -- first start: from now. Afterwards the checkpoint decides.
            'scan.startup.mode' = 'group-offsets',
            'properties.auto.offset.reset' = '{config.KAFKA_STARTING_OFFSETS}',
            'format' = 'raw'
        )
    """)
    return t_env.to_data_stream(t_env.from_path("security_logs"))


def environment():
    conf = Configuration()
    conf.set_string("python.execution-mode", config.PYTHON_EXECUTION_MODE)
    conf.set_string("python.fn-execution.bundle.time", str(config.PYTHON_BUNDLE_MS))
    conf.set_string("python.fn-execution.bundle.size", "1000")
    # Keep every active source's state deserialized in the Python worker;
    # the default (1,000 keys) is below the ~1,800 sources at 1,000/s.
    conf.set_string("python.state.cache-size", "20000")
    env = StreamExecutionEnvironment.get_execution_environment(conf)
    env.set_buffer_timeout(config.BUFFER_TIMEOUT_MS)
    env.enable_checkpointing(config.CHECKPOINT_INTERVAL_MS, CheckpointingMode.AT_LEAST_ONCE)
    return env


def main():
    from core.startup import fetch_schema_versions

    versions = fetch_schema_versions()
    print(f"schemas: {config.SCHEMA_SUBJECT} ids={sorted(versions)}", flush=True)

    env = environment()
    t_env = StreamTableEnvironment.create(env)
    scored, rejected = build(kafka_source_table(t_env), versions)
    scored.sink_to(kafka_sink(config.SCORED_TOPIC)).name("to-kafka-scored").uid("sink-scored")
    rejected.sink_to(kafka_sink(config.REJECTED_TOPIC)).name("to-kafka-rejected").uid("sink-rejected")
    env.execute("watchtower-stream")


if __name__ == "__main__":
    main()
