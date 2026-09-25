"""
Watchtower ETL: Kafka -> Spark -> ClickHouse.

Two independent streaming queries, so two DAGs:

    events       kafka -> parse -> clean -> normalize -> cheap_enrich
                       -> deduplicate -> join_enrich -> features
                       -> [detect, on the driver] -> security_events

    rejected     kafka -> parse -> clean.rejected -> rejected_events

They read Kafka separately and checkpoint separately: a crash in one must
not stall the other. The cost is that Kafka is read twice -- negligible at
100/sec, worth revisiting at high throughput (see docs/context.md).

STARTUP
-------
1. Fetch every registered schema version from the Schema Registry. Retried,
   because under Kubernetes the registry may come up after this pod. If it
   never answers the process exits non-zero and the orchestrator restarts
   it -- there is no silent fallback to a local schema, because the local
   file cannot say which registry id wrote a given message.
2. Serve /metrics and register the progress listener.
3. Start both queries from their durable checkpoints.

Run (the image carries every jar and path this needs):

    spark-submit --master <master> /opt/watchtower/etl/pipeline.py
"""

import re
import sys

for path in ("/opt/watchtower/etl", "/opt/watchtower"):
    if path not in sys.path:
        sys.path.append(path)

import config  # noqa: E402
from detect.score import get_scorer  # noqa: E402
from extract.kafka_source import read_kafka_stream  # noqa: E402
from load.clickhouse_sink import make_events_writer, make_rejected_writer  # noqa: E402
from core.startup import fetch_schema_versions  # noqa: E402
from observability import metrics  # noqa: E402
from pyspark.sql import SparkSession  # noqa: E402
from scaling.executors import ExecutorAutoscaler, ScalingPolicy, SparkExecutors  # noqa: E402
from transform import clean as clean_stage  # noqa: E402
from transform.deduplicate import deduplicate  # noqa: E402
from transform.enrich import build_geoip_lookup, cheap_enrich, join_enrich  # noqa: E402
from transform.features import add_features  # noqa: E402
from transform.normalize import normalize  # noqa: E402
from transform.parse import parse  # noqa: E402

def trigger_seconds(interval):
    """'10 seconds' -> 10.0, '2 minutes' -> 120.0."""
    match = re.match(r"\s*(\d+(?:\.\d+)?)\s*(second|minute)", interval)
    if not match:
        raise ValueError(f"unrecognised trigger interval: {interval!r}")
    value = float(match.group(1))
    return value * 60 if match.group(2) == "minute" else value


def build_session():
    return (
        SparkSession.builder.appName(config.APP_NAME)
        .config("spark.sql.session.timeZone", "UTC")
        # One partition per shuffle stage is plenty at this volume; the
        # default of 200 would schedule 200 near-empty tasks per batch.
        .config("spark.sql.shuffle.partitions", config._env("WATCHTOWER_SHUFFLE_PARTITIONS", "4"))
        # RocksDB keeps state off the JVM heap. The default HDFS-backed
        # provider holds every state row on-heap, which is what OOMs first
        # as the dedup and feature state grows.
        .config(
            "spark.sql.streaming.stateStore.providerClass",
            "org.apache.spark.sql.execution.streaming.state.RocksDBStateStoreProvider",
        )
        # One memory cap for ALL RocksDB instances in a JVM (every state
        # partition it hosts), instead of ~64 MB of memtables each. Without
        # it an executor's off-heap use grows with the partitions it happens
        # to hold -- and an autoscaled executor pod has a fixed memory limit.
        .config("spark.sql.streaming.stateStore.rocksdb.boundedMemoryUsage", "true")
        .config(
            "spark.sql.streaming.stateStore.rocksdb.maxMemoryUsageMB",
            config._env("WATCHTOWER_ROCKSDB_MEMORY_MB", "192"),
        )
        .getOrCreate()
    )


def build_streams(spark, versions):
    """Return (events_df, rejected_df) sharing the parse+validate prefix."""
    raw = read_kafka_stream(
        spark,
        bootstrap_servers=config.KAFKA_BOOTSTRAP_SERVERS,
        topic=config.KAFKA_TOPIC,
        starting_offsets=config.KAFKA_STARTING_OFFSETS,
        max_offsets_per_trigger=config.KAFKA_MAX_OFFSETS_PER_TRIGGER,
        min_partitions=config.KAFKA_MIN_PARTITIONS,
    )

    validated = clean_stage.validate(parse(raw, versions))

    events = clean_stage.valid(validated)
    events = normalize(events)
    events = cheap_enrich(events)
    events = deduplicate(events, watermark=config.WATERMARK)
    events = join_enrich(events, build_geoip_lookup(spark))
    events = add_features(events)

    # Detection is NOT a stage in this DAG. It runs on the driver inside
    # foreachBatch (see load/clickhouse_sink.py), because the Groq detector
    # needs a single shared rate limiter and verdict cache.

    return events, clean_stage.rejected(validated)


def start(df, writer, name):
    return (
        df.writeStream.foreachBatch(writer)
        .outputMode("append")
        .option("checkpointLocation", config.checkpoint_path(name))
        .trigger(processingTime=config.TRIGGER_INTERVAL)
        .queryName(name)
        .start()
    )


def main():
    versions = fetch_schema_versions()

    spark = build_session()
    spark.sparkContext.setLogLevel("WARN")

    metrics.serve(config.METRICS_PORT, trigger_seconds(config.TRIGGER_INTERVAL))
    spark.streams.addListener(metrics.make_listener())

    if config.EXECUTOR_AUTOSCALE:
        policy = ScalingPolicy(
            config.EXECUTORS_MIN,
            config.EXECUTORS_MAX,
            trigger_seconds(config.TRIGGER_INTERVAL),
        )
        scaler = ExecutorAutoscaler(policy, SparkExecutors(spark.sparkContext), metrics=metrics)
        spark.streams.addListener(scaler.listener())
        print(f"executors   : autoscaled {policy.min_executors}..{policy.max_executors}", flush=True)

    print(f"kafka       : {config.KAFKA_BOOTSTRAP_SERVERS} / {config.KAFKA_TOPIC}")
    print(f"schemas     : {config.SCHEMA_SUBJECT} ids={sorted(versions)}")
    print(f"clickhouse  : {config.CLICKHOUSE_HOST}:{config.CLICKHOUSE_PORT} / {config.CLICKHOUSE_DATABASE}")
    print(f"checkpoints : {config.CHECKPOINT_ROOT}")
    print(f"watermark   : {config.WATERMARK}   trigger: {config.TRIGGER_INTERVAL}", flush=True)

    events, rejected = build_streams(spark, versions)

    start(events, make_events_writer(scorer=get_scorer()), "events")
    start(rejected, make_rejected_writer(), "rejected")

    # Returns as soon as EITHER query fails, so a dead query cannot go
    # unnoticed while the other keeps running. Exiting non-zero lets the
    # orchestrator restart the pod, which resumes from the checkpoints.
    spark.streams.awaitAnyTermination()


if __name__ == "__main__":
    main()
