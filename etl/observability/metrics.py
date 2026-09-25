"""
Prometheus metrics for the pipeline, served from the Spark driver.

Two sources feed them:

  1. A StreamingQueryListener, fed by Spark's own progress events: batch
     duration, throughput, state-store size, and Kafka lag.
  2. Counters incremented directly by the sink: rows written, suspicious
     events, detection errors.

WHY LAG COMES FROM SPARK, NOT KAFKA
-----------------------------------
Structured Streaming keeps its Kafka offsets in the checkpoint and never
commits them to a consumer group. A kafka-exporter watching consumer groups
therefore sees nothing for this pipeline. The Kafka source instead reports
`maxOffsetsBehindLatest` in every progress event, and that is the real lag.

Metric names are prefixed `watchtower_`. Labels are low-cardinality on
purpose: `query` has two values, never an IP, user or LLM reason string.
"""

import json
import time

from prometheus_client import Counter, Gauge, start_http_server

# --- from query progress ---------------------------------------------------
BATCH_DURATION = Gauge(
    "watchtower_batch_duration_seconds",
    "Wall time of the last micro-batch (triggerExecution).",
    ["query"],
)
TRIGGER_INTERVAL = Gauge(
    "watchtower_trigger_interval_seconds",
    "Configured trigger interval. A batch longer than this means the query is falling behind.",
)
INPUT_RATE = Gauge("watchtower_input_rows_per_second", "Rows/sec arriving.", ["query"])
PROCESSED_RATE = Gauge("watchtower_processed_rows_per_second", "Rows/sec processed.", ["query"])
BATCH_ROWS = Gauge("watchtower_batch_input_rows", "Rows in the last micro-batch.", ["query"])
STATE_ROWS = Gauge("watchtower_state_rows", "Rows held across all state stores.", ["query"])
STATE_BYTES = Gauge("watchtower_state_memory_bytes", "Memory used by state stores.", ["query"])
KAFKA_LAG = Gauge(
    "watchtower_kafka_offsets_behind_latest",
    "Kafka messages not yet read, worst partition. The pipeline's consumer lag.",
    ["query"],
)
LAST_PROGRESS = Gauge(
    "watchtower_last_progress_timestamp_seconds",
    "Unix time of the last progress event. Stops moving if the query hangs.",
    ["query"],
)
QUERY_UP = Gauge("watchtower_query_up", "1 while the streaming query is running.", ["query"])
BATCHES = Counter("watchtower_batches", "Micro-batches completed.", ["query"])

# --- from the executor autoscaler (scaling/executors.py) --------------------
EXECUTORS_TARGET = Gauge("watchtower_executors_target", "Executors the autoscaler asked for.")
EXECUTORS_ACTIVE = Gauge(
    "watchtower_executors_active",
    "Executors registered with the driver. Below target = pods Pending (cluster full).",
)
EXECUTORS_MAX = Gauge("watchtower_executors_max", "Configured executor ceiling (SPARK_MAX_EXECUTORS).")
SCALING_DECISIONS = Counter(
    "watchtower_executor_scaling_decisions", "Executor scale decisions.", ["direction"]
)

# --- from the sink ---------------------------------------------------------
ROWS_WRITTEN = Counter("watchtower_rows_written", "Rows inserted into ClickHouse.", ["table"])
SUSPICIOUS = Counter("watchtower_suspicious_events", "Events flagged is_suspicious=1.")
DETECTION_OUTCOME = Counter(
    "watchtower_detection_outcomes",
    "Per-event LLM outcome. `error` means the event passed unjudged.",
    ["outcome"],  # scored | below_triage | rule_decided | disabled | error
)
ACTIONS = Counter(
    "watchtower_recommended_actions",
    "Per-event decision: allow, alert, or block.",
    ["action"],
)


def _num(value):
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def record_progress(progress):
    """Update gauges from one StreamingQueryProgress (as a dict)."""
    query = progress.get("name") or "unnamed"

    duration_ms = (progress.get("durationMs") or {}).get("triggerExecution")
    if duration_ms is not None:
        BATCH_DURATION.labels(query).set(_num(duration_ms) / 1000.0)

    INPUT_RATE.labels(query).set(_num(progress.get("inputRowsPerSecond")))
    PROCESSED_RATE.labels(query).set(_num(progress.get("processedRowsPerSecond")))
    BATCH_ROWS.labels(query).set(_num(progress.get("numInputRows")))

    operators = progress.get("stateOperators") or []
    STATE_ROWS.labels(query).set(sum(_num(op.get("numRowsTotal")) for op in operators))
    STATE_BYTES.labels(query).set(sum(_num(op.get("memoryUsedBytes")) for op in operators))

    lag = 0.0
    for source in progress.get("sources") or []:
        metrics = source.get("metrics") or {}
        lag = max(lag, _num(metrics.get("maxOffsetsBehindLatest")))
    KAFKA_LAG.labels(query).set(lag)

    LAST_PROGRESS.labels(query).set(time.time())
    QUERY_UP.labels(query).set(1)
    BATCHES.labels(query).inc()


def classify_reason(reason):
    """Collapse free-text llm_reason into a bounded label set."""
    reason = reason or ""
    if reason.startswith("llm_error"):
        return "error"
    if reason.startswith("detection_disabled"):
        return "disabled"
    if reason.startswith("skipped"):
        return "rule_decided"
    if reason == "below_triage_threshold":
        return "below_triage"
    return "scored"


def make_listener():
    """A StreamingQueryListener that feeds the gauges above.

    Built lazily so this module imports without a SparkSession -- the sink
    and the tests only need the counters.
    """
    from pyspark.sql.streaming import StreamingQueryListener

    class _Listener(StreamingQueryListener):
        def onQueryStarted(self, event):
            QUERY_UP.labels(event.name or "unnamed").set(1)

        def onQueryProgress(self, event):
            try:
                record_progress(json.loads(event.progress.json))
            except Exception as exc:  # a metrics bug must never kill the stream
                print(f"[metrics] progress not recorded: {exc}", flush=True)

        def onQueryIdle(self, event):
            pass

        def onQueryTerminated(self, event):
            # The event carries the id, not the name; mark every query down.
            # With two queries that is exact once either one has died, which
            # is when the pipeline is broken anyway.
            for labels in list(QUERY_UP._metrics):
                QUERY_UP.labels(*labels).set(0)

    return _Listener()


def serve(port, trigger_interval_seconds):
    """Expose /metrics and publish the configured trigger interval."""
    TRIGGER_INTERVAL.set(trigger_interval_seconds)
    start_http_server(port)
    print(f"[metrics] serving on :{port}/metrics", flush=True)
