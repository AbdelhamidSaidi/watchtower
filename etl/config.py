"""
Central configuration.

Every value is overridable by environment variable, so the same image runs
under docker-compose (dev), Kubernetes staging and Kubernetes prod without
edits. Defaults assume the compose network.

SECRETS
-------
Secrets are read from FILES, never from plain environment variables:

    GROQ_API_KEY_FILE=/run/secrets/groq_api_key      -> contents of that file

An environment variable leaks through `docker inspect`, `kubectl describe`,
/proc/<pid>/environ and crash dumps. A mounted file does not. Compose mounts
them from ./secrets/ (gitignored); Kubernetes mounts a Secret. The plain
`GROQ_API_KEY` variable is still honoured as a last resort for ad-hoc local
runs, and read_secret() says so on stderr when it is used.
"""

import os
import sys


def _env(name, default):
    return os.getenv(name, default)


def _env_int(name, default):
    try:
        return int(os.getenv(name, default))
    except (TypeError, ValueError):
        return int(default)


def read_secret(name, default=None):
    """Resolve a secret: NAME_FILE first, then NAME, then default.

    Never logs the value. Returns None if the secret is absent, so callers
    can degrade (detection disabled) rather than crash.
    """
    path = os.getenv(f"{name}_FILE")
    if path:
        try:
            with open(path) as handle:
                value = handle.read().strip()
            return value or default
        except OSError as exc:
            print(f"[config] {name}_FILE={path} unreadable ({exc.strerror})", file=sys.stderr)
            return default

    value = os.getenv(name)
    if value:
        print(
            f"[config] {name} read from a plain environment variable -- "
            f"use {name}_FILE outside of ad-hoc local runs",
            file=sys.stderr,
        )
        return value

    return default


# --- Kafka ----------------------------------------------------------------
# Inside compose: kafka:29092. Inside Kubernetes: the Strimzi bootstrap
# service, set by the overlay.
KAFKA_BOOTSTRAP_SERVERS = _env("KAFKA_BOOTSTRAP_SERVERS", "kafka:29092")
KAFKA_TOPIC = _env("KAFKA_TOPIC", "security-logs")
KAFKA_STARTING_OFFSETS = _env("KAFKA_STARTING_OFFSETS", "latest")
KAFKA_MAX_OFFSETS_PER_TRIGGER = _env_int("KAFKA_MAX_OFFSETS_PER_TRIGGER", 20000)
# Split Kafka partitions into at least this many read tasks per batch (0 =
# one task per partition). Executors added by the autoscaler can only help
# if a batch has more tasks than the current executors have cores.
KAFKA_MIN_PARTITIONS = _env_int("KAFKA_MIN_PARTITIONS", 0)

# --- Streaming path (stream/job.py) ------------------------------------------
# Flink writes finished rows to these topics; ClickHouse's Kafka engine
# inserts them (clickhouse/init/03_streaming_ingest.sql).
SCORED_TOPIC = _env("WATCHTOWER_SCORED_TOPIC", "security-events-scored")
REJECTED_TOPIC = _env("WATCHTOWER_REJECTED_TOPIC", "security-logs-rejected")
CONSUMER_GROUP = _env("WATCHTOWER_CONSUMER_GROUP", "watchtower-stream")
# How long a network buffer may wait to fill before it is sent anyway.
# Flink's default is 100 ms; every hop of the job pays it.
BUFFER_TIMEOUT_MS = _env_int("WATCHTOWER_BUFFER_TIMEOUT_MS", 5)
# How long the JVM may hold events before handing them to the Python
# worker as one bundle. Flink's default is 1,000 ms -- a full second of
# latency added to every event.
PYTHON_BUNDLE_MS = _env_int("WATCHTOWER_PYTHON_BUNDLE_MS", 5)
CHECKPOINT_INTERVAL_MS = _env_int("WATCHTOWER_CHECKPOINT_INTERVAL_MS", 10_000)
# thread: Python runs INSIDE the TaskManager JVM (PEMJA); every keyed-state
# access is an in-process call. process (Flink's default): a separate
# Python worker, reached over gRPC -- each state read that misses its cache
# is a network round trip, and at 1,000 events/sec those round trips, not
# the detection code, were the bottleneck.
PYTHON_EXECUTION_MODE = _env("WATCHTOWER_PYTHON_EXECUTION_MODE", "thread")

# --- Executor autoscaling (scaling/executors.py) ---------------------------
# SPARK_EXECUTORS=auto runs executor pods between these bounds, scaled on
# batch time vs trigger interval and Kafka lag.
EXECUTOR_AUTOSCALE = _env("SPARK_EXECUTORS", "0") == "auto"
EXECUTORS_MIN = _env_int("SPARK_MIN_EXECUTORS", 1)
EXECUTORS_MAX = _env_int("SPARK_MAX_EXECUTORS", 4)

# --- Schema Registry -------------------------------------------------------
SCHEMA_REGISTRY_URL = _env("SCHEMA_REGISTRY_URL", "http://schema-registry:8081")
SCHEMA_SUBJECT = _env("SCHEMA_SUBJECT", "security-logs-value")

# --- ClickHouse -----------------------------------------------------------
CLICKHOUSE_HOST = _env("CLICKHOUSE_HOST", "clickhouse")
CLICKHOUSE_PORT = _env_int("CLICKHOUSE_PORT", 8123)
CLICKHOUSE_USER = _env("CLICKHOUSE_USER", "watchtower")
CLICKHOUSE_DATABASE = _env("CLICKHOUSE_DATABASE", "watchtower")


def clickhouse_password():
    return read_secret("CLICKHOUSE_PASSWORD", default="")


EVENTS_TABLE = _env("WATCHTOWER_EVENTS_TABLE", "security_events")
REJECTED_TABLE = _env("WATCHTOWER_REJECTED_TABLE", "rejected_events")

# --- Streaming ------------------------------------------------------------
WATERMARK = _env("WATCHTOWER_WATERMARK", "10 minutes")
TRIGGER_INTERVAL = _env("WATCHTOWER_TRIGGER", "10 seconds")

# Checkpoints hold Kafka offsets AND state-store contents. They must outlive
# the container: on /tmp, a restart replays from KAFKA_STARTING_OFFSETS with
# cold dedup and feature state, and duplicates slip through.
#
# Driver AND executors write here (executors write the state-store files),
# so the location must be shared by every Spark process:
#   compose     a named volume mounted into master and worker
#   kubernetes  a PersistentVolumeClaim -- fine on one node; multi-node
#               needs object storage (s3a://), see docs/context.md
CHECKPOINT_ROOT = _env("WATCHTOWER_CHECKPOINT_ROOT", "file:///var/lib/watchtower/checkpoints")


def checkpoint_path(query_name):
    return f"{CHECKPOINT_ROOT.rstrip('/')}/{query_name}"


# --- Observability --------------------------------------------------------
METRICS_PORT = _env_int("WATCHTOWER_METRICS_PORT", 9108)

APP_NAME = _env("WATCHTOWER_APP_NAME", "watchtower-etl")
