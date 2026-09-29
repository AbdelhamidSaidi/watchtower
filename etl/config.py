"""
Central configuration.

Every value is overridable by environment variable, so the same image runs
under docker-compose (dev), Kubernetes staging and Kubernetes prod without
edits. Defaults assume the compose network.

SECRETS
-------
Secrets are read from FILES, never from plain environment variables:

    CLICKHOUSE_PASSWORD_FILE=/run/secrets/clickhouse_password  -> that file's contents

An environment variable leaks through `docker inspect`, `kubectl describe`,
/proc/<pid>/environ and crash dumps. A mounted file does not. Compose mounts
them from ./secrets/ (gitignored); Kubernetes mounts a Secret. The plain
variable (e.g. `CLICKHOUSE_PASSWORD`) is still honoured as a last resort for ad-hoc local
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
