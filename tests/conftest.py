"""
Shared fixtures.

Everything runs inside the `test` stage of the Spark image
(docker/spark/Dockerfile), so tests see exactly the jars, Python and
pyspark the pipeline runs with in production.
"""

import io
import json
import os
import sys
import uuid
from datetime import datetime, timezone

import fastavro
import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for path in (os.path.join(ROOT, "etl"), ROOT):
    if path not in sys.path:
        sys.path.insert(0, path)

from schemas.registry import frame, load_local_schema  # noqa: E402

SCHEMA_ID = 1


@pytest.fixture(scope="session")
def spark():
    from pyspark.sql import SparkSession

    session = (
        SparkSession.builder.master("local[2]")
        .appName("watchtower-tests")
        .config("spark.sql.session.timeZone", "UTC")
        .config("spark.sql.shuffle.partitions", "2")
        .config("spark.ui.enabled", "false")
        .getOrCreate()
    )
    session.sparkContext.setLogLevel("ERROR")
    yield session
    session.stop()


@pytest.fixture(scope="session")
def schema_json():
    return load_local_schema()


@pytest.fixture(scope="session")
def versions(schema_json):
    return {SCHEMA_ID: schema_json}


def _nullable_fields():
    schema = json.loads(load_local_schema())
    return [f["name"] for f in schema["fields"] if isinstance(f["type"], list) and "null" in f["type"]]


def make_event(**overrides):
    """A valid event. Override any field to build an edge case.

    Every nullable field in the CURRENT schema starts as None, so tests keep
    working as the schema grows.
    """
    event = {name: None for name in _nullable_fields()}
    event.update({
        "event_id": str(uuid.uuid4()),
        "timestamp": "2026-09-20T14:00:00.123456+00:00",
        "source_ip": "192.168.1.50",
        "user": "alice",
        "event_type": "LOGIN_SUCCESS",
        "hostname": "ws-050",
        "severity": "INFO",
        "scenario": "normal",
    })
    event.update(overrides)
    return event


def v1_schema_json():
    """The schema as it was before v2 -- to prove old messages still decode."""
    schema = json.loads(load_local_schema())
    v2 = {"log_source", "outcome", "session_id", "dest_ip", "dest_port", "protocol",
          "auth_method", "http_method", "url_path", "http_status", "user_agent",
          "bytes_sent", "response_time_ms", "process_name", "process_id",
          "parent_process", "process_uid", "file_path", "file_operation"}
    schema["fields"] = [f for f in schema["fields"] if f["name"] not in v2]
    return json.dumps(schema)


def encode(event, schema_json=None, schema_id=SCHEMA_ID):
    """Confluent-framed Avro, exactly as the producer writes it."""
    schema = fastavro.parse_schema(json.loads(schema_json or load_local_schema()))
    buffer = io.BytesIO()
    fastavro.schemaless_writer(buffer, schema, event)
    return frame(schema_id, buffer.getvalue())


def kafka_frame(spark, messages):
    """A DataFrame with the Kafka source schema, one row per message."""
    from pyspark.sql.types import (
        BinaryType,
        IntegerType,
        LongType,
        StringType,
        StructField,
        StructType,
        TimestampType,
    )

    schema = StructType(
        [
            StructField("value", BinaryType()),
            StructField("topic", StringType()),
            StructField("partition", IntegerType()),
            StructField("offset", LongType()),
            StructField("timestamp", TimestampType()),
        ]
    )
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    rows = [(bytearray(m), "security-logs", 0, i, now) for i, m in enumerate(messages)]
    return spark.createDataFrame(rows, schema)
