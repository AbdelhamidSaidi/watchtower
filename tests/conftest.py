"""
Shared fixtures.

The job's tests run inside the `test` stage of the Flink image
(docker/flink/Dockerfile), so they see exactly the Python and PyFlink the
pipeline runs with; the DAGs' run in the Airflow image.
"""

import io
import json
import os
import sys
import uuid

import fastavro
import pytest

# Tests never reach for a ClickHouse to fetch a model: the job scores with
# rules alone unless a test hands it one (tests/unit/test_ml.py).
os.environ.setdefault("WATCHTOWER_ML", "off")

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for path in (os.path.join(ROOT, "etl"), ROOT):
    if path not in sys.path:
        sys.path.insert(0, path)

from schemas.registry import frame, load_local_schema  # noqa: E402

SCHEMA_ID = 1


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
