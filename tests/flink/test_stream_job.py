"""The Flink job itself, end to end, on a local mini-cluster.

stream/job.py's build() -- the real operators, keyed state and side
output -- fed Kafka-shaped rows through a real Flink TABLE with the Kafka
source's schema, so values reach Python exactly as in production. (The
Kafka timestamp's Python type depends on the execution mode; a collection
source bypassed that conversion once and hid a crash.)
Runs in the Flink image's test stage (make test-flink).
"""

import json
from datetime import datetime, timedelta, timezone

import pytest

from conftest import SCHEMA_ID, encode, make_event

pytest.importorskip("pyflink")

from pyflink.common import Configuration, Types  # noqa: E402
from pyflink.datastream import StreamExecutionEnvironment  # noqa: E402
from pyflink.table import DataTypes, StreamTableEnvironment  # noqa: E402

import config  # noqa: E402
from stream.job import _as_utc, build  # noqa: E402

pytestmark = pytest.mark.flink

T0 = datetime(2026, 9, 20, 14, 0, 0, tzinfo=timezone.utc)
KAFKA_TS = datetime(2026, 9, 20, 14, 5, 0, 250000, tzinfo=timezone.utc)
CULPRIT = "10.0.14.16"


def _run(messages, versions):
    conf = Configuration()
    conf.set_string("python.execution-mode", config.PYTHON_EXECUTION_MODE)
    # The shape of production: one path per source into the keyed
    # operator (here: a single-task source and parser), and the keyed
    # operator itself spread over 2 subtasks.
    env = StreamExecutionEnvironment.get_execution_environment(conf)
    env.set_parallelism(1)
    t_env = StreamTableEnvironment.create(env)

    schema = DataTypes.ROW([
        DataTypes.FIELD("value", DataTypes.BYTES()),
        DataTypes.FIELD("topic", DataTypes.STRING()),
        DataTypes.FIELD("partition", DataTypes.INT()),
        DataTypes.FIELD("offset", DataTypes.BIGINT()),
        DataTypes.FIELD("kafka_ts", DataTypes.TIMESTAMP_LTZ(3)),
    ])
    table = t_env.from_elements(
        [(bytearray(m), "security-logs", 0, i, KAFKA_TS) for i, m in enumerate(messages)], schema
    )
    scored, rejected = build(t_env.to_data_stream(table), versions, detect_parallelism=2)

    pair = Types.TUPLE([Types.STRING(), Types.STRING()])
    both = scored.map(lambda s: ("scored", s), output_type=pair).union(
        rejected.map(lambda s: ("rejected", s), output_type=pair)
    )
    out = {"scored": [], "rejected": []}
    with both.execute_and_collect() as results:
        for kind, text in results:
            out[kind].append(json.loads(text))
    return out


@pytest.fixture(scope="module")
def result(schema_json):
    burst = [make_event(runner_ip=CULPRIT, event_type="BUILD_FAILURE", project="payments-api",
                        reason="compile_error", timestamp=(T0 + timedelta(seconds=i)).isoformat())
             for i in range(30)]
    normal = [make_event(runner_ip=f"192.168.1.{i}", event_type="BUILD_SUCCESS",
                         timestamp=(T0 + timedelta(seconds=i)).isoformat()) for i in range(10)]
    messages = [encode(e) for e in burst + normal]
    messages += [encode(burst[3]), encode(burst[4])]          # Kafka redelivery
    messages += [b"not avro at all", encode(make_event(event_id="nope"))]
    return _run(messages, {SCHEMA_ID: schema_json})


def test_every_valid_event_is_scored_once(result):
    assert len(result["scored"]) == 40
    assert len({r["event_id"] for r in result["scored"]}) == 40


def test_keyed_state_carries_the_burst_to_a_quarantine(result):
    culprit = sorted((r for r in result["scored"] if r["runner_ip"] == CULPRIT),
                      key=lambda r: r["timestamp"])
    assert [r["failed_builds_1m"] for r in culprit] == list(range(1, 31))
    assert culprit[18]["recommended_action"] == "ok"
    assert all(r["recommended_action"] == "quarantine" for r in culprit[19:])


def test_normal_traffic_is_ok(result):
    normal = [r for r in result["scored"] if r["runner_ip"] != CULPRIT]
    assert {r["recommended_action"] for r in normal} == {"ok"}


def test_rejects_go_to_the_side_output_with_their_reason(result):
    reasons = sorted(r["reject_reason"] for r in result["rejected"])
    assert reasons == ["invalid_event_id", "not_avro_framed"]


def test_rejects_carry_the_real_kafka_timestamp(result):
    """Through the real TIMESTAMP_LTZ conversion, whatever the mode."""
    assert {r["kafka_timestamp"] for r in result["rejected"]} == {"2026-09-20 14:05:00.250"}


def test_timestamp_conversion_accepts_both_instant_types():
    from pyflink.common.time import Instant

    assert _as_utc(Instant.of_epoch_milli(1_790_000_000_123)) == datetime(
        2026, 9, 21, 14, 13, 20, 123000, tzinfo=timezone.utc
    )
    with pytest.raises(TypeError):
        _as_utc(None)
