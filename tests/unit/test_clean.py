"""clean: validation reasons, the timestamp cast, and the valid/rejected split."""

import json

from conftest import encode, kafka_frame, make_event
from transform import clean
from transform.parse import parse


def _validated(spark, versions, messages):
    return clean.validate(parse(kafka_frame(spark, messages), versions))


def _reasons(spark, versions, events):
    df = _validated(spark, versions, [encode(e) for e in events])
    return [r.reject_reason for r in df.orderBy("kafka_offset").collect()]


def test_valid_event_passes(spark, versions):
    assert _reasons(spark, versions, [make_event()]) == [None]


def test_timestamp_becomes_a_real_timestamp(spark, versions):
    from pyspark.sql.types import TimestampType

    df = _validated(spark, versions, [encode(make_event())])
    assert isinstance(df.schema["timestamp"].dataType, TimestampType)


def test_timestamp_without_fraction_still_parses(spark, versions):
    # datetime.isoformat() drops the fraction when microseconds are exactly 0
    event = make_event(timestamp="2026-09-20T14:00:00+00:00")
    assert _reasons(spark, versions, [event]) == [None]


def test_each_invalid_field_gets_its_own_reason(spark, versions):
    events = [
        make_event(timestamp="not-a-time"),
        make_event(event_type="TELEPORT"),
        make_event(source_ip="  "),
        make_event(event_type="PORT_SCAN", target_port=70000),
        make_event(event_id=""),
    ]
    assert _reasons(spark, versions, events) == [
        "invalid_timestamp",
        "unknown_event_type",
        "missing_source_ip",
        "port_out_of_range",
        "missing_event_id",
    ]


def test_wire_error_outranks_field_checks(spark, versions):
    # An undecodable message is missing every field; reporting
    # "missing_event_id" would hide the real cause.
    df = _validated(spark, versions, [json.dumps(make_event()).encode()])
    assert df.first().reject_reason == "not_avro_framed"


def test_valid_drops_internal_columns(spark, versions):
    good = clean.valid(_validated(spark, versions, [encode(make_event())]))
    for internal in ("reject_reason", "wire_error", "schema_id", "raw_value"):
        assert internal not in good.columns


def test_rejected_carries_bytes_and_reason(spark, versions):
    bad = clean.rejected(
        _validated(spark, versions, [json.dumps(make_event()).encode(), encode(make_event())])
    ).collect()

    assert len(bad) == 1
    assert bad[0].reject_reason == "not_avro_framed"
    assert bad[0].raw_value
    # the id is meaningless when there was no header to read it from
    assert bad[0].schema_id is None


def test_http_request_is_a_known_event_type(spark, versions):
    event = make_event(event_type="HTTP_REQUEST", http_status=200, url_path="/")
    assert _reasons(spark, versions, [event]) == [None]


def test_impossible_http_status_is_rejected(spark, versions):
    event = make_event(event_type="HTTP_REQUEST", http_status=999)
    assert _reasons(spark, versions, [event]) == ["invalid_http_status"]
