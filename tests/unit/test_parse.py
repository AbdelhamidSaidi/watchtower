"""parse: Confluent-framed Avro -> typed columns, with explicit wire errors."""

import json

from conftest import encode, kafka_frame, make_event, v1_schema_json
from transform.parse import parse


def _rows(spark, versions, messages):
    return parse(kafka_frame(spark, messages), versions).collect()


def test_valid_message_decodes_every_field(spark, versions):
    event = make_event(event_type="PORT_SCAN", target_port=3389)
    [row] = _rows(spark, versions, [encode(event)])

    assert row.wire_error is None
    assert row.event_id == event["event_id"]
    assert row.source_ip == "192.168.1.50"
    assert row.target_port == 3389
    assert row.schema_id == 1


def test_ground_truth_never_reaches_the_pipeline(spark, versions):
    df = parse(kafka_frame(spark, [encode(make_event())]), versions)
    assert "scenario" not in df.columns


def test_timestamp_stays_a_string(spark, versions):
    # clean.py does the cast, so a bad timestamp is rejected with a reason
    # rather than nulled silently at decode time.
    [row] = _rows(spark, versions, [encode(make_event())])
    assert isinstance(row.timestamp, str)


def test_old_json_message_is_not_avro_framed(spark, versions):
    [row] = _rows(spark, versions, [json.dumps(make_event()).encode()])
    assert row.wire_error == "not_avro_framed"
    assert row.event_id is None


def test_unregistered_schema_id_is_rejected_not_misread(spark, versions):
    [row] = _rows(spark, versions, [encode(make_event(), schema_id=99)])
    assert row.wire_error == "unknown_schema_version"


def test_truncated_payload_is_undecodable(spark, versions):
    whole = encode(make_event())
    [row] = _rows(spark, versions, [whole[:12]])
    assert row.wire_error == "undecodable_payload"


def test_raw_bytes_survive_for_the_dead_letter_table(spark, versions):
    import base64

    message = json.dumps(make_event()).encode()  # well over 57 bytes
    [row] = _rows(spark, versions, [message])

    # No line breaks: Spark's base64() is MIME-chunked by default, and
    # ClickHouse's base64Decode refuses chunked input. A lenient decode here
    # (b64decode silently skips newlines) is exactly how that bug hid.
    assert "\n" not in row.raw_value and "\r" not in row.raw_value
    assert base64.b64decode(row.raw_value, validate=True) == message


def test_each_message_decodes_with_the_version_that_wrote_it(spark, schema_json):
    """A compatible v2 must not strand v1 messages, or vice versa."""
    v2 = json.loads(schema_json)
    # a field no real version has -- the next version, hypothetically
    v2["fields"].append({"name": "tenant_region", "type": ["null", "string"], "default": None})
    v2_json = json.dumps(v2)

    old = make_event(user="v1-user")
    new = dict(make_event(user="v2-user"), tenant_region="eu-west")

    rows = _rows(
        spark,
        {1: schema_json, 2: v2_json},
        [encode(old, schema_json, 1), encode(new, v2_json, 2)],
    )

    assert [r.wire_error for r in rows] == [None, None]
    assert sorted(r.user for r in rows) == ["v1-user", "v2-user"]
    assert {r.schema_id for r in rows} == {1, 2}


def test_v2_request_context_decodes(spark, versions):
    event = make_event(
        event_type="HTTP_REQUEST", http_method="GET", url_path="/api/v1/products?id=42' OR '1'='1",
        http_status=500, user_agent="sqlmap/1.8.2", bytes_sent=5_000_000_000, process_uid=0,
    )
    [row] = _rows(spark, versions, [encode(event)])
    assert row.url_path == "/api/v1/products?id=42' OR '1'='1"
    assert row.http_status == 500
    assert row.bytes_sent == 5_000_000_000   # LongType: past the int32 ceiling
    assert row.process_uid == 0


def test_a_v1_message_still_decodes_after_the_upgrade(spark, schema_json):
    """Old messages already in Kafka must keep flowing: v2 fields come out
    null, the message is not rejected."""
    v1 = v1_schema_json()
    old = {k: v for k, v in make_event(user="written-by-v1").items()
           if k in {f["name"] for f in json.loads(v1)["fields"]}}
    new = make_event(user="written-by-v2", http_status=200)

    rows = _rows(spark, {1: v1, 2: schema_json}, [encode(old, v1, 1), encode(new, schema_json, 2)])
    by_user = {r.user: r for r in rows}

    assert by_user["written-by-v1"].wire_error is None
    assert by_user["written-by-v1"].http_status is None
    assert by_user["written-by-v2"].http_status == 200


def test_each_version_is_decoded_exactly_once(spark, schema_json):
    """Regression guard. Repeating the decode per field blew the generated
    code past the JVM's 64 KB limit; Spark then INTERPRETED the stage and a
    1,000 events/sec batch took 229 s. One from_avro per version, no more."""
    v1 = v1_schema_json()
    df = parse(kafka_frame(spark, [encode(make_event())]), {1: v1, 2: schema_json})
    plan = df._jdf.queryExecution().executedPlan().toString()
    assert plan.count("from_avro(") == 2, plan



def test_the_validation_filter_does_not_multiply_the_decode(spark, schema_json):
    """Regression guard. Without the barrier in parse.py, pushing
    clean.valid()'s filter down substituted the decode into the predicate
    once per referenced field -- 458 from_avro calls per row, 80x slower."""
    from transform import clean

    v1 = v1_schema_json()
    df = clean.valid(clean.validate(
        parse(kafka_frame(spark, [encode(make_event())]), {1: v1, 2: schema_json})
    ))
    plan = df._jdf.queryExecution().executedPlan().toString()
    assert plan.count("from_avro(") == 2, plan.count("from_avro(")
