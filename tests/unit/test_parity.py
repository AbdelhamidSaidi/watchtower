"""Parity: the per-event path (core/, run by Flink) and the Spark path
(transform/ + detect/) must turn the same Kafka messages into the same rows.

The stream is realistic: the producer's own generators for normal traffic
and all nine attacks, timestamps compressed so every behavioural threshold
is crossed, plus v1 messages and every kind of malformed message.
"""

import random
from datetime import datetime, timedelta, timezone

import pandas as pd
import pytest

from conftest import SCHEMA_ID, encode, kafka_frame, make_event, v1_schema_json
from core.columns import EVENT_COLUMNS, SCORE_COLUMNS
from core.processor import SourceState
from core.records import Decoder, enrich, normalize, reject_reason
from core.window import FEATURES
from detect.score import make_scorer
from transform import clean as clean_stage
from transform.enrich import build_geoip_lookup, cheap_enrich, join_enrich
from transform.features import _update_bucket
from transform.normalize import normalize as spark_normalize
from transform.parse import parse


def _import_producer():
    """The producer's generators, without its Kafka client (not installed
    in the test image, and never called here)."""
    import os
    import sys
    import types

    sys.modules.setdefault("kafka", types.SimpleNamespace(KafkaProducer=None))
    root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    sys.path.insert(0, os.path.join(root, "producer"))
    import security_log_producer

    return security_log_producer


producer = _import_producer()

T0 = datetime(2026, 9, 20, 21, 58, 0, tzinfo=timezone.utc)  # crosses the night boundary
V1_ID = 7


def _traffic(seconds=150, normal_per_second=12, seed=3):
    """Producer events, re-timed: `seconds` of traffic, every attack kind."""
    random.seed(seed)
    attacks = []
    for i, (kind, _, (low, high)) in enumerate(producer.ATTACK_KINDS):
        attack = producer.Attack(kind, duration=40, rate=max(low, high // 2))
        attack.start = i * 12          # staggered so they overlap
        attacks.append(attack)

    events = []
    for s in range(seconds):
        batch = [producer.generate_normal() for _ in range(normal_per_second)]
        for attack in attacks:
            if attack.start <= s and attack.remaining > 0:
                batch.extend(attack.tick())
        for j, event in enumerate(batch):
            event["timestamp"] = (T0 + timedelta(seconds=s, microseconds=j * 997)).isoformat()
        events.extend(batch)
    return events


def _malformed(schema_json):
    good = make_event
    return [
        b'{"event_id": "not avro"}',                                   # not_avro_framed
        b"\x00\x00\x00\x00\x63" + encode(good())[5:],                 # unknown_schema_version
        b"\x00" + SCHEMA_ID.to_bytes(4, "big") + b"\xff\xff\xff",       # undecodable_payload
        encode(good(event_id="")),                                     # missing_event_id
        encode(good(event_id="evt-1")),                                # invalid_event_id
        encode(good(timestamp="yesterday")),                           # invalid_timestamp
        encode(good(event_type="  ")),                                 # missing_event_type
        encode(good(event_type="LOGIN_MAYBE")),                        # unknown_event_type
        encode(good(source_ip="")),                                    # missing_source_ip
        encode(good(target_port=70000)),                               # port_out_of_range
        encode(good(dest_port=-1)),                                    # port_out_of_range
        encode(good(http_status=42)),                                  # invalid_http_status
        encode(good(timestamp="2026-09-20T22:10:00Z", user="  Bob ", severity="weird",
                    event_type=" login_failure ", hostname=" WS-1 ")),   # valid, needs normalizing
        encode(good(timestamp="2026-09-20 22:10:01", source_ip=" 45.134.26.7 ")),
    ]


@pytest.fixture(scope="module")
def messages(schema_json):
    events = _traffic()
    msgs = [encode(e) for e in events]
    # v1 messages under their own schema id: decoded with v1, v2 fields null
    msgs += [encode(make_event(source_ip="10.0.10.20", timestamp=(T0 + timedelta(seconds=i)).isoformat()),
                    schema_json=v1_schema_json(), schema_id=V1_ID) for i in range(5)]
    msgs += _malformed(schema_json)
    return msgs


def _record_path(messages, versions):
    decoder = Decoder(versions)
    rows, rejected, states = [], [], {}
    decoded = []
    for offset, raw in enumerate(messages):
        event, wire_error, schema_id = decoder.decode(raw)
        event = event or {}
        reason = reject_reason(event, wire_error)
        if reason:
            rejected.append((offset, reason, None if reason == "not_avro_framed" else schema_id))
            continue
        decoded.append(enrich(normalize(event)))
    # Spark orders each source's events by event time; so does this
    for event in sorted(decoded, key=lambda e: e["_ts"]):
        row = states.setdefault(event["source_ip"], SourceState()).process(event)
        if row is not None:
            rows.append(row)
    return rows, rejected


def _spark_path(spark, messages, versions):
    raw = kafka_frame(spark, messages)
    validated = clean_stage.validate(parse(raw, versions))
    rejected = [
        (r.kafka_offset, r.reject_reason, r.schema_id)
        for r in clean_stage.rejected(validated).collect()
    ]
    events = spark_normalize(clean_stage.valid(validated))
    events = join_enrich(cheap_enrich(events), build_geoip_lookup(spark))
    # applyInPandasWithState only runs in a streaming query; call the very
    # function it runs, on one bucket holding every source.
    from test_features import FakeState

    frame = events.toPandas()
    out = pd.concat(list(_update_bucket((0,), iter([frame]), FakeState())))
    return make_scorer(llm=None)(out[EVENT_COLUMNS].reset_index(drop=True)), rejected


def _canonical(value):
    if isinstance(value, float):
        return round(value, 4)
    if isinstance(value, pd.Timestamp):
        return value.strftime("%Y-%m-%d %H:%M:%S.") + f"{value.microsecond // 1000:03d}"
    if hasattr(value, "item"):  # numpy scalar
        return _canonical(value.item())
    return value


COMPARED = [c for c in EVENT_COLUMNS + SCORE_COLUMNS if c != "llm_reason"]


def test_both_paths_produce_identical_rows_and_rejects(spark, messages, schema_json):
    versions = {SCHEMA_ID: schema_json, V1_ID: v1_schema_json()}
    record_rows, record_rejects = _record_path(messages, versions)
    spark_pdf, spark_rejects = _spark_path(spark, messages, versions)

    assert sorted(record_rejects) == sorted(spark_rejects)
    assert len(record_rejects) == 12

    spark_rows = {
        r["event_id"]: {c: _canonical(r[c]) for c in COMPARED}
        for r in spark_pdf.to_dict("records")
    }
    record_rows = {r["event_id"]: {c: _canonical(r[c]) for c in COMPARED} for r in record_rows}
    assert record_rows.keys() == spark_rows.keys()

    mismatches = [
        (eid, c, record_rows[eid][c], spark_rows[eid][c])
        for eid in record_rows for c in COMPARED
        if record_rows[eid][c] != spark_rows[eid][c]
    ]
    assert mismatches == [], mismatches[:10]


def test_the_stream_actually_exercises_the_detections(schema_json):
    """Parity on boring data proves nothing: every rule family must fire."""
    # the one alert-level pattern: a lone probe of /.env, ordinary browser
    probe = make_event(source_ip="196.200.4.9", event_type="HTTP_REQUEST", http_method="GET",
                       url_path="/.env", http_status=404, user_agent="Mozilla/5.0",
                       timestamp=(T0 + timedelta(seconds=5)).isoformat())
    rows, _ = _record_path([encode(e) for e in _traffic() + [probe]], {SCHEMA_ID: schema_json})
    fired = {hit for r in rows for hit in r["rule_hits"].split(",") if hit}
    assert {"brute_force", "login_after_brute_force", "password_spray", "port_scan",
            "lateral_movement", "sqli", "path_traversal", "web_scan", "data_exfiltration",
            "sensitive_command_as_root", "scanner_agent", "sensitive_path_probe"} <= fired, fired
    assert {r["recommended_action"] for r in rows} == {"allow", "alert", "block"}
    assert {name for name, _ in FEATURES} <= rows[0].keys()
