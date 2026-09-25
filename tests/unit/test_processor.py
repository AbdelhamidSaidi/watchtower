"""core/processor + core/records: the per-event path the Flink job runs."""

import json
import uuid
from datetime import datetime, timedelta, timezone

import pytest

from conftest import SCHEMA_ID, encode, make_event
from core.processor import DEDUP_MS, SourceState
from core.records import Decoder, enrich, normalize, parse_timestamp, reject_reason, rejected_row

T0 = datetime(2026, 9, 20, 14, 0, 0, tzinfo=timezone.utc)


def ready(**overrides):
    """A decoded, validated, normalized, enriched event."""
    event = {k: v for k, v in make_event(**overrides).items() if k != "scenario"}
    assert reject_reason(event) is None
    return enrich(normalize(event))


def at(seconds, **kw):
    return ready(timestamp=(T0 + timedelta(seconds=seconds)).isoformat(), **kw)


def test_duplicate_event_id_is_dropped():
    state = SourceState()
    event = at(0)
    assert state.process(dict(event)) is not None
    assert state.process(dict(event)) is None


def test_redelivery_with_padded_id_is_still_a_duplicate():
    state = SourceState()
    event = at(0)
    state.process(dict(event))
    assert state.process(dict(event, event_id=f" {event['event_id']} ")) is None


def test_dedup_memory_is_bounded_by_the_horizon():
    state = SourceState()
    first = at(0)
    state.process(dict(first))
    state.process(at(DEDUP_MS / 1000 + 1))
    assert first["event_id"] not in state.seen
    assert len(state.seen) == 1


def test_brute_force_is_blocked_on_the_20th_failure_not_later():
    state = SourceState()
    rows = [state.process(at(i, source_ip="45.134.26.7", event_type="LOGIN_FAILURE", user="root"))
            for i in range(25)]
    actions = [r["recommended_action"] for r in rows]
    assert actions[:19] == ["allow"] * 19
    assert actions[19] == "block" and "brute_force" in rows[19]["rule_hits"]


def test_row_matches_the_clickhouse_contract():
    row = SourceState().process(at(0, source_ip="45.134.26.7"))
    assert row["timestamp"] == "2026-09-20 14:00:00.000"
    assert row["country_code"] == "NL"
    assert row["is_internal_ip"] == 0
    json.dumps(row)  # serialisable as-is
    assert "_ts" not in row


def test_timestamp_parsing_accepts_what_producers_write():
    assert parse_timestamp("2026-09-20T14:00:00+00:00") == T0
    assert parse_timestamp("2026-09-20T14:00:00.500000+00:00") == T0 + timedelta(milliseconds=500)
    assert parse_timestamp("2026-09-20T14:00:00Z") == T0
    assert parse_timestamp("2026-09-20 16:00:00+02:00") == T0
    assert parse_timestamp("2026-09-20 14:00:00") == T0      # naive = UTC
    assert parse_timestamp("yesterday") is None
    assert parse_timestamp(None) is None


@pytest.mark.parametrize("raw,reason", [
    (b"{}", "not_avro_framed"),
    (b"\x00\x00\x00", "not_avro_framed"),
    (b"\x00\x00\x00\x00\x09rest", "unknown_schema_version"),
])
def test_decoder_names_the_wire_error(raw, reason, schema_json):
    event, wire_error, _ = Decoder({SCHEMA_ID: schema_json}).decode(raw)
    assert event is None and wire_error == reason


def test_decoder_round_trips_a_producer_message(schema_json):
    source = make_event(url_path="/login", http_status=200, bytes_sent=10**10)
    event, wire_error, schema_id = Decoder({SCHEMA_ID: schema_json}).decode(encode(source))
    assert wire_error is None and schema_id == SCHEMA_ID
    assert event["bytes_sent"] == 10**10
    assert "scenario" not in event  # ground truth never reaches detection


def test_rejected_row_keeps_the_raw_bytes():
    row = rejected_row("not_avro_framed", 123, b"\x01\x02", "security-logs", 3, 42, T0)
    assert row["schema_id"] is None  # garbage when the message is not framed
    assert row["raw_value"] == "AQI="
    assert row["kafka_timestamp"] == "2026-09-20 14:00:00.000"


def test_state_pickles_for_flink_keyed_state():
    import pickle

    state = SourceState()
    for i in range(50):
        state.process(at(i, event_type="LOGIN_FAILURE", event_id=str(uuid.uuid4())))
    restored = pickle.loads(pickle.dumps(state))
    nxt = at(60, event_type="LOGIN_FAILURE")
    assert restored.process(dict(nxt)) == state.process(dict(nxt))
