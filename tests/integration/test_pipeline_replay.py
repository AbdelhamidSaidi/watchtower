"""
Replays a fixed event set through the FULL streaming chain -- parse, clean,
normalize, enrich, deduplicate, features -- and asserts on what comes out.

No Kafka: the framed messages are written to a directory and read back with
a streaming file source reshaped to exactly the Kafka source schema, so
every stage runs as it does in production, stateful operators included.

The fixture is deterministic. Each assertion names the behaviour it guards.
"""

import base64
import json
import os
from datetime import datetime, timedelta, timezone

import pytest

from conftest import encode, make_event
from detect.llm_detector import is_candidate

pytestmark = pytest.mark.integration

T0 = datetime(2026, 9, 20, 14, 0, 0, tzinfo=timezone.utc)
ATTACKER = "45.134.26.7"
NORMAL_IPS = ["192.168.1.10", "192.168.1.11", "10.0.10.20"]
# A separate server for the post-compromise commands. Once a host reads
# /etc/shadow as root it IS compromised, and the pipeline rightly keeps
# treating it as suspicious -- so it must not be one of the "normal" hosts.
OWNED_HOST = "10.0.10.25"
BURST = 40


def _at(seconds):
    return (T0 + timedelta(seconds=seconds)).isoformat()


def build_fixture():
    """Return (messages, expectations)."""
    # Baseline: quiet internal traffic, one ordinary failed login per host.
    normal = []
    for n, ip in enumerate(NORMAL_IPS):
        for i in range(20):
            kind = "LOGIN_FAILURE" if i == 7 else "FILE_ACCESS"
            normal.append(encode(make_event(
                source_ip=ip, event_type=kind, timestamp=_at(n + i * 6),
                user=f"user{n}", reason="invalid_password" if kind == "LOGIN_FAILURE" else None,
            )))

    # Brute force: 40 failures against one account in 40 seconds.
    burst = [
        make_event(source_ip=ATTACKER, event_type="LOGIN_FAILURE", user="root",
                   timestamp=_at(100 + i), reason="invalid_password")
        for i in range(BURST)
    ]

    # Ordered so the stream's two micro-batches split the burst down the
    # middle, and the redelivered duplicates arrive a batch AFTER their
    # originals. Both are the cross-batch cases: counters that must carry
    # over in state, and a duplicate the dedup state must still remember.
    messages = normal[:30] + [encode(e) for e in burst] + normal[30:]

    # Kafka redelivery: the first five burst messages again, byte for byte.
    messages += [encode(e) for e in burst[:5]]


    # v2: bad REQUESTS and COMMANDS, identifiable from the event itself.
    messages.append(encode(make_event(
        source_ip="193.201.9.88", event_type="HTTP_REQUEST", timestamp=_at(150),
        http_method="GET", url_path="/api/v1/products?id=42' UNION SELECT username,password FROM users--",
        http_status=500, user_agent="sqlmap/1.8.2#stable", bytes_sent=4200, log_source="nginx",
    )))
    messages.append(encode(make_event(
        source_ip=OWNED_HOST, event_type="COMMAND_EXECUTION", timestamp=_at(151),
        command="cat /etc/shadow", process_name="cat", parent_process="sshd", process_uid=0,
        log_source="auditd",
    )))
    # ...and the benign look-alike: the backup job, legitimately as root.
    messages.append(encode(make_event(
        source_ip=OWNED_HOST, event_type="COMMAND_EXECUTION", timestamp=_at(152),
        command="rsync -a /srv/data /backup/data", process_name="rsync", parent_process="cron",
        process_uid=0, log_source="auditd",
    )))

    # Things that must be rejected, each for a different reason.
    messages.append(json.dumps(make_event()).encode())                 # old JSON producer
    messages.append(encode(make_event(), schema_id=99))                # unregistered version
    messages.append(encode(make_event())[:12])                         # truncated in transit
    messages.append(encode(make_event(timestamp="yesterday-ish")))     # bad field

    # Guard the ordering against the REAL split (the replay fixture halves the
    # finished list), so a future edit cannot quietly collapse this test into
    # one micro-batch and stop exercising cross-batch state.
    half = len(messages) // 2
    burst_start = 30
    first_duplicate = burst_start + BURST + (len(normal) - 30)
    assert messages[first_duplicate] == messages[burst_start], "duplicate layout changed"
    assert burst_start < half < burst_start + BURST, "burst must straddle the batch boundary"
    assert burst_start < half <= first_duplicate, "duplicates must arrive a batch after originals"

    valid_unique = len(NORMAL_IPS) * 20 + BURST + 3
    return messages, {
        "valid_unique": valid_unique,
        "rejected": {
            "not_avro_framed": 1,
            "unknown_schema_version": 1,
            "undecodable_payload": 1,
            "invalid_timestamp": 1,
        },
    }


def _kafka_stream(spark, source_dir):
    """Streaming DataFrame with the Kafka source schema, from framed files."""
    from pyspark.sql import functions as F

    return (
        spark.readStream.schema("value_b64 string, offset long")
        .option("maxFilesPerTrigger", 1)
        .json(source_dir)
        .select(
            F.unbase64("value_b64").alias("value"),
            F.lit("security-logs").alias("topic"),
            F.lit(0).alias("partition"),
            F.col("offset"),
            F.current_timestamp().alias("timestamp"),
        )
    )


def _run(df, name, checkpoint):
    query = (
        df.writeStream.format("memory")
        .queryName(name)
        .outputMode("append")
        .option("checkpointLocation", checkpoint)
        .trigger(availableNow=True)
        .start()
    )
    query.awaitTermination(timeout=240)
    assert query.exception() is None, query.exception()


@pytest.fixture(scope="module")
def replay(spark, versions, tmp_path_factory):
    from transform import clean
    from transform.deduplicate import deduplicate
    from transform.enrich import build_geoip_lookup, cheap_enrich, join_enrich
    from transform.features import add_features
    from transform.normalize import normalize
    from transform.parse import parse

    messages, expected = build_fixture()

    work = tmp_path_factory.mktemp("replay")
    source = os.path.join(work, "source")
    os.makedirs(source)
    # Two files, read one per trigger, so the stream really runs as two
    # micro-batches and state has to carry across the boundary.
    half = len(messages) // 2
    for index, chunk in enumerate([messages[:half], messages[half:]]):
        with open(os.path.join(source, f"part-{index}.json"), "w") as handle:
            for offset, message in enumerate(chunk, start=index * half):
                handle.write(json.dumps({
                    "value_b64": base64.b64encode(message).decode(),
                    "offset": offset,
                }) + "\n")

    validated = clean.validate(parse(_kafka_stream(spark, source), versions))

    events = clean.valid(validated)
    events = normalize(events)
    events = cheap_enrich(events)
    events = deduplicate(events, watermark="10 minutes")
    events = join_enrich(events, build_geoip_lookup(spark))
    events = add_features(events)

    _run(events, "it_events", os.path.join(work, "ck_events"))
    _run(clean.rejected(validated), "it_rejected", os.path.join(work, "ck_rejected"))

    return (
        [r.asDict() for r in spark.sql("select * from it_events").collect()],
        [r.asDict() for r in spark.sql("select * from it_rejected").collect()],
        expected,
    )


def test_every_bad_message_is_rejected_with_its_own_reason(replay):
    _, rejected, expected = replay
    counts = {}
    for row in rejected:
        counts[row["reject_reason"]] = counts.get(row["reject_reason"], 0) + 1
    assert counts == expected["rejected"]


def test_nothing_is_silently_lost(replay):
    events, rejected, expected = replay
    # every input is either a stored event, a rejected row, or a duplicate
    assert len(events) == expected["valid_unique"]
    assert len(rejected) == sum(expected["rejected"].values())


def test_redelivered_messages_are_deduplicated(replay):
    events, _, _ = replay
    ids = [e["event_id"] for e in events]
    assert len(ids) == len(set(ids))


def test_brute_force_state_accumulates_across_batches(replay):
    events, _, _ = replay
    burst = [e for e in events if e["source_ip"] == ATTACKER]
    assert len(burst) == BURST
    assert max(e["failed_logins_1m"] for e in burst) == BURST


def test_normal_hosts_stay_quiet(replay):
    events, _, _ = replay
    normal = [e for e in events if e["source_ip"] in NORMAL_IPS]
    assert max(e["failed_logins_5m"] for e in normal) == 1


def test_triage_gate_separates_attacker_from_baseline(replay):
    events, _, _ = replay
    attacker = [e for e in events if e["source_ip"] == ATTACKER]
    normal = [e for e in events if e["source_ip"] in NORMAL_IPS]

    assert is_candidate(max(attacker, key=lambda e: e["failed_logins_1m"]))
    assert not any(is_candidate(e) for e in normal)


def test_enrichment_reaches_the_output(replay):
    events, _, _ = replay
    by_ip = {e["source_ip"]: e for e in events}
    assert by_ip[ATTACKER]["is_internal_ip"] == 0
    assert by_ip[ATTACKER]["country_code"] == "NL"
    assert by_ip["192.168.1.10"]["is_internal_ip"] == 1


def _decisions(events):
    """Apply the real scorer, rules only -- exactly what runs with no API key."""
    import pandas as pd

    from detect.score import make_scorer

    return make_scorer(llm=None)(pd.DataFrame(events)).to_dict("records")


def test_sql_injection_is_blocked_end_to_end(replay):
    events, _, _ = replay
    decided = {d["source_ip"]: d for d in _decisions(events) if d["event_type"] == "HTTP_REQUEST"}
    sqli = decided["193.201.9.88"]
    assert sqli["request_signature"] == "sqli"
    assert sqli["is_scanner_agent"] == 1
    assert sqli["recommended_action"] == "block"
    assert "sqli" in sqli["rule_hits"]


def test_root_reading_shadow_is_blocked_but_the_root_backup_is_not(replay):
    events, _, _ = replay
    by_cmd = {d["command"]: d for d in _decisions(events) if d["event_type"] == "COMMAND_EXECUTION"}
    assert by_cmd["cat /etc/shadow"]["recommended_action"] == "block"
    assert "sensitive_command_as_root" in by_cmd["cat /etc/shadow"]["rule_hits"]
    # same host, same uid 0 -- routine, and must stay allowed
    assert by_cmd["rsync -a /srv/data /backup/data"]["recommended_action"] == "allow"


def test_the_successful_login_after_the_burst_is_what_matters(replay):
    events, _, _ = replay
    attacker = [d for d in _decisions(events) if d["source_ip"] == ATTACKER]
    assert all(d["recommended_action"] == "block" for d in attacker if d["failed_logins_1m"] >= 20)


def test_normal_hosts_are_never_blocked(replay):
    events, _, _ = replay
    normal = [d for d in _decisions(events) if d["source_ip"] in NORMAL_IPS]
    assert {d["recommended_action"] for d in normal} == {"allow"}
