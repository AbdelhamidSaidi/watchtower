"""normalize: one canonical spelling per value, nulls -> ClickHouse defaults."""

from transform.normalize import normalize


STRINGS = [
    "user", "hostname", "event_type", "severity", "source_ip", "reason", "command",
    "log_source", "outcome", "session_id", "dest_ip", "protocol", "auth_method",
    "http_method", "url_path", "user_agent", "process_name", "parent_process",
    "file_path", "file_operation",
]
INTS = ["target_port", "dest_port", "http_status", "response_time_ms", "process_id", "process_uid"]


def _one(spark, **fields):
    base = {name: None for name in STRINGS + INTS + ["bytes_sent"]}
    base.update(user="alice", hostname="ws-1", event_type="LOGIN_SUCCESS",
                severity="INFO", source_ip="10.0.0.1")
    base.update(fields)
    schema = ", ".join(
        [f"{n} string" for n in STRINGS] + [f"{n} int" for n in INTS] + ["bytes_sent bigint"]
    )
    return normalize(spark.createDataFrame([base], schema)).first()


def test_identifiers_are_lowercased_and_trimmed(spark):
    row = _one(spark, user="  John ", hostname="WS-001 ")
    assert (row.user, row.hostname) == ("john", "ws-001")


def test_event_type_is_uppercased(spark):
    assert _one(spark, event_type=" login_failure ").event_type == "LOGIN_FAILURE"


def test_unknown_severity_becomes_unknown(spark):
    # A closed set: a dashboard filter can never miss a value it didn't expect.
    assert _one(spark, severity="critical!!").severity == "UNKNOWN"
    assert _one(spark, severity=" warning ").severity == "WARNING"


def test_ip_text_is_not_rewritten(spark):
    # enrich joins on the IP's text; zero-padding or case changes would break it
    assert _one(spark, source_ip=" 010.0.0.1 ").source_ip == "010.0.0.1"


def test_nulls_become_the_clickhouse_defaults(spark):
    row = _one(spark)
    assert (row.reason, row.command, row.target_port) == ("", "", 0)


def test_unknown_uid_is_not_root(spark):
    # 0 is root. An event that reports no uid must NOT become a root event.
    assert _one(spark).process_uid == -1
    assert _one(spark, process_uid=0).process_uid == 0


def test_url_keeps_case_and_encoding(spark):
    # /Admin and /admin are different resources, and %2e%2e is evidence --
    # decoding it would erase the traversal signature.
    row = _one(spark, url_path="  /Static/%2e%2e/etc/passwd ")
    assert row.url_path == "/Static/%2e%2e/etc/passwd"


def test_http_method_is_uppercased(spark):
    assert _one(spark, http_method=" get ").http_method == "GET"
