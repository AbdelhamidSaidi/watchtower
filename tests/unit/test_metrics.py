"""Metrics: progress events -> gauges, free-text reasons -> bounded labels."""

from prometheus_client import REGISTRY

from observability.metrics import classify_reason, record_progress

PROGRESS = {
    "name": "unit-test",
    "numInputRows": 1000,
    "inputRowsPerSecond": 100.0,
    "processedRowsPerSecond": 72.4,
    "durationMs": {"triggerExecution": 13808},
    "stateOperators": [
        {"numRowsTotal": 5000, "memoryUsedBytes": 1_000_000},
        {"numRowsTotal": 180, "memoryUsedBytes": 250_000},
    ],
    "sources": [
        {"metrics": {"maxOffsetsBehindLatest": "12", "avgOffsetsBehindLatest": "4.0"}},
        {"metrics": {"maxOffsetsBehindLatest": "430"}},
    ],
}


def _value(name):
    return REGISTRY.get_sample_value(name, {"query": "unit-test"})


def test_progress_becomes_gauges():
    record_progress(PROGRESS)
    assert _value("watchtower_batch_duration_seconds") == 13.808
    assert _value("watchtower_batch_input_rows") == 1000
    assert _value("watchtower_processed_rows_per_second") == 72.4


def test_state_is_summed_across_operators():
    record_progress(PROGRESS)
    assert _value("watchtower_state_rows") == 5180
    assert _value("watchtower_state_memory_bytes") == 1_250_000


def test_lag_is_the_worst_partition_not_the_average():
    record_progress(PROGRESS)
    assert _value("watchtower_kafka_offsets_behind_latest") == 430


def test_missing_fields_do_not_raise():
    record_progress({"name": "unit-test"})  # an idle batch reports almost nothing


def test_reasons_collapse_to_a_bounded_label_set():
    assert classify_reason("llm_error:RateLimitError") == "error"
    assert classify_reason("detection_disabled:no_api_key") == "disabled"
    assert classify_reason("below_triage_threshold") == "below_triage"
    assert classify_reason("skipped:rule_decided") == "rule_decided"
    assert classify_reason("47 failed SSH logins from one IP") == "scored"
