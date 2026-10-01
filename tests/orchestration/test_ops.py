"""orchestration/ops: what the Airflow DAGs do, without Airflow or ClickHouse.

A stand-in ClickHouse records every statement and answers value() from a
function, so each step's SQL and decisions are checked directly.
"""

import math
from datetime import date, datetime, timedelta, timezone

import pytest

from orchestration.ops import daily, detection, quality

UTC = timezone.utc


class FakeClickHouse:
    def __init__(self, answer=lambda sql, params: 0):
        self.answer = answer
        self.calls = []

    def value(self, sql, **params):
        self.calls.append(("value", sql, params))
        return self.answer(sql, params)

    def command(self, sql, **params):
        self.calls.append(("command", sql, params))

    def commands(self):
        return [sql for kind, sql, _ in self.calls if kind == "command"]


# --- quality -----------------------------------------------------------------

def test_every_check_is_well_formed():
    assert len(quality.NAMES) == len(set(quality.NAMES))
    for check in quality.CHECKS:
        assert check.severity in ("fail", "warn")
        assert check.op in quality.OPS
        assert "{start:String}" in check.sql


@pytest.mark.parametrize("name, value, passed", [
    ("volume", 0, False),
    ("volume", 1, True),
    ("rejected_share", 0.02, False),
    ("rejected_share", 0.01, True),
    ("missing_identity", 3, False),
    ("missing_identity", 0, True),
    ("latency_p95_ms", 2500.0, False),
])
def test_judge_compares_to_the_threshold(name, value, passed):
    assert quality.judge(quality.BY_NAME[name], value)["passed"] is passed


@pytest.mark.parametrize("value", [None, math.nan])
def test_no_data_is_not_a_failure_of_the_ratio_checks(value):
    # An empty hour makes every ratio NULL or NaN; `volume` is the check
    # that reports an empty hour.
    result = quality.judge(quality.BY_NAME["rejected_share"], value)
    assert result["passed"] and result["value"] is None


def test_only_failed_fail_checks_fail_the_run():
    results = [
        quality.judge(quality.BY_NAME["latency_p95_ms"], 9999.0),   # warn, failed
        quality.judge(quality.BY_NAME["volume"], 10),               # fail, passed
    ]
    assert quality.failures(results) == []
    results.append(quality.judge(quality.BY_NAME["volume"], 0))
    assert [r["check_name"] for r in quality.failures(results)] == ["volume"]


def test_interval_reaches_clickhouse_as_utc():
    ch = FakeClickHouse(lambda sql, params: 5)
    paris = timezone(timedelta(hours=2))
    start = datetime(2026, 9, 27, 16, 0, tzinfo=paris)
    quality.run(ch, "volume", start, start + timedelta(hours=1))
    _, _, params = ch.calls[0]
    assert params == {"start": "2026-09-27 14:00:00.000", "end": "2026-09-27 15:00:00.000"}


# --- daily -------------------------------------------------------------------

END = datetime(2026, 9, 27, 0, 0, tzinfo=UTC)


def test_day_long_past_is_closed_without_asking():
    ch = FakeClickHouse()
    assert daily.day_closed(ch, END, END + timedelta(hours=2))
    assert ch.calls == []


@pytest.mark.parametrize("after_midnight, closed", [(0, False), (120, True)])
def test_day_closes_once_the_stream_has_moved_past_it(after_midnight, closed):
    ch = FakeClickHouse(lambda sql, params: after_midnight)
    assert daily.day_closed(ch, END, END + timedelta(minutes=10)) is closed
    _, _, params = ch.calls[0]
    assert params["since"] == "2026-09-27 00:02:00"


def test_deduplicate_merges_only_when_there_are_copies():
    ch = FakeClickHouse(lambda sql, params: 0)
    assert daily.deduplicate(ch, date(2026, 9, 26)) == 0
    assert ch.commands() == []

    ch = FakeClickHouse(lambda sql, params: 42)
    assert daily.deduplicate(ch, "2026-09-26T00:00:00+00:00") == 42
    assert ch.commands() == ["OPTIMIZE TABLE watchtower.security_events PARTITION '2026-09-26' FINAL"]


def test_summarize_replaces_the_day_in_every_table():
    ch = FakeClickHouse(lambda sql, params: 7)
    rows = daily.summarize(ch, datetime(2026, 9, 26, tzinfo=UTC))
    assert rows == {table: 7 for table in daily.TABLES}
    commands = ch.commands()
    for table in daily.TABLES:
        drop = commands.index(f"ALTER TABLE watchtower.{table} DROP PARTITION '2026-09-26'")
        insert = next(i for i, sql in enumerate(commands) if f"INSERT INTO watchtower.{table}" in sql)
        assert drop < insert, "the day is dropped before it is inserted again"


def test_a_day_is_a_date_and_nothing_else():
    # The day is spelled into ALTER ... PARTITION, which takes no parameters.
    with pytest.raises(ValueError):
        daily.deduplicate(FakeClickHouse(), "2026-09-26'; DROP TABLE x --")


def test_reconcile_reports_both_counts():
    counts = {"daily_summary": 900, "security_events": 901}
    ch = FakeClickHouse(lambda sql, params: next(v for k, v in counts.items() if k in sql))
    assert daily.reconcile(ch, date(2026, 9, 26)) == (900, 901)


# --- detection -----------------------------------------------------------------

def report(**summary):
    base = {
        "coverage": 1.0, "incidents_seen": 29, "incidents_caught": 29, "incident_flagged": 0.993,
        "incident_quarantined": 0.993, "normal_events": 868_112, "normal_quarantined": 297,
        "normal_quarantined_uninvolved": 7, "precision_quarantine": 0.975, "median_time_to_flag_s": 1.1,
    }
    return {"window": {"minutes": 15, "events": 879_721}, "summary": {**base, **summary}}


def test_the_measured_flink_run_passes():
    assert detection.assess(report()) == []


@pytest.mark.parametrize("summary, expected", [
    ({"coverage": 0.99}, "coverage"),
    ({"incidents_caught": 28}, "1 of 29 incidents never flagged"),
    ({"median_time_to_flag_s": 12.0}, "median time to first flag"),
    ({"normal_quarantined_uninvolved": 200}, "uninvolved runners"),
])
def test_each_threshold_can_fail_the_run(summary, expected):
    failures = detection.assess(report(**summary))
    assert len(failures) == 1 and expected in failures[0]


def test_a_window_without_incidents_is_not_judged_on_them():
    assert detection.assess(report(incidents_seen=0, incidents_caught=0, incident_flagged=None,
                                   median_time_to_flag_s=None)) == []


def test_few_incident_events_flagged_is_reported_not_failed():
    # Two small incidents, both caught within 1.5 s: their pre-threshold
    # events are 8% of all incident events. Measured in dev, 2026-09-27.
    assert detection.assess(report(incidents_seen=2, incidents_caught=2, incident_flagged=0.9188,
                                   median_time_to_flag_s=1.07)) == []


def test_an_empty_window_fails():
    empty = report()
    empty["window"]["events"] = 0
    assert detection.assess(empty) == ["no events in the window -- is the producer running?"]


def test_row_carries_the_verdict_and_the_whole_report():
    row = detection.row(report(), ["x"], "manual__1")
    assert row["passed"] == 0 and row["failures"] == ["x"] and row["run_id"] == "manual__1"
    assert '"normal_quarantined_uninvolved": 7' in row["report"]
