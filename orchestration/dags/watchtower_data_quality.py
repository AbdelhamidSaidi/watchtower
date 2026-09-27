"""
### Hourly data-quality checks

Every hour, for the hour that just closed, one task per check
(`orchestration/ops/quality.py`) measures a number in ClickHouse and judges
it. All results are recorded in `watchtower.data_quality_checks`; the run
fails only if a **fail** check failed.

| check | severity | passes when |
|---|---|---|
| volume | fail | at least one event was stored |
| rejected_share | fail | ≤ 1% of messages were refused |
| missing_identity | fail | no event lacks source_ip or event_type |
| latency_p95_ms | warn | p95 event-to-row ≤ 2 s |
| duplicate_share | warn | ≤ 1% unmerged replay copies |
| block_share_vs_7d | warn | block share ≤ 5× the trailing week |

Prometheus alerts on the pipeline; these check the data it wrote.
"""

from datetime import datetime, timedelta, timezone

from airflow.sdk import CronDataIntervalTimetable, dag, task
from airflow.sdk.exceptions import AirflowFailException

from orchestration.ops import quality
from orchestration.ops.clickhouse import ClickHouse


@dag(
    # Each run covers [HH:00, HH+1:00) and starts when that hour ends.
    schedule=CronDataIntervalTimetable("0 * * * *", timezone="UTC"),
    start_date=datetime(2026, 9, 1, tzinfo=timezone.utc),
    catchup=False,
    max_active_runs=1,
    default_args={"owner": "dataops", "retries": 2, "retry_delay": timedelta(minutes=1)},
    tags=["watchtower", "data-quality"],
    doc_md=__doc__,
)
def watchtower_data_quality():

    @task(execution_timeout=timedelta(minutes=10))
    def run_check(name, data_interval_start=None, data_interval_end=None):
        result = quality.run(ClickHouse(), name, data_interval_start, data_interval_end)
        print(result["detail"])
        return result

    @task
    def record(results, run_id=None, data_interval_start=None, data_interval_end=None):
        ClickHouse().insert("watchtower.data_quality_checks", [
            {**r, "run_id": run_id,
             "interval_start": quality.ch_time(data_interval_start),
             "interval_end": quality.ch_time(data_interval_end),
             "passed": int(r["passed"])}
            for r in results
        ])

    @task
    def gate(results):
        failed = quality.failures(list(results))
        if failed:
            # No retry: the data will not change by trying again.
            raise AirflowFailException("; ".join(r["detail"] for r in failed))

    results = run_check.expand(name=quality.NAMES)
    record(results) >> gate(results)


watchtower_data_quality()
