"""
### Detection quality

Every 6 hours: `tools/evaluate_detection.py` over the last N minutes of
live traffic — the synthetic producer's ground truth joined to the
pipeline's decisions — judged against the thresholds in
`orchestration/ops/detection.py`. Every report is kept in
`watchtower.detection_quality`, so a rule change shows up as a step in
the trend.

It first waits for `watchtower_pipeline` to have found the pipeline
healthy in the last 20 minutes: measured on a broken pipeline, detection
would look broken too. With no healthy verdict within an hour, the run is
**skipped**, not failed.

Defined only where the traffic is synthetic
(`WATCHTOWER_SYNTHETIC_TRAFFIC=true`): real logs carry no ground truth.
Trigger by hand with a different window: **Trigger DAG w/ config** →
`{"minutes": 5}`.
"""

import os
from datetime import datetime, timedelta, timezone

from airflow.sdk import CronTriggerTimetable, Param, dag, task
from airflow.sdk.exceptions import AirflowFailException

from orchestration.ops import detection, pipeline
from orchestration.ops.clickhouse import ClickHouse

SYNTHETIC = os.getenv("WATCHTOWER_SYNTHETIC_TRAFFIC", "false").lower() == "true"


@dag(
    # No data interval: the evaluator measures the minutes before it runs.
    schedule=CronTriggerTimetable("15 */6 * * *", timezone="UTC"),
    start_date=datetime(2026, 9, 1, tzinfo=timezone.utc),
    catchup=False,
    max_active_runs=1,
    default_args={"owner": "dataops", "retries": 1, "retry_delay": timedelta(minutes=5)},
    params={"minutes": Param(15, type="integer", minimum=1, maximum=60,
                             description="Window to evaluate, in minutes")},
    tags=["watchtower", "detection"],
    doc_md=__doc__,
)
def watchtower_detection_quality():

    @task.sensor(poke_interval=120, timeout=3600, mode="reschedule", soft_fail=True)
    def pipeline_healthy():
        return pipeline.healthy_recently(ClickHouse(), max_age_minutes=20)

    # Holds the window's ground truth in memory: ~300 MB for 15 minutes at
    # 1,000 events/s.
    @task(execution_timeout=timedelta(minutes=30))
    def evaluate(params=None):
        return detection.run(int(params["minutes"]))

    @task
    def assess(report):
        failures = detection.assess(report)
        for line in failures or ["all thresholds met"]:
            print(line)
        return failures

    @task
    def record(report, failures, run_id=None):
        ClickHouse().insert("watchtower.detection_quality", [detection.row(report, failures, run_id)])

    @task
    def gate(failures):
        if failures:
            raise AirflowFailException("; ".join(failures))

    report = evaluate()
    pipeline_healthy() >> report
    failures = assess(report)
    record(report, failures) >> gate(failures)


if SYNTHETIC:
    watchtower_detection_quality()
