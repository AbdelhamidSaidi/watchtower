"""
### The pipeline, end to end

Every 10 minutes, the whole path an event takes, in order — the graph
turns red at the stage where it is broken:

```
kafka ──────────┐
schema_registry ┼─> stream_job ─> sample_flow ─┬─> extract ───┐
clickhouse ─────┘                             ├─> transform ─┼─> record ─> verdict
                                              └─> load ──────┘
```

| task | checks | fails when |
|---|---|---|
| kafka, schema_registry, clickhouse | each service answers, topics / schema / tables exist | one is down or not set up |
| stream_job | the Flink job is RUNNING; a job stopped for good is restarted through the Flink operator (Kubernetes) | not RUNNING within 5 min |
| sample_flow | every topic's offsets and both consumer groups' lag, 20 s apart | Kafka unreachable |
| extract | events arriving in `security-logs` | fewer than `min_input_rate`/s |
| transform | Flink's lag; results written per event arriving | > 120 s behind, or writing < half of what arrives |
| load | ClickHouse's intake lag; rows landing; latency; intake errors | > 60 s behind, or no rows in the last minute |

Every result goes to `watchtower.pipeline_health`, including those of a
failed stage. `verdict` runs only if a stage failed, and fails: that is
what marks the run failed, since `record` succeeds either way. A healthy `load` also marks the `watchtower_security_events`
asset as updated. `watchtower_detection_quality` waits for a healthy
verdict here before it measures live traffic.
"""

from datetime import datetime, timedelta, timezone

from airflow.sdk import Asset, CronTriggerTimetable, Param, dag, get_current_context, task
from airflow.sdk.exceptions import AirflowFailException

from orchestration.ops import pipeline
from orchestration.ops.clickhouse import ClickHouse

SECURITY_EVENTS = Asset(name="watchtower_security_events", uri="clickhouse://clickhouse/watchtower/security_events")
STAGES = ["kafka", "schema_registry", "clickhouse", "stream_job", "extract", "transform", "load"]


def report(results):
    """Keep this stage's results for `record` whatever happens next, print
    them, and fail the task on a failed `fail` check."""
    get_current_context()["ti"].xcom_push(key="results", value=results)
    for r in results:
        print(("OK   " if r["passed"] else "FAIL " if r["severity"] == "fail" else "WARN ") + r["detail"])
    failed = pipeline.failures(results)
    if failed:
        # No retry: the next run is 10 minutes away and sees fresh state.
        raise AirflowFailException("; ".join(r["detail"] for r in failed))
    return results


@dag(
    schedule=CronTriggerTimetable("*/10 * * * *", timezone="UTC"),
    start_date=datetime(2026, 9, 1, tzinfo=timezone.utc),
    catchup=False,
    max_active_runs=1,
    default_args={"owner": "dataops", "retries": 0},
    params={"min_input_rate": Param(1.0, type="number", minimum=0,
                                    description="Events/s below which the input counts as stopped")},
    tags=["watchtower", "pipeline"],
    doc_md=__doc__,
)
def watchtower_pipeline():

    @task(execution_timeout=timedelta(minutes=2))
    def kafka():
        return report(pipeline.check_kafka())

    @task(execution_timeout=timedelta(minutes=2))
    def schema_registry():
        return report(pipeline.check_registry())

    @task(execution_timeout=timedelta(minutes=2))
    def clickhouse():
        return report(pipeline.check_clickhouse(ClickHouse()))

    @task(execution_timeout=timedelta(minutes=10))
    def stream_job():
        return report(pipeline.ensure_stream_job())

    @task(execution_timeout=timedelta(minutes=3))
    def sample_flow():
        sample = pipeline.sample_flow()
        print(sample)
        return sample

    @task
    def extract(sample, params=None):
        return report(pipeline.judge_extract(sample, float(params["min_input_rate"])))

    @task
    def transform(sample):
        return report(pipeline.judge_transform(sample))

    @task(outlets=[SECURITY_EVENTS])
    def load(sample, params=None):
        return report(pipeline.judge_load(sample, ClickHouse(), float(params["min_input_rate"])))

    # all_done: runs after a failed stage too -- a broken pipeline is
    # exactly the run whose evidence must be kept.
    @task(trigger_rule="all_done")
    def record(run_id=None):
        ti = get_current_context()["ti"]
        rows = [
            {**r, "run_id": run_id, "passed": int(r["passed"])}
            for results in ti.xcom_pull(task_ids=STAGES, key="results")
            if results
            for r in results
        ]
        ClickHouse().insert("watchtower.pipeline_health", rows)
        print(f"{len(rows)} results recorded")

    # Airflow judges a run by its last tasks. `record` succeeds even after a
    # stage failed, so without this the run of a broken pipeline would
    # show green. Skipped -- and the run green -- when every stage passed.
    @task(trigger_rule="one_failed")
    def verdict():
        raise AirflowFailException("a pipeline stage failed -- see the red task, or "
                                   "watchtower.pipeline_health for this run")

    services = [kafka(), schema_registry(), clickhouse()]
    job, sample = stream_job(), sample_flow()
    stages = [extract(sample), transform(sample), load(sample)]
    services >> job >> sample
    done = verdict()
    stages >> record() >> done
    # Directly downstream of every check, so any failure reaches it.
    [*services, job, sample, *stages] >> done


watchtower_pipeline()
