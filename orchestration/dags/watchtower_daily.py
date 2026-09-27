"""
### Daily rollup

For each day (UTC), once the stream has moved past it:

1. **day_closed** — wait until events from after midnight are stored, so
   the day's own are all in (or until the day ended an hour ago).
2. **deduplicate** — merge away replayed copies in the day's partition of
   `security_events` (only if there are any).
3. **summarize** — rebuild the day in `daily_summary`, `daily_rule_hits`
   and `daily_top_sources`.
4. **reconcile** — the summary must count exactly the day's stored events.

Idempotent: re-run a day, or backfill a range, and the tables come out
the same.

    airflow backfill create --dag-id watchtower_daily \\
        --from-date 2026-09-01 --to-date 2026-09-26
"""

from datetime import datetime, timedelta, timezone

from airflow.sdk import CronDataIntervalTimetable, dag, task
from airflow.sdk.exceptions import AirflowFailException

from orchestration.ops import daily
from orchestration.ops.clickhouse import ClickHouse


@dag(
    # Each run covers one UTC day, [00:00, 24:00).
    schedule=CronDataIntervalTimetable("0 0 * * *", timezone="UTC"),
    start_date=datetime(2026, 9, 1, tzinfo=timezone.utc),
    catchup=False,
    max_active_runs=1,
    default_args={"owner": "dataops", "retries": 2, "retry_delay": timedelta(minutes=5)},
    tags=["watchtower", "rollup"],
    doc_md=__doc__,
)
def watchtower_daily():

    # Reschedule mode: between pokes the sensor gives its slot back.
    @task.sensor(poke_interval=300, timeout=6 * 3600, mode="reschedule")
    def day_closed(data_interval_end=None):
        return daily.day_closed(ClickHouse(), data_interval_end, datetime.now(timezone.utc))

    @task(execution_timeout=timedelta(hours=2))
    def deduplicate(data_interval_start=None):
        found = daily.deduplicate(ClickHouse(), data_interval_start)
        print(f"{found} replayed copies merged away" if found else "no copies to merge")
        return found

    @task(execution_timeout=timedelta(hours=1))
    def summarize(data_interval_start=None):
        rows = daily.summarize(ClickHouse(), data_interval_start)
        print(rows)
        return rows

    @task
    def reconcile(data_interval_start=None):
        summarized, stored = daily.reconcile(ClickHouse(), data_interval_start)
        print(f"summarized {summarized:,}, stored {stored:,}")
        if summarized != stored:
            raise AirflowFailException(
                f"daily_summary counts {summarized:,} events, security_events holds {stored:,}: "
                "events arrived after the rollup -- clear and re-run the day"
            )

    day_closed() >> deduplicate() >> summarize() >> reconcile()


watchtower_daily()
