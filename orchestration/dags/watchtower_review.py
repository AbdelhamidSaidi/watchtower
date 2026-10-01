"""
### Hourly review of what the pipeline passed

For the hour that just closed:

1. **collect_labels** — the simulator's ground truth for the hour, read
   back out of Kafka into `training_labels` (every incident event, 2% of
   normal ones). Only where the traffic is synthetic.
2. **select** — events worth a second look: passed near-misses (highest
   model scores), passed unusual ones (the hour's top 0.1% on a behaviour
   feature), a passed uniform random sample, and the model's own alerts.
   At most 150 a run, 3,000 a day.
3. **review** — Groq judges each: normal / degraded / incident, with a
   confidence and a reason. All verdicts go to `event_reviews`;
   disagreements appear in the `label_changes` view.
4. **learn** — confident disagreements become training labels, both ways:
   a passed event judged not normal (a missed incident), and a model-only
   alert judged normal (a false alarm). Adding any updates the
   `watchtower_training_labels` asset, which **starts a retraining now**.
5. **urgent** — fails the run if the reviewer is ≥ 90% sure a passed
   event was an incident: someone should look now, not after retraining.
6. **guard** — if the reviewer called more than half of the active
   model's own alerts normal (≥ 20 reviewed in 24 h), the previous model
   is promoted back and the run fails, so someone sees it.

Without a Groq key (`secrets/groq_api_key` empty) steps 3–5 are skipped.
"""

import os
from datetime import datetime, timedelta, timezone

from airflow.sdk import CronDataIntervalTimetable, dag, task
from airflow.sdk.exceptions import AirflowFailException, AirflowSkipException

from orchestration.assets import TRAINING_LABELS
from orchestration.ops import review, training
from orchestration.ops.clickhouse import ClickHouse
from orchestration.ops.quality import ch_time

SYNTHETIC = os.getenv("WATCHTOWER_SYNTHETIC_TRAFFIC", "false").lower() == "true"


@dag(
    schedule=CronDataIntervalTimetable("0 * * * *", timezone="UTC"),
    start_date=datetime(2026, 9, 1, tzinfo=timezone.utc),
    catchup=False,
    max_active_runs=1,
    default_args={"owner": "dataops", "retries": 1, "retry_delay": timedelta(minutes=5)},
    tags=["watchtower", "ml"],
    doc_md=__doc__,
)
def watchtower_review():

    @task(execution_timeout=timedelta(minutes=20))
    def collect_labels(data_interval_start=None, data_interval_end=None):
        if not SYNTHETIC:
            raise AirflowSkipException("real traffic: no ground truth to collect")
        rows = training.collect_labels(int(data_interval_start.timestamp() * 1000),
                                       int(data_interval_end.timestamp() * 1000))
        ClickHouse().insert("watchtower.training_labels", rows)
        incidents = sum(r["label"] for r in rows)
        print(f"{len(rows)} labels: {incidents} incident events, {len(rows) - incidents} sampled normal")

    @task
    def select(data_interval_start=None, data_interval_end=None):
        ch = ClickHouse()
        caps = review.budget(ch)
        if not sum(caps.values()):
            raise AirflowSkipException("today's review budget is spent")
        rows = review.candidates(ch, ch_time(data_interval_start), ch_time(data_interval_end), caps)
        print(f"{len(rows)} candidates (caps {caps})")
        return rows

    # none_failed: on real traffic collect_labels is skipped, and that must
    # not skip the review too.
    @task(execution_timeout=timedelta(minutes=20), trigger_rule="none_failed")
    def judge(rows, run_id=None):
        key = review.api_key()
        if not key:
            raise AirflowSkipException("no Groq key (secrets/groq_api_key): nothing reviewed")
        if not rows:
            return []
        reviews = review.review(rows, key, run_id)
        ClickHouse().insert("watchtower.event_reviews", reviews)
        changed = [r for r in reviews if r["verdict"] != "normal"]
        print(f"{len(reviews)} reviewed, {len(changed)} judged not normal")
        return reviews

    # Succeeding marks TRAINING_LABELS updated, which starts
    # watchtower_training; with nothing new it skips, and starts nothing.
    @task(outlets=[TRAINING_LABELS])
    def learn(reviews):
        labels = review.labels_from(reviews or [])
        if not labels:
            raise AirflowSkipException("no confident disagreement: nothing new to learn")
        ClickHouse().insert("watchtower.training_labels", labels)
        missed = sum(label["label"] for label in labels)
        print(f"{len(labels)} new labels: {missed} missed incidents, {len(labels) - missed} false alarms")

    @task
    def urgent(reviews):
        found = review.urgent(reviews or [])
        if found:
            raise AirflowFailException(
                f"{len(found)} passed event(s) the reviewer is sure were incidents: "
                + "; ".join(f"{r['event_id']} from {r['runner_ip']}: {r['reason']}" for r in found[:5]))

    @task
    def guard(reviews):
        rolled = training.guard(ClickHouse())
        if rolled:
            raise AirflowFailException(rolled["reason"] + f"; now scoring with {rolled['to']}")

    reviews = judge(select())
    collect_labels() >> reviews
    learn(reviews)
    urgent(reviews)
    guard(reviews)


watchtower_review()
