"""
### Training the stream's ML detector

Runs **whenever the reviewer adds labels** (the `watchtower_training_labels`
asset, updated by `watchtower_review`), and nightly regardless.

Trains a LightGBM model on the last 14 days of labelled events — the
simulator's ground truth plus the reviewer's confident corrections
(`watchtower_review`) — and scores it against the active model on the
same holdout: events neither trained on, and never relabelled by the
reviewer.

The new model is registered in `ml_models` either way, and **promoted**
(a row in `ml_model_active`) only if it is at least as good: average
precision no lower, false positives no higher. The Flink job picks up a
promoted model within 5 minutes, without a restart.

Rolling back: insert an older version into `ml_model_active`.
Switching the model off: `WATCHTOWER_ML=off` on the Flink job.
"""

import json
from datetime import datetime, timedelta, timezone

from airflow.sdk import AssetOrTimeSchedule, CronTriggerTimetable, dag, task
from airflow.sdk.exceptions import AirflowSkipException

from orchestration.assets import TRAINING_LABELS
from orchestration.ops import training


@dag(
    # New reviewer labels start a run at once; the nightly run picks up the
    # simulator's labels (collected hourly) even when the reviewer is quiet.
    schedule=AssetOrTimeSchedule(timetable=CronTriggerTimetable("30 2 * * *", timezone="UTC"),
                                 assets=[TRAINING_LABELS]),
    start_date=datetime(2026, 9, 1, tzinfo=timezone.utc),
    catchup=False,
    max_active_runs=1,
    default_args={"owner": "dataops", "retries": 1, "retry_delay": timedelta(minutes=10)},
    tags=["watchtower", "ml"],
    doc_md=__doc__,
)
def watchtower_training():

    # Holds the dataset in memory: 14 days of labels (all attack events, 2%
    # of normal ones) -- ~100-300k rows at 1,000 events/s.
    @task(execution_timeout=timedelta(hours=1))
    def train_and_promote():
        report = training.run()
        print(json.dumps(report, indent=2))
        if report.get("status") == "skipped":
            raise AirflowSkipException(report["reason"])
        return report

    train_and_promote()


watchtower_training()
