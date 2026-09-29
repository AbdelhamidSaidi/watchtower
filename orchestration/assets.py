"""Airflow assets: the data that ties one DAG's output to another's start.

TRAINING_LABELS is updated when the reviewer (watchtower_review) adds
labels, and that update starts watchtower_training: the model retrains on
the reviewer's corrections within the hour, not the next night.
"""

from airflow.sdk import Asset

TRAINING_LABELS = Asset(name="watchtower_training_labels",
                        uri="clickhouse://clickhouse/watchtower/training_labels")
