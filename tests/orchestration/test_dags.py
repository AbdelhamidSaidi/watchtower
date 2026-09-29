"""The DAG files: they parse, and they are wired the way the docs say.

Parsing is what the DAG processor does every minute; an import error
there silently removes a DAG from the UI. This catches it before deploy.
Runs in the Airflow image (`make test-airflow`).
"""

import os

import pytest

pytest.importorskip("airflow")

from airflow.dag_processing.dagbag import DagBag  # noqa: E402

DAGS = os.path.join(os.path.dirname(__file__), "..", "..", "orchestration", "dags")


def load(monkeypatch, synthetic):
    monkeypatch.setenv("WATCHTOWER_SYNTHETIC_TRAFFIC", "true" if synthetic else "false")
    # Examples are off by config (AIRFLOW__CORE__LOAD_EXAMPLES in the image).
    bag = DagBag(dag_folder=DAGS)
    assert bag.import_errors == {}
    return bag.dags


def test_all_dags_parse_where_traffic_is_synthetic(monkeypatch):
    assert set(load(monkeypatch, synthetic=True)) == {
        "watchtower_pipeline", "watchtower_data_quality", "watchtower_daily",
        "watchtower_detection_quality", "watchtower_review", "watchtower_training",
    }


def test_no_detection_quality_on_real_traffic(monkeypatch):
    assert "watchtower_detection_quality" not in load(monkeypatch, synthetic=False)


def test_every_dag_runs_one_at_a_time_without_catchup(monkeypatch):
    for dag in load(monkeypatch, synthetic=True).values():
        assert dag.max_active_runs == 1 and dag.catchup is False, dag.dag_id
        assert "watchtower" in dag.tags
        for t in dag.tasks:
            assert t.owner == "dataops"


def downstream(dag, task_id):
    return {t for t in dag.get_task(task_id).downstream_task_ids}


def test_pipeline_follows_the_data(monkeypatch):
    dag = load(monkeypatch, synthetic=True)["watchtower_pipeline"]
    for service in ("kafka", "schema_registry", "clickhouse"):
        assert downstream(dag, service) == {"stream_job", "verdict"}
    assert downstream(dag, "stream_job") == {"sample_flow", "verdict"}
    assert downstream(dag, "sample_flow") == {"extract", "transform", "load", "verdict"}
    for stage in ("extract", "transform", "load"):
        assert downstream(dag, stage) == {"record", "verdict"}
    assert downstream(dag, "record") == {"verdict"}


def test_pipeline_records_even_when_a_stage_fails(monkeypatch):
    dag = load(monkeypatch, synthetic=True)["watchtower_pipeline"]
    assert dag.get_task("record").trigger_rule == "all_done"
    # ...and still ends failed: `verdict` sees every check directly.
    assert dag.get_task("verdict").trigger_rule == "one_failed"
    assert len(dag.tasks) == 10
    # Only a verified load says the events table is fresh.
    assert [a.name for a in dag.get_task("load").outlets] == ["watchtower_security_events"]


def test_data_quality_records_every_result_before_the_gate(monkeypatch):
    dag = load(monkeypatch, synthetic=True)["watchtower_data_quality"]
    assert downstream(dag, "run_check") == {"record", "gate"}
    assert downstream(dag, "record") == {"gate"}


def test_daily_steps_run_in_order(monkeypatch):
    dag = load(monkeypatch, synthetic=True)["watchtower_daily"]
    chain = ["day_closed", "deduplicate", "summarize", "reconcile"]
    for before, after in zip(chain, chain[1:]):
        assert downstream(dag, before) == {after}
    assert dag.get_task("day_closed").mode == "reschedule"


def test_detection_quality_records_before_the_gate(monkeypatch):
    dag = load(monkeypatch, synthetic=True)["watchtower_detection_quality"]
    # Measured only on a pipeline found healthy; skipped, not failed, otherwise.
    assert downstream(dag, "pipeline_healthy") == {"evaluate"}
    assert dag.get_task("pipeline_healthy").soft_fail
    assert downstream(dag, "evaluate") == {"assess", "record"}
    assert downstream(dag, "record") == {"gate"}
    assert dag.params["minutes"] == 15


def test_review_judges_then_learns_and_alerts(monkeypatch):
    dag = load(monkeypatch, synthetic=True)["watchtower_review"]
    assert downstream(dag, "select") == {"judge"}
    assert downstream(dag, "judge") == {"learn", "urgent", "guard"}
    # New labels are what start a retraining.
    assert [a.name for a in dag.get_task("learn").outlets] == ["watchtower_training_labels"]
    # On real traffic collect_labels is skipped; the review must still run.
    assert downstream(dag, "collect_labels") == {"judge"}
    assert dag.get_task("judge").trigger_rule == "none_failed"


def test_training_starts_when_the_reviewer_adds_labels(monkeypatch):
    dag = load(monkeypatch, synthetic=True)["watchtower_training"]
    assert "watchtower_training_labels" in repr(dag.timetable)
