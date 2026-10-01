"""Airflow's verdicts, from the tables its DAGs write.

  pipeline_health       every 10 minutes: each stage of the path checked
  data_quality_checks   hourly: the closed hour's data
  detection_quality     every 6 hours: detection against ground truth

Each shows its latest run and when it ran: a verdict is only as good as its
age, and when Airflow is down the ages grow while the values stay put.
"""

import json

from monitor.exposition import gauge

PIPELINE = """
SELECT stage, check_name, severity, passed, value, toUnixTimestamp64Milli(checked_at) AS at
FROM watchtower.pipeline_health
WHERE run_id = (SELECT argMax(run_id, checked_at) FROM watchtower.pipeline_health)"""

QUALITY = """
SELECT check_name, severity, passed, value, toUnixTimestamp64Milli(checked_at) AS at,
       toUnixTimestamp(interval_end) AS interval_end
FROM watchtower.data_quality_checks
WHERE run_id = (SELECT argMax(run_id, checked_at) FROM watchtower.data_quality_checks)"""

DETECTION = """
SELECT toUnixTimestamp64Milli(evaluated_at) AS at, window_minutes, events, coverage, incidents_seen,
       incidents_caught, incident_events_flagged, incident_events_quarantined, normal_quarantined_uninvolved,
       normal_events, precision_quarantine, median_time_to_flag_s, passed, report
FROM watchtower.detection_quality ORDER BY evaluated_at DESC LIMIT 1"""


class AirflowVerdicts:
    name = "verdicts"
    interval = 30.0

    def __init__(self, ch):
        self.ch = ch

    def collect(self):
        f = []
        rows = self.ch.rows(PIPELINE)
        if rows:
            passed = gauge("watchtower_pipeline_check_passed",
                           "The latest end-to-end pipeline check (watchtower_pipeline DAG), per stage and check.")
            value = gauge("watchtower_pipeline_check_value", "The value each pipeline check measured.")
            for r in rows:
                labels = {"stage": r["stage"], "check": r["check_name"], "severity": r["severity"]}
                passed.add(int(r["passed"]), **labels)
                value.add(r["value"], **labels)
            f += [passed, value, gauge("watchtower_pipeline_check_timestamp_seconds",
                                       "When the latest pipeline check ran.")
                  .add(max(r["at"] for r in rows) / 1000)]

        rows = self.ch.rows(QUALITY)
        if rows:
            passed = gauge("watchtower_quality_check_passed",
                           "The latest hourly data-quality run (watchtower_data_quality DAG), per check.")
            value = gauge("watchtower_quality_check_value", "The value each data-quality check measured.")
            for r in rows:
                passed.add(int(r["passed"]), check=r["check_name"], severity=r["severity"])
                value.add(r["value"], check=r["check_name"], severity=r["severity"])
            f += [passed, value,
                  gauge("watchtower_quality_check_timestamp_seconds", "When the latest data-quality run ran.")
                  .add(max(r["at"] for r in rows) / 1000),
                  gauge("watchtower_quality_interval_end_timestamp_seconds", "The end of the hour it checked.")
                  .add(max(r["interval_end"] for r in rows))]

        r = self.ch.row(DETECTION)
        if r:
            summary = json.loads(r["report"]).get("summary", {}) if r["report"] else {}
            metrics = gauge("watchtower_detection_eval",
                            "The latest 6-hourly detection evaluation (watchtower_detection_quality DAG).")
            for name in ("coverage", "incident_events_flagged", "incident_events_quarantined", "precision_quarantine",
                         "median_time_to_flag_s"):
                metrics.add(r[name], metric=name)
            metrics.add(summary.get("model_only_precision"), metric="model_only_precision")
            counts = gauge("watchtower_detection_eval_events", "Counts from the latest detection evaluation.")
            for name in ("events", "incidents_seen", "incidents_caught", "normal_quarantined_uninvolved", "normal_events"):
                counts.add(r[name], kind=name)
            counts.add(summary.get("model_only_flags"), kind="model_only_flags")
            f += [metrics, counts,
                  gauge("watchtower_detection_eval_passed", "1 when the latest evaluation met every threshold.")
                  .add(int(r["passed"])),
                  gauge("watchtower_detection_eval_timestamp_seconds", "When it ran.").add(r["at"] / 1000),
                  gauge("watchtower_detection_eval_window_minutes", "The window it measured.")
                  .add(r["window_minutes"])]
        return f
