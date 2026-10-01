"""The model and the loop that trains it.

  active    which version is promoted, since when, and what it scored on
            its holdout and its shadow check when the gate let it through
  serving   the version Flink actually scored the last minute's events with
            (ModelSource polls every 5 minutes, so a new promotion shows
            here within 5)
  reviewer  the AI reviewer's verdicts over 24 h, its disagreements with the
            pipeline, and the guard's inputs: how many of the active model's
            own alerts it reviewed, and how many it called benign
  labels    what the next training run will learn from
"""

import json
import time

from monitor.exposition import gauge
from orchestration.ops.training import GUARD_MAX_FALSE_ALARMS, GUARD_MIN_REVIEWED, REVIEW_MIN_CONFIDENCE

ACTIVE = """
SELECT version, toUnixTimestamp64Milli(activated_at) AS at, reason
FROM watchtower.ml_model_active ORDER BY activated_at DESC LIMIT 1"""

TRAINED = """
SELECT trained_rows, metrics FROM watchtower.ml_models
WHERE version = {version:String} ORDER BY created_at DESC LIMIT 1"""

HISTORY = """
SELECT (SELECT count() FROM watchtower.ml_models) AS trained,
       count() AS activations, countIf(startsWith(reason, 'rollback')) AS rollbacks
FROM watchtower.ml_model_active"""

SERVING = """
SELECT ml_model AS model, count() AS n FROM watchtower.security_events
WHERE timestamp > now64(3) - INTERVAL 10 MINUTE AND ingested_at > now64(3) - INTERVAL 60 SECOND
GROUP BY model ORDER BY n DESC"""

REVIEWS = """
SELECT why_selected, verdict, count() AS n FROM watchtower.event_reviews
WHERE reviewed_at > now64(3) - INTERVAL 24 HOUR GROUP BY why_selected, verdict"""

LAST_REVIEW = """
SELECT toUnixTimestamp64Milli(max(reviewed_at)) AS at, count() AS n FROM watchtower.event_reviews"""

DISAGREEMENTS = """
SELECT count() AS n FROM watchtower.label_changes
WHERE reviewed_at > now64(3) - INTERVAL 24 HOUR AND confidence >= {confidence:Float64}"""

# orchestration/ops/training.py guard(), on the active version.
GUARD = """
SELECT countIf(why_selected = 'model_alert') AS reviewed,
       countIf(why_selected = 'model_alert' AND verdict = 'benign' AND confidence >= {confidence:Float64}) AS benign
FROM watchtower.event_reviews
WHERE ml_model = {version:String} AND reviewed_at > now64(3) - INTERVAL 24 HOUR"""

LABELS = """
SELECT source, label, count() AS n FROM watchtower.training_labels GROUP BY source, label"""

HOLDOUT_RATES = ("average_precision", "precision_at_alert", "recall_at_alert", "false_positive_rate_at_alert")
HOLDOUT_COUNTS = ("rows", "attacks", "normal", "false_positives")
SHADOW = ("rows", "sources", "candidate_alerts", "candidate_sources", "incumbent_alerts", "incumbent_sources")


class ModelLifecycle:
    name = "model"
    interval = 30.0

    def __init__(self, ch):
        self.ch = ch

    def collect(self):
        f = []
        active = self.ch.row(ACTIVE)
        history = self.ch.row(HISTORY)
        f.append(gauge("watchtower_models_trained", "Models trained so far (watchtower.ml_models).")
                 .add(int(history["trained"])))
        acts = gauge("watchtower_model_activations",
                     "Rows in ml_model_active: promotions by the gate, and rollbacks by the guard.")
        acts.add(int(history["activations"]) - int(history["rollbacks"]), kind="promotion")
        acts.add(int(history["rollbacks"]), kind="rollback")
        f.append(acts)

        version = active["version"] if active else None
        if version:
            f.append(gauge("watchtower_model_active_info", "The active model version (value 1).")
                     .add(1, version=version))
            f.append(gauge("watchtower_model_activated_timestamp_seconds",
                           "When the active model was activated.").add(active["at"] / 1000))
            trained = self.ch.row(TRAINED, version=version)
            if trained:
                f += self._report(json.loads(trained["metrics"]), int(trained["trained_rows"]))

        serving = self.ch.rows(SERVING)
        if serving:
            top = serving[0]["model"] or "none"
            f.append(gauge("watchtower_model_serving_info",
                           "The model version most of the last minute's events were scored with "
                           "(none: rules alone).").add(1, version=top))
            if version:
                f.append(gauge("watchtower_model_serving_matches_active",
                               "1 when Flink scores with the active model.").add(int(top == version)))

        reviews = gauge("watchtower_reviews_24h", "AI reviews in the last 24 h, by why the event was "
                        "selected and the reviewer's verdict.")
        for r in self.ch.rows(REVIEWS):
            reviews.add(int(r["n"]), why_selected=r["why_selected"], verdict=r["verdict"])
        f.append(reviews)
        last = self.ch.row(LAST_REVIEW)
        if int(last["n"]):
            f.append(gauge("watchtower_last_review_timestamp_seconds", "When the newest review was written.")
                     .add(last["at"] / 1000))
        f.append(gauge("watchtower_reviewer_disagreements_24h",
                       "Confident reviews in 24 h that disagree with the pipeline (label_changes): "
                       "an allowed event judged not benign, or a model alert judged benign.")
                 .add(int(self.ch.row(DISAGREEMENTS, confidence=REVIEW_MIN_CONFIDENCE)["n"])))

        if version:
            g = self.ch.row(GUARD, version=version, confidence=REVIEW_MIN_CONFIDENCE)
            guard = gauge("watchtower_guard_model_alerts_24h",
                          "The active model's own alerts the reviewer judged in 24 h, and how many it "
                          "called benign. The guard rolls back past its thresholds.")
            guard.add(int(g["reviewed"]), kind="reviewed")
            guard.add(int(g["benign"]), kind="benign")
            f.append(guard)
            limits = gauge("watchtower_guard_threshold", "The guard's rollback thresholds "
                           "(orchestration/ops/training.py).")
            limits.add(GUARD_MIN_REVIEWED, kind="min_reviewed")
            limits.add(GUARD_MAX_FALSE_ALARMS, kind="max_benign_share")
            f.append(limits)

        labels = gauge("watchtower_training_labels", "Training labels by source and label (1 attack, 0 benign); "
                       "copies not yet merged count twice.")
        for r in self.ch.rows(LABELS):
            labels.add(int(r["n"]), source=r["source"], label=str(r["label"]))
        f.append(labels)
        f.append(gauge("watchtower_model_scrape_timestamp_seconds", "When this was read.").add(time.time()))
        return f

    @staticmethod
    def _report(report, trained_rows):
        holdout = report.get("holdout") or {}
        rates = gauge("watchtower_model_holdout",
                      "The active model on its holdout when it was trained (threshold 0.65 = alert).")
        for name in HOLDOUT_RATES:
            rates.add(holdout.get(name), metric=name)
        counts = gauge("watchtower_model_holdout_events", "The active model's holdout: its size and false alarms.")
        for name in HOLDOUT_COUNTS:
            counts.add(holdout.get(name), kind=name)
        shadow = gauge("watchtower_model_shadow",
                       "The promotion gate's shadow check: the candidate alone on recent traffic, "
                       "against the incumbent.")
        for name in SHADOW:
            shadow.add((report.get("shadow") or {}).get(name), kind=name)
        wrong = (report.get("reviewed_events") or {}).get("wrong") or [None, None]
        reviewed = gauge("watchtower_model_reviewed_events",
                         "The gate's reviewed-events check: how many reviewed events it had, and how many "
                         "the candidate and the incumbent got wrong.")
        reviewed.add((report.get("reviewed_events") or {}).get("count"), kind="count")
        reviewed.add(wrong[0], kind="wrong_candidate")
        reviewed.add(wrong[1], kind="wrong_incumbent")
        return [
            gauge("watchtower_model_trained_rows", "Labelled rows the active model was trained on.").add(trained_rows),
            rates, counts, shadow, reviewed,
        ]
