-- The ML detector's lifecycle (orchestration/dags):
--
--   training_labels   what each event really was, and who said so
--   event_reviews     the Groq reviewer's verdicts (hourly)
--   label_changes     (view) reviews that disagree with the pipeline
--   ml_models         every trained model: its dump, its metrics
--   ml_model_active   which model the stream scores with (newest row wins)
--
-- The Flink job reads the last two (etl/stream/models.py); Airflow writes
-- all five. security_events is never rewritten: a review sits beside the
-- event, joined by event_id, and the original decision stays auditable.

-- Labels for training. `source` says where a label came from:
--   simulator  the producer's ground truth (synthetic traffic only)
--   reviewer   the Groq reviewer, when it disagreed confidently
-- A reviewer label outranks a simulator one for the same event (newest
-- wins at training time).
CREATE TABLE IF NOT EXISTS watchtower.training_labels
(
    event_id     UUID,
    label        UInt8,                    -- 1 incident, 0 normal
    source       LowCardinality(String),
    weight       Float32 DEFAULT 1,
    labeled_at   DateTime64(3, 'UTC') DEFAULT now64(3),
    detail       String DEFAULT ''
)
ENGINE = ReplacingMergeTree(labeled_at)
ORDER BY (event_id, source)
TTL toDateTime(labeled_at) + INTERVAL 90 DAY;

CREATE TABLE IF NOT EXISTS watchtower.event_reviews
(
    reviewed_at      DateTime64(3, 'UTC') DEFAULT now64(3),
    run_id           String,
    event_id         UUID,
    event_time       DateTime64(3, 'UTC'),
    runner_ip        String,
    event_type       LowCardinality(String),
    pipeline_action  LowCardinality(String),
    ml_score         Float32,
    ml_model         LowCardinality(String),   -- the model version that scored it
    why_selected     LowCardinality(String),   -- near_miss | unusual | random | model_alert
    verdict          LowCardinality(String),   -- normal | degraded | incident
    confidence       Float32,
    reason           String,
    reviewer         LowCardinality(String)    -- the LLM model id
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(reviewed_at)
ORDER BY (reviewed_at, event_id)
TTL toDateTime(reviewed_at) + INTERVAL 365 DAY;
-- Installs created before ml_model was recorded per review.
ALTER TABLE watchtower.event_reviews ADD COLUMN IF NOT EXISTS ml_model LowCardinality(String) AFTER ml_score;
-- label_changes was a materialized view before it became a plain view. It
-- never held rows (no review ran before the change); drop the old one.
DROP VIEW IF EXISTS watchtower.mv_label_changes;

-- The reviews that matter: the reviewer disagreed with the pipeline --
-- an event the pipeline let through that it judged not normal, or a
-- model-only alert it judged normal. A report for the build team. A plain view: it stores nothing, so its
-- definition can change without losing history.
CREATE OR REPLACE VIEW watchtower.label_changes AS
SELECT reviewed_at, run_id, event_id, event_time, runner_ip, event_type,
       pipeline_action, why_selected, ml_model, ml_score, verdict, confidence, reason, reviewer
FROM watchtower.event_reviews
WHERE (pipeline_action = 'ok' AND verdict != 'normal')
   OR (why_selected = 'model_alert' AND verdict = 'normal');

CREATE TABLE IF NOT EXISTS watchtower.ml_models
(
    version       String,
    created_at    DateTime64(3, 'UTC') DEFAULT now64(3),
    trained_rows  UInt64,
    metrics       String,                  -- JSON: holdout scores, and the incumbent's
    params        String,                  -- JSON: training parameters
    model         String                   -- LightGBM dump_model() JSON
)
ENGINE = MergeTree
ORDER BY (created_at, version)
TTL toDateTime(created_at) + INTERVAL 365 DAY;

-- Promotion is an insert: the newest row is the active model. Rolling back
-- is inserting an older version again.
CREATE TABLE IF NOT EXISTS watchtower.ml_model_active
(
    activated_at  DateTime64(3, 'UTC') DEFAULT now64(3),
    version       String,
    reason        String
)
ENGINE = MergeTree
ORDER BY activated_at;

-- ---- OLAP over the model's life ----------------------------------------------
-- Plain views: computed when queried, always current, nothing to backfill.

-- What each model did, hour by hour, in the stream.
CREATE OR REPLACE VIEW watchtower.ml_decisions_hourly AS
SELECT toStartOfHour(timestamp) AS hour, ml_model,
       count() AS events,
       countIf(ml_reason != '') AS raised_by_model,
       countIf(ml_reason != '' AND recommended_action = 'alert') AS model_alerts,
       round(avg(ml_score), 4) AS avg_ml_score,
       round(quantile(0.99)(ml_score), 4) AS p99_ml_score,
       countIf(recommended_action = 'quarantine') AS quarantined,
       countIf(recommended_action = 'alert') AS alerted
FROM watchtower.security_events
GROUP BY hour, ml_model;

-- How each model fares under review: of its own alerts, how many the
-- reviewer called normal; of what it let through, how many were incidents.
CREATE OR REPLACE VIEW watchtower.ml_model_review AS
SELECT ml_model, toStartOfHour(reviewed_at) AS hour,
       count() AS reviewed,
       countIf(why_selected = 'model_alert') AS model_alerts_reviewed,
       countIf(why_selected = 'model_alert' AND verdict = 'normal' AND confidence >= 0.8) AS false_alarms,
       countIf(pipeline_action = 'ok') AS passed_reviewed,
       countIf(pipeline_action = 'ok' AND verdict != 'normal' AND confidence >= 0.8) AS missed_incidents,
       countIf(why_selected = 'random') AS random_reviewed,
       countIf(why_selected = 'random' AND verdict != 'normal' AND confidence >= 0.8) AS random_missed
FROM watchtower.event_reviews
GROUP BY ml_model, hour;
