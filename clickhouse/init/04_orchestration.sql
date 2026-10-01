-- Tables written by Airflow (orchestration/dags), the batch side of the
-- pipeline. The live path never reads them.
--
--   watchtower_pipeline           every 10 min -> pipeline_health
--   watchtower_data_quality       hourly  -> data_quality_checks
--   watchtower_daily              daily   -> daily_summary, daily_rule_hits,
--                                            daily_top_sources (runners)
--   watchtower_detection_quality  6-hourly -> detection_quality
--
-- The daily tables are PARTITIONED BY DAY so a day is rebuilt idempotently:
-- the DAG drops the day's partition and inserts it again. Re-running or
-- backfilling a day never double-counts.

-- The pipeline end to end, every 10 minutes: one row per check, per stage
-- (infrastructure, stream_job, extract, transform, load). Other DAGs read
-- the latest verdict here before trusting live data
-- (orchestration/ops/pipeline.py healthy_recently).
CREATE TABLE IF NOT EXISTS watchtower.pipeline_health
(
    checked_at   DateTime64(3, 'UTC') DEFAULT now64(3),
    run_id       String,
    stage        LowCardinality(String),
    check_name   LowCardinality(String),
    severity     LowCardinality(String),
    value        Nullable(Float64),
    threshold    Float64,
    passed       UInt8,
    detail       String
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(checked_at)
ORDER BY (checked_at, stage, check_name)
TTL toDateTime(checked_at) + INTERVAL 90 DAY;

-- One row per check per run. A failed `fail` check fails the DAG run; a
-- `warn` check is recorded and visible here, nothing more.
CREATE TABLE IF NOT EXISTS watchtower.data_quality_checks
(
    checked_at      DateTime64(3, 'UTC') DEFAULT now64(3),
    run_id          String,
    interval_start  DateTime('UTC'),
    interval_end    DateTime('UTC'),
    check_name      LowCardinality(String),
    severity        LowCardinality(String),
    value           Nullable(Float64),
    threshold       Float64,
    passed          UInt8,
    detail          String
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(interval_start)
ORDER BY (check_name, interval_start, checked_at)
TTL toDateTime(checked_at) + INTERVAL 180 DAY;

-- Events per day, type and decision. Additive: sum(events) for a day is the
-- day's event count (watchtower_daily reconciles exactly that).
CREATE TABLE IF NOT EXISTS watchtower.daily_summary
(
    day                 Date,
    event_type          LowCardinality(String),
    recommended_action  LowCardinality(String),
    events              UInt64,
    runners             UInt64,
    suspicious          UInt64,
    built_at            DateTime DEFAULT now()
)
ENGINE = MergeTree
PARTITION BY day
ORDER BY (day, event_type, recommended_action)
TTL day + INTERVAL 400 DAY;

-- Events per day and rule. NOT additive: an event that fired three rules
-- is counted under each.
CREATE TABLE IF NOT EXISTS watchtower.daily_rule_hits
(
    day                 Date,
    rule                LowCardinality(String),
    recommended_action  LowCardinality(String),
    events              UInt64,
    runners             UInt64,
    built_at            DateTime DEFAULT now()
)
ENGINE = MergeTree
PARTITION BY day
ORDER BY (day, rule, recommended_action)
TTL day + INTERVAL 400 DAY;

-- The day's most-quarantined runners: the build team's morning list.
CREATE TABLE IF NOT EXISTS watchtower.daily_top_sources
(
    day          Date,
    runner_ip    String,
    events       UInt64,
    quarantined  UInt64,
    alerted      UInt64,
    first_seen   DateTime64(3, 'UTC'),
    last_seen    DateTime64(3, 'UTC'),
    rules        Array(String),
    built_at     DateTime DEFAULT now()
)
ENGINE = MergeTree
PARTITION BY day
ORDER BY (day, quarantined, runner_ip)
TTL day + INTERVAL 400 DAY;

-- Detection quality against the synthetic producer's ground truth
-- (tools/evaluate_detection.py). `report` is the evaluator's full JSON.
CREATE TABLE IF NOT EXISTS watchtower.detection_quality
(
    evaluated_at                DateTime64(3, 'UTC') DEFAULT now64(3),
    run_id                      String,
    window_minutes              UInt16,
    events                      UInt64,
    coverage                    Nullable(Float64),
    incidents_seen              UInt32,
    incidents_caught            UInt32,
    incident_events_flagged     Nullable(Float64),
    incident_events_quarantined Nullable(Float64),
    normal_quarantined          UInt64,
    normal_quarantined_uninvolved UInt64,
    normal_events               UInt64,
    precision_quarantine        Nullable(Float64),
    median_time_to_flag_s       Nullable(Float64),
    passed                      UInt8,
    failures                    Array(String),
    report                      String
)
ENGINE = MergeTree
ORDER BY evaluated_at
TTL toDateTime(evaluated_at) + INTERVAL 400 DAY;
