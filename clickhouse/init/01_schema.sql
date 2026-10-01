-- Watchtower analytical storage: build-farm logs.
-- Runs once, on first initialisation of an empty clickhouse-data volume.

CREATE DATABASE IF NOT EXISTS watchtower;

-- Final sink for the streaming job: raw event fields + enrichment +
-- rolling features + the detector's scores, one row per build-farm event
-- (a build starting or finishing, a compiler invocation, a test run, a
-- dependency fetch, an artifact upload).
--
-- The table, topics and schema subject keep the names they had as a
-- security-log pipeline (security_events, security-logs, ...): the data
-- changed, the plumbing did not.
CREATE TABLE IF NOT EXISTS watchtower.security_events
(
    -- ---- raw event (producer schema) ----------------------------------
    event_id                UUID,
    timestamp               DateTime64(3, 'UTC') CODEC(Delta, ZSTD(1)),
    runner_ip               LowCardinality(String),
    project                 LowCardinality(String),
    event_type              LowCardinality(String),
    hostname                LowCardinality(String),
    severity                LowCardinality(String),

    -- conditional fields, empty/0 when not applicable to the event_type
    reason                  LowCardinality(String) DEFAULT '',
    command                 String                 DEFAULT '' CODEC(ZSTD(3)),
    exit_code               UInt16                 DEFAULT 0,

    -- ---- enrichment ---------------------------------------------------
    is_internal_ip          UInt8   DEFAULT 0,
    region                  LowCardinality(String) DEFAULT '',

    -- ---- engineered features: the runner's last 1 and 5 minutes --------
    events_1m               UInt32  DEFAULT 0,
    failed_builds_1m        UInt32  DEFAULT 0,
    failed_builds_5m        UInt32  DEFAULT 0,
    unique_projects_5m      UInt32  DEFAULT 0,
    oom_kills_5m            UInt32  DEFAULT 0,
    distinct_exit_codes_5m  UInt32  DEFAULT 0,
    compile_steps_5m        UInt32  DEFAULT 0,
    build_frequency         Float32 DEFAULT 0,
    hour                    UInt8   DEFAULT 0,
    is_night                UInt8   DEFAULT 0,

    -- ---- detection ------------------------------------------------------
    -- Rules settle what is unambiguous; a LightGBM model (etl/core/ml.py),
    -- scored on the same features in the same pass, judges the rest.
    -- ml_reason names the features that drove a model score that mattered,
    -- so an alert can be explained without re-running anything; ml_model
    -- is the model version (watchtower.ml_models).
    -- final_anomaly_score = max(rule_score, ml_score), the model's share
    -- capped below `quarantine` unless a rule agrees
    -- (WATCHTOWER_ML_CAN_QUARANTINE). is_suspicious = flagged: alert or worse.
    rule_score              Float32 DEFAULT 0,
    rule_hits               LowCardinality(String) DEFAULT '',
    recommended_action      LowCardinality(String) DEFAULT 'ok',
    ml_score                Float32 DEFAULT 0,
    ml_reason               String  DEFAULT '',
    ml_model                LowCardinality(String) DEFAULT '',
    final_anomaly_score     Float32 DEFAULT 0,
    is_suspicious           UInt8   DEFAULT 0,

    -- ---- context: build, registry, process, step -----------------------
    log_source              LowCardinality(String) DEFAULT '',
    outcome                 LowCardinality(String) DEFAULT '',
    build_id                String DEFAULT '',
    dest_ip                 String DEFAULT '',
    dest_port               UInt16 DEFAULT 0,
    protocol                LowCardinality(String) DEFAULT '',
    triggered_by            LowCardinality(String) DEFAULT '',
    http_method             LowCardinality(String) DEFAULT '',
    url_path                String DEFAULT '' CODEC(ZSTD(3)),
    http_status             UInt16 DEFAULT 0,
    user_agent              LowCardinality(String) DEFAULT '',
    bytes_sent              UInt64 DEFAULT 0,
    response_time_ms        UInt32 DEFAULT 0,
    process_name            LowCardinality(String) DEFAULT '',
    process_id              UInt32 DEFAULT 0,
    parent_process          LowCardinality(String) DEFAULT '',
    -- -1 = unknown. 0 is root, so it cannot double as "not reported".
    process_uid             Int32 DEFAULT -1,
    step                    LowCardinality(String) DEFAULT '',
    file_path               String DEFAULT '',
    duration_ms             UInt32 DEFAULT 0,
    peak_memory_mb          UInt32 DEFAULT 0,
    cache_status            LowCardinality(String) DEFAULT '',
    error_message           String DEFAULT '' CODEC(ZSTD(3)),
    -- ---- indicators -- why an event looks wrong, one column each --------
    failure_signature       LowCardinality(String) DEFAULT '',
    is_failure_signature    UInt8 DEFAULT 0,
    is_untrusted_fetch      UInt8 DEFAULT 0,
    is_rogue_command        UInt8 DEFAULT 0,
    is_privileged           UInt8 DEFAULT 0,
    is_slow_step            UInt8 DEFAULT 0,
    is_cache_miss           UInt8 DEFAULT 0,
    -- ---- more rolling features -------------------------------------------
    rogue_commands_5m       UInt32 DEFAULT 0,
    failure_signatures_5m   UInt32 DEFAULT 0,
    http_errors_5m          UInt32 DEFAULT 0,
    dependency_404_1m       UInt32 DEFAULT 0,
    distinct_artifacts_5m   UInt32 DEFAULT 0,
    published_bytes_5m      UInt64 DEFAULT 0,
    slow_steps_5m           UInt32 DEFAULT 0,
    cache_misses_5m         UInt32 DEFAULT 0,

    -- ---- lineage ---------------------------------------------------------
    ingested_at             DateTime64(3, 'UTC') DEFAULT now64(3) CODEC(Delta, ZSTD(1)),
    -- One event by id (alert drill-down): skip every granule whose bloom
    -- filter says the id is not there.
    INDEX idx_event_id event_id TYPE bloom_filter(0.001) GRANULARITY 1,
    -- "What arrived in the last N seconds" (latency checks, smoke tests):
    -- ingested_at tracks the sort order closely, so min/max per granule
    -- skips all but the newest.
    INDEX idx_ingested_at ingested_at TYPE minmax GRANULARITY 1,
    -- Time ranges. The key leads with a 10-minute BUCKET, and ClickHouse
    -- (25.8) does not derive a bucket condition from `timestamp > x` on a
    -- DateTime64 -- without this index a "last 10 minutes" query read
    -- the whole day. Each granule sits inside one bucket, so min/max is tight.
    INDEX idx_timestamp timestamp TYPE minmax GRANULARITY 1
)
ENGINE = ReplacingMergeTree
PARTITION BY toDate(timestamp)
-- WHY THIS KEY (measured on 43M events, tools/bench_queries.py):
--   The old key, (timestamp, runner_ip, event_id), led with a near-unique
--   millisecond timestamp, so the columns after it never narrowed a read:
--   "this runner" and "this event_id" scanned the whole table (1 GB, 43M rows).
--   Bucketing time into 10 minutes first keeps time-range pruning, and
--   inside each bucket one runner's events sit together:
--     one runner, whole history   43M rows / 1 GB  ->  1M rows / 5 MB
--     one runner, +-15 min         2M rows / 101 MB -> 68K rows / 1 MB
--     event by id (bloom)         43M rows / 683 MB -> 65K rows / 3 MB
--   ReplacingMergeTree deduplicates on this key; a redelivered event has
--   the same bucket, runner_ip, timestamp and event_id, so it still collapses.
ORDER BY (toStartOfTenMinutes(timestamp), runner_ip, timestamp, event_id)
TTL toDateTime(timestamp) + INTERVAL 30 DAY
SETTINGS index_granularity = 8192;

-- Flagged events only: small, and what a dashboard hits most often.
-- `recommended_action` is the work queue: action = 'quarantine' is a runner
-- to pull out of the farm, with rule_hits and the command or error saying why.
CREATE TABLE IF NOT EXISTS watchtower.suspicious_events
(
    event_id                UUID,
    timestamp               DateTime64(3, 'UTC'),
    runner_ip               String,
    project                 LowCardinality(String),
    event_type              LowCardinality(String),
    hostname                LowCardinality(String),
    recommended_action      LowCardinality(String),
    rule_hits               String,
    rule_score              Float32,
    ml_score                Float32,
    ml_reason               String,
    final_anomaly_score     Float32,
    url_path                String,
    error_message           String,
    command                 String,
    process_uid             Int32
)
ENGINE = MergeTree
PARTITION BY toDate(timestamp)
ORDER BY (timestamp, final_anomaly_score)
TTL toDateTime(timestamp) + INTERVAL 90 DAY;

-- The materialized view feeding this table is created in 02_views.sql.

-- Rows clean.py refused, kept with the original bytes so a dropped log is
-- auditable rather than invisible. A rising count here is a health signal.
--
-- raw_value is BASE64 of the original Kafka message: messages are Avro
-- binary now, and base64 keeps them lossless in a String column.
--     SELECT reject_reason, base64Decode(raw_value) FROM rejected_events
-- schema_id is the registry id from the message header -- NULL when the
-- message had no header at all (reject_reason = 'not_avro_framed').
CREATE TABLE IF NOT EXISTS watchtower.rejected_events
(
    reject_reason    LowCardinality(String),
    schema_id        Nullable(Int64),
    raw_value        String,
    kafka_topic      LowCardinality(String),
    kafka_partition  Int32,
    kafka_offset     Int64,
    kafka_timestamp  DateTime64(3, 'UTC'),
    rejected_at      DateTime64(3, 'UTC') DEFAULT now64(3)
)
ENGINE = MergeTree
PARTITION BY toDate(rejected_at)
ORDER BY (rejected_at, reject_reason)
TTL toDateTime(rejected_at) + INTERVAL 30 DAY;
