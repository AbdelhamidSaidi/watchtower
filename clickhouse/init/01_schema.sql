-- Watchtower analytical storage.
-- Runs once, on first initialisation of an empty clickhouse-data volume.

CREATE DATABASE IF NOT EXISTS watchtower;

-- Final sink for the ETL pipeline: raw event fields + enrichment +
-- engineered features + per-model scores, one row per security event.
CREATE TABLE IF NOT EXISTS watchtower.security_events
(
    -- ---- raw event (producer schema) ----------------------------------
    event_id                UUID,
    timestamp               DateTime64(3, 'UTC') CODEC(Delta, ZSTD(1)),
    source_ip               LowCardinality(String),
    user                    LowCardinality(String),
    event_type              LowCardinality(String),
    hostname                LowCardinality(String),
    severity                LowCardinality(String),

    -- conditional fields, empty/0 when not applicable to the event_type
    reason                  LowCardinality(String) DEFAULT '',
    command                 String                 DEFAULT '' CODEC(ZSTD(3)),
    target_port             UInt16                 DEFAULT 0,

    -- ---- enrichment ---------------------------------------------------
    is_internal_ip          UInt8   DEFAULT 0,
    country_code            LowCardinality(String) DEFAULT '',

    -- ---- engineered features -------------------------------------------
    failed_logins_1m        UInt32  DEFAULT 0,
    failed_logins_5m        UInt32  DEFAULT 0,
    unique_source_ips_5m    UInt32  DEFAULT 0,
    unique_users_5m         UInt32  DEFAULT 0,
    requests_1m             UInt32  DEFAULT 0,
    port_scan_count_5m      UInt32  DEFAULT 0,
    unique_ports_5m         UInt32  DEFAULT 0,
    commands_executed_5m    UInt32  DEFAULT 0,
    login_frequency         Float32 DEFAULT 0,
    hour                    UInt8   DEFAULT 0,
    is_night                UInt8   DEFAULT 0,

    -- ---- detection ------------------------------------------------------
    -- Rules settle what is unambiguous; a LightGBM model (etl/core/ml.py),
    -- scored on the same features in the same pass, judges the rest.
    -- ml_reason names the features that drove a model score that mattered,
    -- so an alert can be explained without re-running anything; ml_model
    -- is the model version (watchtower.ml_models).
    -- final_anomaly_score = max(rule_score, ml_score), the model's share
    -- capped below `block` unless a rule agrees (WATCHTOWER_ML_CAN_BLOCK).
    rule_score              Float32 DEFAULT 0,
    rule_hits               LowCardinality(String) DEFAULT '',
    recommended_action      LowCardinality(String) DEFAULT 'allow',
    ml_score                Float32 DEFAULT 0,
    ml_reason               String  DEFAULT '',
    ml_model                LowCardinality(String) DEFAULT '',
    final_anomaly_score     Float32 DEFAULT 0,
    is_suspicious           UInt8   DEFAULT 0,

    -- ---- v2: request / network / process / file context --------------
    log_source              LowCardinality(String) DEFAULT '',
    outcome                 LowCardinality(String) DEFAULT '',
    session_id              String DEFAULT '',
    dest_ip                 String DEFAULT '',
    dest_port               UInt16 DEFAULT 0,
    protocol                LowCardinality(String) DEFAULT '',
    auth_method             LowCardinality(String) DEFAULT '',
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
    file_path               String DEFAULT '',
    file_operation          LowCardinality(String) DEFAULT '',
    -- ---- v2: indicators -- why an event looks bad, one column each -----
    request_signature       LowCardinality(String) DEFAULT '',
    is_attack_signature     UInt8 DEFAULT 0,
    is_scanner_agent        UInt8 DEFAULT 0,
    is_sensitive_path       UInt8 DEFAULT 0,
    is_sensitive_command    UInt8 DEFAULT 0,
    is_privileged           UInt8 DEFAULT 0,
    -- ---- v2: rolling features ------------------------------------------
    sensitive_commands_5m   UInt32 DEFAULT 0,
    attack_signatures_5m    UInt32 DEFAULT 0,
    http_errors_5m          UInt32 DEFAULT 0,
    http_404_1m             UInt32 DEFAULT 0,
    distinct_paths_5m       UInt32 DEFAULT 0,
    bytes_sent_5m           UInt64 DEFAULT 0,

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
--   The old key, (timestamp, source_ip, event_id), led with a near-unique
--   millisecond timestamp, so the columns after it never narrowed a read:
--   "this IP" and "this event_id" scanned the whole table (1 GB, 43M rows).
--   Bucketing time into 10 minutes first keeps time-range pruning, and
--   inside each bucket one IP's events sit together:
--     one IP, whole history   43M rows / 1 GB  ->  1M rows / 5 MB
--     one IP, +-15 min         2M rows / 101 MB -> 68K rows / 1 MB
--     event by id (bloom)     43M rows / 683 MB -> 65K rows / 3 MB
--   ReplacingMergeTree deduplicates on this key; a redelivered event has
--   the same bucket, source_ip, timestamp and event_id, so it still collapses.
ORDER BY (toStartOfTenMinutes(timestamp), source_ip, timestamp, event_id)
TTL toDateTime(timestamp) + INTERVAL 30 DAY
SETTINGS index_granularity = 8192;

-- Suspicious events only: small, and what a dashboard hits most often.
-- `recommended_action` is the work queue: action = 'block' is what must be
-- stopped, with rule_hits and the request/command saying why.
CREATE TABLE IF NOT EXISTS watchtower.suspicious_events
(
    event_id                UUID,
    timestamp               DateTime64(3, 'UTC'),
    source_ip               String,
    user                    LowCardinality(String),
    event_type              LowCardinality(String),
    hostname                LowCardinality(String),
    recommended_action      LowCardinality(String),
    rule_hits               String,
    rule_score              Float32,
    ml_score                Float32,
    ml_reason               String,
    final_anomaly_score     Float32,
    url_path                String,
    user_agent              String,
    command                 String,
    process_uid             Int32
)
ENGINE = MergeTree
PARTITION BY toDate(timestamp)
ORDER BY (timestamp, final_anomaly_score)
TTL toDateTime(timestamp) + INTERVAL 90 DAY;

-- The materialized view feeding this table is created in
-- 02_v2_request_context.sql, AFTER that file adds the v2 columns. It cannot
-- live here: ClickHouse analyses a view's SELECT even under IF NOT EXISTS,
-- so on a volume created before v2 the statement fails on columns the
-- table does not have yet.

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
