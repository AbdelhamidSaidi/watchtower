-- The streaming path's way into ClickHouse (etl/stream/job.py).
--
-- Kafka-engine SETTINGS cannot be ALTERed: to apply a change here to an
-- existing install, `make ch-recreate-ingest` drops and recreates the
-- queue tables and their views (the consumer groups keep their offsets in
-- Kafka, so nothing is skipped or re-read).
--
--   Flink -> Kafka security-events-scored -> [Kafka engine] -> MV -> security_events
--   Flink -> Kafka security-logs-rejected -> [Kafka engine] -> MV -> rejected_events
--
-- ClickHouse wants inserts in blocks, not one row at a time. The Kafka
-- engine consumes continuously and inserts a block every
-- kafka_flush_interval_ms -- the only batching left between an event and
-- its row (50 ms for events). It commits Kafka offsets only
-- after the insert succeeded (at-least-once; ReplacingMergeTree absorbs
-- repeats).
--
-- A row that does not parse is not dropped and does not stall the consumer
-- (kafka_handle_error_mode = 'stream'): it goes to rejected_events with
-- reject_reason = 'sink_parse_error' and its raw text.
--
-- The broker list is the {kafka_brokers} macro, set per environment in
-- the server config (clickhouse/config/streaming.xml, from the
-- WATCHTOWER_KAFKA_BROKERS env var) -- the SQL is the same everywhere.
--
-- Idempotent: safe to re-run (make ch-migrate).

CREATE TABLE IF NOT EXISTS watchtower.security_events_queue
(
    event_id               UUID,
    timestamp              DateTime64(3, 'UTC'),
    runner_ip              String,
    project                LowCardinality(String),
    event_type             LowCardinality(String),
    hostname               LowCardinality(String),
    severity               LowCardinality(String),
    reason                 LowCardinality(String),
    command                String,
    exit_code              UInt16,
    is_internal_ip         UInt8,
    region                 LowCardinality(String),
    hour                   UInt8,
    is_night               UInt8,
    events_1m              UInt32,
    failed_builds_1m       UInt32,
    failed_builds_5m       UInt32,
    unique_projects_5m     UInt32,
    oom_kills_5m           UInt32,
    distinct_exit_codes_5m UInt32,
    compile_steps_5m       UInt32,
    build_frequency        Float32,
    log_source             LowCardinality(String),
    outcome                LowCardinality(String),
    build_id               String,
    dest_ip                String,
    dest_port              UInt16,
    protocol               LowCardinality(String),
    triggered_by           LowCardinality(String),
    http_method            LowCardinality(String),
    url_path               String,
    http_status            UInt16,
    user_agent             String,
    bytes_sent             UInt64,
    response_time_ms       UInt32,
    process_name           LowCardinality(String),
    process_id             UInt32,
    parent_process         LowCardinality(String),
    process_uid            Int32,
    step                   LowCardinality(String),
    file_path              String,
    duration_ms            UInt32,
    peak_memory_mb         UInt32,
    cache_status           LowCardinality(String),
    error_message          String,
    failure_signature      LowCardinality(String),
    is_failure_signature   UInt8,
    is_untrusted_fetch     UInt8,
    is_rogue_command       UInt8,
    is_privileged          UInt8,
    is_slow_step           UInt8,
    is_cache_miss          UInt8,
    rogue_commands_5m      UInt32,
    failure_signatures_5m  UInt32,
    http_errors_5m         UInt32,
    dependency_404_1m      UInt32,
    distinct_artifacts_5m  UInt32,
    published_bytes_5m     UInt64,
    slow_steps_5m          UInt32,
    cache_misses_5m        UInt32,
    rule_score             Float32,
    rule_hits              String,
    ml_score               Float32,
    ml_reason              String,
    ml_model               LowCardinality(String),
    final_anomaly_score    Float32,
    is_suspicious          UInt8,
    recommended_action     LowCardinality(String)
)
ENGINE = Kafka
SETTINGS
    kafka_broker_list = '{kafka_brokers}',
    kafka_topic_list = 'security-events-scored',
    kafka_group_name = 'clickhouse-security-events',
    kafka_format = 'JSONEachRow',
    kafka_num_consumers = 1,
    -- A block every 50 ms, polls that return after 10 ms: the two waits
    -- that made up most of the end-to-end latency (at 250/100 ms the
    -- median was ~200 ms, with detection itself at ~5 ms). ~20 small
    -- inserts/s; they land as compact parts and merge cheaply.
    kafka_flush_interval_ms = 50,
    kafka_poll_timeout_ms = 10,
    kafka_handle_error_mode = 'stream';

CREATE MATERIALIZED VIEW IF NOT EXISTS watchtower.security_events_from_queue
TO watchtower.security_events
AS SELECT * FROM watchtower.security_events_queue
WHERE length(_error) = 0;

CREATE TABLE IF NOT EXISTS watchtower.rejected_events_queue
(
    reject_reason    String,
    schema_id        Nullable(Int64),
    raw_value        String,
    kafka_topic      String,
    kafka_partition  Int32,
    kafka_offset     Int64,
    kafka_timestamp  DateTime64(3, 'UTC')
)
ENGINE = Kafka
SETTINGS
    kafka_broker_list = '{kafka_brokers}',
    kafka_topic_list = 'security-logs-rejected',
    kafka_group_name = 'clickhouse-rejected-events',
    kafka_format = 'JSONEachRow',
    kafka_num_consumers = 1,
    kafka_flush_interval_ms = 250,
    kafka_poll_timeout_ms = 100,
    kafka_handle_error_mode = 'stream';

CREATE MATERIALIZED VIEW IF NOT EXISTS watchtower.rejected_events_from_queue
TO watchtower.rejected_events
AS SELECT * FROM watchtower.rejected_events_queue
WHERE length(_error) = 0;

-- Rows either queue could not parse: kept, with the text that failed.
CREATE MATERIALIZED VIEW IF NOT EXISTS watchtower.sink_errors_from_events_queue
TO watchtower.rejected_events
AS SELECT
    'sink_parse_error'                   AS reject_reason,
    CAST(NULL AS Nullable(Int64))        AS schema_id,
    base64Encode(_raw_message)           AS raw_value,
    _topic                               AS kafka_topic,
    toInt32(_partition)                  AS kafka_partition,
    toInt64(_offset)                     AS kafka_offset,
    coalesce(_timestamp_ms, now64(3))    AS kafka_timestamp
FROM watchtower.security_events_queue
WHERE length(_error) > 0;

CREATE MATERIALIZED VIEW IF NOT EXISTS watchtower.sink_errors_from_rejected_queue
TO watchtower.rejected_events
AS SELECT
    'sink_parse_error'                   AS reject_reason,
    CAST(NULL AS Nullable(Int64))        AS schema_id,
    base64Encode(_raw_message)           AS raw_value,
    _topic                               AS kafka_topic,
    toInt32(_partition)                  AS kafka_partition,
    toInt64(_offset)                     AS kafka_offset,
    coalesce(_timestamp_ms, now64(3))    AS kafka_timestamp
FROM watchtower.rejected_events_queue
WHERE length(_error) > 0;
