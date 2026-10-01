-- v2 migration: request, network, process and file context, plus the
-- rule-based decision columns.
--
-- IDEMPOTENT: every statement is safe to run again. On a fresh volume 01
-- already created all of this and these are no-ops; on a volume created
-- before v2 they add what is missing. Applied by the ClickHouse entrypoint
-- on first init, and by `make ch-migrate` against a running server.

ALTER TABLE watchtower.security_events ADD COLUMN IF NOT EXISTS rule_score Float32 DEFAULT 0;
ALTER TABLE watchtower.security_events ADD COLUMN IF NOT EXISTS rule_hits String DEFAULT '';
ALTER TABLE watchtower.security_events ADD COLUMN IF NOT EXISTS recommended_action LowCardinality(String) DEFAULT 'allow';
ALTER TABLE watchtower.security_events ADD COLUMN IF NOT EXISTS log_source LowCardinality(String) DEFAULT '';
ALTER TABLE watchtower.security_events ADD COLUMN IF NOT EXISTS outcome LowCardinality(String) DEFAULT '';
ALTER TABLE watchtower.security_events ADD COLUMN IF NOT EXISTS session_id String DEFAULT '';
ALTER TABLE watchtower.security_events ADD COLUMN IF NOT EXISTS dest_ip String DEFAULT '';
ALTER TABLE watchtower.security_events ADD COLUMN IF NOT EXISTS dest_port UInt16 DEFAULT 0;
ALTER TABLE watchtower.security_events ADD COLUMN IF NOT EXISTS protocol LowCardinality(String) DEFAULT '';
ALTER TABLE watchtower.security_events ADD COLUMN IF NOT EXISTS auth_method LowCardinality(String) DEFAULT '';
ALTER TABLE watchtower.security_events ADD COLUMN IF NOT EXISTS http_method LowCardinality(String) DEFAULT '';
ALTER TABLE watchtower.security_events ADD COLUMN IF NOT EXISTS url_path String DEFAULT '';
ALTER TABLE watchtower.security_events ADD COLUMN IF NOT EXISTS http_status UInt16 DEFAULT 0;
ALTER TABLE watchtower.security_events ADD COLUMN IF NOT EXISTS user_agent String DEFAULT '';
ALTER TABLE watchtower.security_events ADD COLUMN IF NOT EXISTS bytes_sent UInt64 DEFAULT 0;
ALTER TABLE watchtower.security_events ADD COLUMN IF NOT EXISTS response_time_ms UInt32 DEFAULT 0;
ALTER TABLE watchtower.security_events ADD COLUMN IF NOT EXISTS process_name LowCardinality(String) DEFAULT '';
ALTER TABLE watchtower.security_events ADD COLUMN IF NOT EXISTS process_id UInt32 DEFAULT 0;
ALTER TABLE watchtower.security_events ADD COLUMN IF NOT EXISTS parent_process LowCardinality(String) DEFAULT '';
ALTER TABLE watchtower.security_events ADD COLUMN IF NOT EXISTS process_uid Int32 DEFAULT -1;
ALTER TABLE watchtower.security_events ADD COLUMN IF NOT EXISTS file_path String DEFAULT '';
ALTER TABLE watchtower.security_events ADD COLUMN IF NOT EXISTS file_operation LowCardinality(String) DEFAULT '';
ALTER TABLE watchtower.security_events ADD COLUMN IF NOT EXISTS request_signature LowCardinality(String) DEFAULT '';
ALTER TABLE watchtower.security_events ADD COLUMN IF NOT EXISTS is_attack_signature UInt8 DEFAULT 0;
ALTER TABLE watchtower.security_events ADD COLUMN IF NOT EXISTS is_scanner_agent UInt8 DEFAULT 0;
ALTER TABLE watchtower.security_events ADD COLUMN IF NOT EXISTS is_sensitive_path UInt8 DEFAULT 0;
ALTER TABLE watchtower.security_events ADD COLUMN IF NOT EXISTS is_sensitive_command UInt8 DEFAULT 0;
ALTER TABLE watchtower.security_events ADD COLUMN IF NOT EXISTS is_privileged UInt8 DEFAULT 0;
ALTER TABLE watchtower.security_events ADD COLUMN IF NOT EXISTS sensitive_commands_5m UInt32 DEFAULT 0;
ALTER TABLE watchtower.security_events ADD COLUMN IF NOT EXISTS attack_signatures_5m UInt32 DEFAULT 0;
ALTER TABLE watchtower.security_events ADD COLUMN IF NOT EXISTS http_errors_5m UInt32 DEFAULT 0;
ALTER TABLE watchtower.security_events ADD COLUMN IF NOT EXISTS http_404_1m UInt32 DEFAULT 0;
ALTER TABLE watchtower.security_events ADD COLUMN IF NOT EXISTS distinct_paths_5m UInt32 DEFAULT 0;
ALTER TABLE watchtower.security_events ADD COLUMN IF NOT EXISTS bytes_sent_5m UInt64 DEFAULT 0;

ALTER TABLE watchtower.suspicious_events ADD COLUMN IF NOT EXISTS recommended_action LowCardinality(String);
ALTER TABLE watchtower.suspicious_events ADD COLUMN IF NOT EXISTS rule_hits String;
ALTER TABLE watchtower.suspicious_events ADD COLUMN IF NOT EXISTS rule_score Float32;
ALTER TABLE watchtower.suspicious_events ADD COLUMN IF NOT EXISTS url_path String;
ALTER TABLE watchtower.suspicious_events ADD COLUMN IF NOT EXISTS user_agent String;
ALTER TABLE watchtower.suspicious_events ADD COLUMN IF NOT EXISTS command String;
ALTER TABLE watchtower.suspicious_events ADD COLUMN IF NOT EXISTS process_uid Int32;

-- A materialized view's SELECT cannot be altered in place: recreate it.
DROP VIEW IF EXISTS watchtower.mv_suspicious_events;
CREATE MATERIALIZED VIEW IF NOT EXISTS watchtower.mv_suspicious_events
TO watchtower.suspicious_events
AS
SELECT
    event_id, timestamp, source_ip, user, event_type, hostname,
    recommended_action, rule_hits, rule_score, ml_score, ml_reason,
    final_anomaly_score, url_path, user_agent, command, process_uid
FROM watchtower.security_events
WHERE is_suspicious = 1;
