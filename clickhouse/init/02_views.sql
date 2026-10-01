-- Views over security_events. Idempotent: safe to run again
-- (`make ch-migrate`).
--
-- A materialized view's SELECT cannot be altered in place: recreate it.

DROP VIEW IF EXISTS watchtower.mv_suspicious_events;
CREATE MATERIALIZED VIEW IF NOT EXISTS watchtower.mv_suspicious_events
TO watchtower.suspicious_events
AS
SELECT
    event_id, timestamp, runner_ip, project, event_type, hostname,
    recommended_action, rule_hits, rule_score, ml_score, ml_reason,
    final_anomaly_score, url_path, error_message, command, process_uid
FROM watchtower.security_events
WHERE is_suspicious = 1;
