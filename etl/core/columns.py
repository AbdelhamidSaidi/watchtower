"""The ClickHouse row contract, shared by both writers.

Explicit column lists rather than "whatever the frame has": a column added
upstream then fails loudly instead of silently not being stored. Columns
left out (ingested_at, rejected_at) take their ClickHouse DEFAULT -- which
is what makes end-to-end latency measurable: ingested_at - timestamp.
"""

EVENT_COLUMNS = [
    "event_id",
    "timestamp",
    "source_ip",
    "user",
    "event_type",
    "hostname",
    "severity",
    "reason",
    "command",
    "target_port",
    "is_internal_ip",
    "country_code",
    "hour",
    "is_night",
    "requests_1m",
    "failed_logins_1m",
    "failed_logins_5m",
    "unique_source_ips_5m",
    "unique_users_5m",
    "port_scan_count_5m",
    "unique_ports_5m",
    "commands_executed_5m",
    "login_frequency",
    # --- v2: request / network / process / file context -------------------
    "log_source",
    "outcome",
    "session_id",
    "dest_ip",
    "dest_port",
    "protocol",
    "auth_method",
    "http_method",
    "url_path",
    "http_status",
    "user_agent",
    "bytes_sent",
    "response_time_ms",
    "process_name",
    "process_id",
    "parent_process",
    "process_uid",
    "file_path",
    "file_operation",
    # --- v2: indicators (enrich) ------------------------------------------
    "request_signature",
    "is_attack_signature",
    "is_scanner_agent",
    "is_sensitive_path",
    "is_sensitive_command",
    "is_privileged",
    # --- v2: rolling features ---------------------------------------------
    "sensitive_commands_5m",
    "attack_signatures_5m",
    "http_errors_5m",
    "http_404_1m",
    "distinct_paths_5m",
    "bytes_sent_5m",
]

# Added by scoring (core/rules.py).
SCORE_COLUMNS = [
    "rule_score",
    "rule_hits",
    "ml_score",
    "ml_reason",
    "ml_model",
    "final_anomaly_score",
    "is_suspicious",
    "recommended_action",
]

REJECTED_COLUMNS = [
    "reject_reason",
    "schema_id",
    "raw_value",
    "kafka_topic",
    "kafka_partition",
    "kafka_offset",
    "kafka_timestamp",
]
