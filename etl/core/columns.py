"""The ClickHouse row contract, shared by both writers.

Explicit column lists rather than "whatever the frame has": a column added
upstream then fails loudly instead of silently not being stored. Columns
left out (ingested_at, rejected_at) take their ClickHouse DEFAULT -- which
is what makes end-to-end latency measurable: ingested_at - timestamp.
"""

EVENT_COLUMNS = [
    "event_id",
    "timestamp",
    "runner_ip",
    "project",
    "event_type",
    "hostname",
    "severity",
    "reason",
    "command",
    "exit_code",
    "is_internal_ip",
    "region",
    "hour",
    "is_night",
    "events_1m",
    "failed_builds_1m",
    "failed_builds_5m",
    "unique_projects_5m",
    "oom_kills_5m",
    "distinct_exit_codes_5m",
    "compile_steps_5m",
    "build_frequency",
    # --- context: build, registry, process, step --------------------------
    "log_source",
    "outcome",
    "build_id",
    "dest_ip",
    "dest_port",
    "protocol",
    "triggered_by",
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
    "step",
    "file_path",
    "duration_ms",
    "peak_memory_mb",
    "cache_status",
    "error_message",
    # --- indicators (enrich) ----------------------------------------------
    "failure_signature",
    "is_failure_signature",
    "is_untrusted_fetch",
    "is_rogue_command",
    "is_privileged",
    "is_slow_step",
    "is_cache_miss",
    # --- rolling features -------------------------------------------------
    "rogue_commands_5m",
    "failure_signatures_5m",
    "http_errors_5m",
    "dependency_404_1m",
    "distinct_artifacts_5m",
    "published_bytes_5m",
    "slow_steps_5m",
    "cache_misses_5m",
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
