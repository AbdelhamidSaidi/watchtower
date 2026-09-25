"""
Transform stage 3: one canonical spelling per value.

Runs AFTER clean (don't canonicalise garbage) and BEFORE deduplicate and
features, because both of those key on these values:

    "John " and "john" hash to different dedup keys
    "John " and "john" land in different failed_logins_5m counters

so an attacker whose username arrives inconsistently cased would be split
across several counters and never cross a threshold.

This stage also coalesces nulls to the defaults the ClickHouse schema
declares (DEFAULT '' / DEFAULT 0), so the sink never has to.
"""

from pyspark.sql import functions as F


from core.vocab import DEFAULT_SEVERITY, KNOWN_SEVERITIES, UNKNOWN_UID  # noqa: F401


def _lower(name):
    return F.lower(F.trim(F.coalesce(F.col(name), F.lit(""))))


def _text(name):
    return F.trim(F.coalesce(F.col(name), F.lit("")))


def normalize(df):
    """Standardise field formats. One row in, one row out, nothing dropped."""
    severity = F.upper(F.trim(F.coalesce(F.col("severity"), F.lit(""))))

    return (
        df
        # identifiers and free text: case is not meaningful
        .withColumn("user", F.lower(F.trim(F.coalesce(F.col("user"), F.lit("")))))
        .withColumn("hostname", F.lower(F.trim(F.coalesce(F.col("hostname"), F.lit("")))))
        # enums: upper-case, and closed
        .withColumn("event_type", F.upper(F.trim(F.col("event_type"))))
        .withColumn(
            "severity",
            F.when(severity.isin(KNOWN_SEVERITIES), severity).otherwise(
                F.lit(DEFAULT_SEVERITY)
            ),
        )
        # IPs: whitespace only. no case folding, no zero-padding -- changing
        # an IP's text would break the joins enrich does against it.
        .withColumn("source_ip", F.trim(F.col("source_ip")))
        # conditional fields -> the ClickHouse defaults, so the sink can
        # insert into non-nullable columns
        .withColumn("reason", F.lower(F.trim(F.coalesce(F.col("reason"), F.lit("")))))
        .withColumn("command", F.trim(F.coalesce(F.col("command"), F.lit(""))))
        .withColumn("target_port", F.coalesce(F.col("target_port"), F.lit(0)))
        # --- v2 context -----------------------------------------------------
        # closed vocabularies: lower-case
        .withColumn("log_source", _lower("log_source"))
        .withColumn("outcome", _lower("outcome"))
        .withColumn("protocol", _lower("protocol"))
        .withColumn("auth_method", _lower("auth_method"))
        .withColumn("file_operation", _lower("file_operation"))
        .withColumn("process_name", _lower("process_name"))
        .withColumn("parent_process", _lower("parent_process"))
        .withColumn("http_method", F.upper(F.trim(F.coalesce(F.col("http_method"), F.lit("")))))
        # free text: trimmed only. Paths and file names are CASE-SENSITIVE
        # (/Admin and /admin are different resources), and URL encoding is
        # left alone -- %2e%2e is evidence, decoding it would erase it.
        .withColumn("url_path", _text("url_path"))
        .withColumn("user_agent", _text("user_agent"))
        .withColumn("file_path", _text("file_path"))
        .withColumn("session_id", _text("session_id"))
        .withColumn("dest_ip", _text("dest_ip"))
        # numbers: 0 means "not applicable"
        .withColumn("dest_port", F.coalesce(F.col("dest_port"), F.lit(0)))
        .withColumn("http_status", F.coalesce(F.col("http_status"), F.lit(0)))
        .withColumn("bytes_sent", F.coalesce(F.col("bytes_sent"), F.lit(0).cast("long")))
        .withColumn("response_time_ms", F.coalesce(F.col("response_time_ms"), F.lit(0)))
        .withColumn("process_id", F.coalesce(F.col("process_id"), F.lit(0)))
        # ...EXCEPT the uid. 0 is root. Coalescing an unknown uid to 0 would
        # stamp every event from a source that does not report one as root.
        .withColumn("process_uid", F.coalesce(F.col("process_uid"), F.lit(UNKNOWN_UID)))
    )
