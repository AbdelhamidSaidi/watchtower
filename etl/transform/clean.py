"""
Transform stage 2: validate, and turn `timestamp` into a real timestamp.

Nothing is silently discarded here. Every row gets a `reject_reason`
column -- null means the row is good -- and the pipeline splits on it:

        clean.validate(df)
              |
     +--------+--------+
     |                 |
  valid(df)       rejected(df)
     |                 |
     v                 v
  normalize      dead-letter sink

A dropped security log is a blind spot, so a rejected row keeps its
raw bytes (base64) and its Kafka coordinates and stays auditable.

This is also where `timestamp` stops being a string. Every watermark,
window and dedup downstream depends on that cast having happened.
"""

from pyspark.sql import functions as F
from pyspark.sql.types import TimestampType


from core.vocab import KNOWN_EVENT_TYPES, MAX_PORT, UUID_REGEX  # noqa: F401  (re-exported)


def validate(df):
    """Cast the timestamp and attach a reject_reason to every row.

    Order matters: the first matching condition wins, so a row that fails
    to parse at all is reported as unparseable rather than as a row with a
    missing event_id.
    """
    # Cast first so the null check below can see whether it worked.
    #
    # No explicit format string on purpose. The producer uses
    # datetime.isoformat(), which omits the fractional part when
    # microseconds happen to be exactly 0 -- a strict
    # "yyyy-MM-dd'T'HH:mm:ss.SSSSSSXXX" would reject those rare events.
    # Spark's default ISO-8601 parser handles both shapes.
    cast = df.withColumn(
        "timestamp",
        F.col("timestamp").cast(TimestampType()),
    )

    # parse.py already knows why a message would not decode. That reason
    # wins over anything below: a row with no fields is missing everything,
    # and "missing_event_id" would hide the real cause.
    reason = (
        F.when(F.col("wire_error").isNotNull(), F.col("wire_error"))
        .when(
            F.col("event_id").isNull() | (F.trim(F.col("event_id")) == ""),
            F.lit("missing_event_id"),
        )
        .when(~F.trim(F.col("event_id")).rlike(UUID_REGEX), F.lit("invalid_event_id"))
        .when(F.col("timestamp").isNull(), F.lit("invalid_timestamp"))
        .when(
            F.col("event_type").isNull() | (F.trim(F.col("event_type")) == ""),
            F.lit("missing_event_type"),
        )
        .when(
            ~F.upper(F.trim(F.col("event_type"))).isin(KNOWN_EVENT_TYPES),
            F.lit("unknown_event_type"),
        )
        .when(
            F.col("source_ip").isNull() | (F.trim(F.col("source_ip")) == ""),
            F.lit("missing_source_ip"),
        )
        .when(
            F.col("target_port").isNotNull()
            & ((F.col("target_port") < 0) | (F.col("target_port") > MAX_PORT)),
            F.lit("port_out_of_range"),
        )
        .when(
            F.col("dest_port").isNotNull()
            & ((F.col("dest_port") < 0) | (F.col("dest_port") > MAX_PORT)),
            F.lit("port_out_of_range"),
        )
        .when(
            F.col("http_status").isNotNull()
            & ((F.col("http_status") < 100) | (F.col("http_status") > 599)),
            F.lit("invalid_http_status"),
        )
        .otherwise(F.lit(None).cast("string"))
    )

    return cast.withColumn("reject_reason", reason)


def valid(df):
    """Rows that passed validation. Feed this to normalize.

    raw_value is dropped here: it roughly doubles the row size and every
    stage after this one crosses a shuffle. A good row can still be traced
    back to its original bytes via kafka_offset. Rejected rows keep it.
    """
    return df.filter(F.col("reject_reason").isNull()).drop(
        "reject_reason", "wire_error", "schema_id", "raw_value"
    )


def rejected(df):
    """Rows that failed, trimmed to what the dead-letter sink needs."""
    return df.filter(F.col("reject_reason").isNotNull()).select(
        "reject_reason",
        # Garbage when the message was not framed at all -- read it together
        # with reject_reason.
        F.when(F.col("wire_error") == "not_avro_framed", F.lit(None))
        .otherwise(F.col("schema_id"))
        .alias("schema_id"),
        "raw_value",
        "kafka_topic",
        "kafka_partition",
        "kafka_offset",
        "kafka_timestamp",
    )


def clean(df):
    """Convenience: validate then keep only the good rows."""
    return valid(validate(df))
