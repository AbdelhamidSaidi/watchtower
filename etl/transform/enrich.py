"""
Transform stage 5: add context the raw log never carried.

Two very different costs live here, and it is worth keeping them apart:

  cheap_enrich()   pure column expressions. narrow, stateless, no shuffle.
                   fuses into the same pass as parse/clean/normalize, so it
                   is effectively free -- run it BEFORE deduplicate.

  join_enrich()    lookups against reference data. broadcast the small side
                   and it stays narrow; let Spark shuffle it and you have
                   paid for a whole extra stage.

Never use a stream-stream join here. The reference data is finite, so the
static side belongs in a broadcast, not in a second state store.
"""

from pyspark.sql import functions as F


from core.indicators import (  # noqa: F401  (re-exported for tests)
    GEOIP_PREFIXES,
    NIGHT_END_HOUR,
    NIGHT_START_HOUR,
    PRIVATE_IP_REGEX,
    SCANNER_AGENT_REGEX,
    SENSITIVE_COMMAND_REGEX,
    SENSITIVE_FILE_REGEX,
    SENSITIVE_PATH_REGEX,
    SQLI_REGEX,
    TRAVERSAL_REGEX,
    XSS_REGEX,
)


def _flag(condition):
    return F.when(condition, F.lit(1)).otherwise(F.lit(0))


def cheap_enrich(df):
    """Column math only. Safe and near-free to run before deduplicate."""
    hour = F.hour(F.col("timestamp"))
    url = F.col("url_path")

    # One label, not three flags: an analyst filters on WHICH payload.
    signature = (
        F.when(url.rlike(SQLI_REGEX), F.lit("sqli"))
        .when(url.rlike(TRAVERSAL_REGEX), F.lit("path_traversal"))
        .when(url.rlike(XSS_REGEX), F.lit("xss"))
        .otherwise(F.lit(""))
    )

    return (
        df.withColumn("request_signature", signature)
        .withColumn("is_attack_signature", _flag(signature != ""))
        .withColumn("is_scanner_agent", _flag(F.col("user_agent").rlike(SCANNER_AGENT_REGEX)))
        .withColumn("is_sensitive_path", _flag(url.rlike(SENSITIVE_PATH_REGEX)))
        .withColumn(
            "is_sensitive_command",
            _flag(
                F.col("command").rlike(SENSITIVE_COMMAND_REGEX)
                | F.col("file_path").rlike(SENSITIVE_FILE_REGEX)
            ),
        )
        # root. Only a KNOWN uid of 0 -- normalize maps unknown to -1.
        .withColumn("is_privileged", _flag(F.col("process_uid") == 0))
        .withColumn(
            "is_internal_ip",
            F.when(F.col("source_ip").rlike(PRIVATE_IP_REGEX), F.lit(1)).otherwise(
                F.lit(0)
            ),
        )
        .withColumn("hour", hour)
        .withColumn(
            "is_night",
            F.when(
                (hour >= NIGHT_START_HOUR) | (hour < NIGHT_END_HOUR), F.lit(1)
            ).otherwise(F.lit(0)),
        )
    )


def build_geoip_lookup(spark):
    """The static side of the join. Replace with a real GeoIP source."""
    return spark.createDataFrame(GEOIP_PREFIXES, ["geo_prefix", "country_code"])


def join_enrich(df, lookup_df):
    """Stream-static broadcast join.

    F.broadcast() is not optional here. Without it Spark may shuffle the
    stream to join it, adding a stage boundary for a lookup table small
    enough to fit in every executor's memory many times over.

    Left join, so an IP missing from the lookup keeps its event rather than
    dropping it -- an unknown IP is exactly the kind of thing worth keeping.
    """
    # Join key is the first two octets. Computed once here rather than
    # inside the join condition so Spark can hash it.
    with_prefix = df.withColumn(
        "geo_prefix",
        F.concat_ws(
            ".",
            F.split(F.col("source_ip"), r"\.").getItem(0),
            F.split(F.col("source_ip"), r"\.").getItem(1),
        ),
    )

    joined = with_prefix.join(F.broadcast(lookup_df), on="geo_prefix", how="left")

    return joined.drop("geo_prefix").withColumn(
        "country_code", F.coalesce(F.col("country_code"), F.lit(""))
    )


def enrich(df, lookup_df=None):
    """Both halves. Pass lookup_df=None to skip the join entirely."""
    out = cheap_enrich(df)

    if lookup_df is not None:
        out = join_enrich(out, lookup_df)
    else:
        out = out.withColumn("country_code", F.lit(""))

    return out
