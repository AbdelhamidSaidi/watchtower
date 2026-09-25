"""
Transform stage 1: decode Confluent-framed Avro into typed columns.

    binary value
        |  bytes 0     magic byte    -> must be 0x00
        |  bytes 1-4   schema id     -> which registered version wrote this
        |  bytes 5..   Avro binary   -> decoded with THAT version
        v
    flat typed columns

MULTI-VERSION DECODING
----------------------
Avro binary is not self-describing: it can only be decoded with the exact
schema that wrote it. So `versions` carries EVERY registered version, and
each message is decoded with the one its header names. A producer that moves
to a new compatible version therefore keeps flowing, instead of having its
messages misread with the wrong schema or dropped.

A version registered AFTER the pipeline started is unknown to it until the
next restart; those messages are rejected with `unknown_schema_version`,
loudly, never misdecoded. Deploy order for a schema change is therefore:
register the schema, restart the pipeline, then roll out the producer.

NOTHING IS DROPPED HERE
-----------------------
A message that cannot be decoded comes out with null event fields and a
`wire_error` saying why. clean.py turns that into a reject_reason and routes
it to the dead-letter table with the original bytes (base64) attached.

    not_avro_framed          no 0x00 magic byte -- e.g. a JSON message
    unknown_schema_version   framed, but the id is not a known version
    undecodable_payload      right version, bytes do not decode
"""

import json

from pyspark.sql import functions as F
from pyspark.sql.avro.functions import from_avro
from pyspark.sql.types import IntegerType, LongType, StringType

from core.vocab import EVENT_FIELDS as VOCAB_FIELDS

# The fields this pipeline reads (core/vocab.py), as Spark types. A version
# that lacks one (because it was added later, or removed) yields null for it.
_SPARK_TYPES = {"string": StringType(), "int": IntegerType(), "long": LongType()}
EVENT_FIELDS = [(name, _SPARK_TYPES[kind]) for name, kind in VOCAB_FIELDS]

# PERMISSIVE: a malformed payload yields null instead of failing the query.
# The default, FAILFAST, would kill the entire stream on one bad message.
AVRO_OPTIONS = {"mode": "PERMISSIVE"}


def _field_names(schema_json):
    return {field["name"] for field in json.loads(schema_json)["fields"]}


def parse(df, versions):
    """Decode Kafka `value` into flat typed columns.

    versions: {schema_id: schema_json} -- every registered version. The
              pipeline fetches these from the registry at startup; tests
              pass the local .avsc directly.
    """
    if not versions:
        raise ValueError("parse() needs at least one schema version")

    framed = df.select(
        F.col("value").alias("_raw"),
        F.col("topic").alias("kafka_topic"),
        F.col("partition").alias("kafka_partition"),
        F.col("offset").alias("kafka_offset"),
        F.col("timestamp").alias("kafka_timestamp"),
    )

    length = F.length(F.col("_raw"))
    magic = F.conv(F.hex(F.substring(F.col("_raw"), 1, 1)), 16, 10).cast("int")
    schema_id = F.conv(F.hex(F.substring(F.col("_raw"), 2, 4)), 16, 10).cast("long")
    payload = F.expr("substring(_raw, 6, length(_raw) - 5)")

    is_framed = (length >= 5) & (magic == 0)

    # DECODE ONCE PER VERSION, into its own column, then read fields off the
    # decoded struct.
    #
    # The first version of this wrote `from_avro(...).getField(name)` for
    # every field, repeating the whole decode expression per field per
    # version -- ~60 decodes per row with v2's 29 fields. The generated code
    # blew past the JVM's 64 KB method limit ("Code grows beyond 64 KB"),
    # Spark fell back to INTERPRETING the stage, and at 1,000 events/sec one
    # 11,000-row batch took 229 s. Spark will not re-inline a decode that is
    # referenced many times, so materialising it keeps it to one per version;
    # tests/unit/test_parse.py counts the from_avro calls in the plan.
    #
    # ...and an OPTIMISER BARRIER. Downstream, clean.valid() filters on
    # reject_reason, which reads decoded fields. Spark pushes filters down
    # through projections by SUBSTITUTING each referenced column with its
    # definition -- so every decoded field the filter touched dragged its own
    # copy of the decode into the predicate: 458 Avro decodes per row, and a
    # stage that ran at 61,000 events/sec fell to 771. Spark never pushes a
    # filter through, or duplicates, a NON-DETERMINISTIC expression -- so the
    # decode columns are made non-deterministic with a condition that is
    # always true. It has to survive three constraints, and two obvious
    # choices each fail one:
    #
    #   rand() >= 0                  folded to `true` -- Spark knows rand()'s
    #                                range -- so the barrier silently vanishes
    #   monotonically_increasing_id  survives, but is REJECTED in streaming
    #   rand() < length(_raw) + 1    survives (the bound is a column, not a
    #                                literal), streaming-safe, and always true
    #                                since rand() < 1 <= length + 1
    #
    # The regression tests count the decodes in the plan AFTER clean.valid(),
    # and the streaming integration test proves the query is accepted.
    barrier = F.rand(0) < F.length(F.col("_raw")) + F.lit(1)
    decoded_cols = {}
    for version_id, schema_json in versions.items():
        decoded_cols[f"_v{version_id}"] = F.when(
            is_framed & (schema_id == version_id) & barrier,
            from_avro(payload, schema_json, AVRO_OPTIONS),
        )

    decoded = None
    for version_id, schema_json in versions.items():
        present = _field_names(schema_json)
        v = F.col(f"_v{version_id}")
        row = F.struct(
            *[
                (v.getField(name) if name in present else F.lit(None))
                .cast(dtype)
                .alias(name)
                for name, dtype in EVENT_FIELDS
            ]
        )
        # A payload that fails to decode comes back either as a null struct
        # or a struct of nulls depending on the Spark build; event_id is a
        # required field in every version, so its absence means "failed".
        matched = v.getField("event_id").isNotNull()
        decoded = F.when(matched, row) if decoded is None else decoded.when(matched, row)

    known_ids = list(versions.keys())

    wire_error = (
        F.when(~is_framed, F.lit("not_avro_framed"))
        .when(~schema_id.isin(known_ids), F.lit("unknown_schema_version"))
        .when(F.col("_parsed").isNull(), F.lit("undecodable_payload"))
        .otherwise(F.lit(None).cast("string"))
    )

    return (
        framed.withColumn("_schema_id", schema_id)
        .withColumns(decoded_cols)
        .withColumn("_parsed", decoded)
        .withColumn("wire_error", wire_error)
        .select(
            *[F.col(f"_parsed.{name}").alias(name) for name, _ in EVENT_FIELDS],
            F.col("wire_error"),
            F.col("_schema_id").alias("schema_id"),
            # Lossless and text-safe for the dead-letter table.
            # In ClickHouse: base64Decode(raw_value).
            #
            # Spark 3.5's base64() is MIME-chunked: it inserts CRLF every 76
            # characters. ClickHouse's base64Decode rejects that, so any
            # message over 57 bytes was stored undecodable. Strip the breaks.
            F.regexp_replace(F.base64(F.col("_raw")), r"[\r\n]", "").alias("raw_value"),
            "kafka_topic",
            "kafka_partition",
            "kafka_offset",
            "kafka_timestamp",
        )
    )
