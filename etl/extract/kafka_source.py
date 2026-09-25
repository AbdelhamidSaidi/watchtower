"""
Extract stage: open the Kafka stream that feeds the Watchtower pipeline.

This module only reads. It hands back the raw Kafka DataFrame with its
native schema (key/value/topic/partition/offset/timestamp) and leaves the
JSON inside `value` untouched -- decoding it is parse.py's job.

Run it on its own to check the broker connection:

    docker exec watchtower-spark-master /opt/spark/bin/spark-submit \
      --master spark://spark-master:7077 \
      --packages org.apache.spark:spark-sql-kafka-0-10_2.12:3.5.9 \
      --conf spark.jars.ivy=/opt/spark/work-dir/.ivy2 \
      /opt/watchtower/etl/extract/kafka_source.py
"""

from pyspark.sql import SparkSession

# Defaults come from config.py -- one place, so the smoke-test entry point
# below and the real pipeline can never disagree about where Kafka is.
from config import (
    KAFKA_BOOTSTRAP_SERVERS as DEFAULT_BOOTSTRAP_SERVERS,
    KAFKA_MAX_OFFSETS_PER_TRIGGER as DEFAULT_MAX_OFFSETS_PER_TRIGGER,
    KAFKA_MIN_PARTITIONS as DEFAULT_MIN_PARTITIONS,
    KAFKA_STARTING_OFFSETS as DEFAULT_STARTING_OFFSETS,
    KAFKA_TOPIC as DEFAULT_TOPIC,
)


def read_kafka_stream(
    spark,
    bootstrap_servers=DEFAULT_BOOTSTRAP_SERVERS,
    topic=DEFAULT_TOPIC,
    starting_offsets=DEFAULT_STARTING_OFFSETS,
    max_offsets_per_trigger=DEFAULT_MAX_OFFSETS_PER_TRIGGER,
    min_partitions=DEFAULT_MIN_PARTITIONS,
):
    """Return the raw Kafka stream as a streaming DataFrame.

    Schema is fixed by the connector:

        key            binary
        value          binary     <- the JSON security event
        topic          string
        partition      int
        offset         long
        timestamp      timestamp  <- broker ingest time, not event time
        timestampType  int
    """
    reader = (
        spark.readStream.format("kafka")
        .option("kafka.bootstrap.servers", bootstrap_servers)
        .option("subscribe", topic)
        .option("startingOffsets", starting_offsets)
        .option("maxOffsetsPerTrigger", max_offsets_per_trigger)
        # Spark tracks offsets in its own checkpoint, not in a consumer group.
        # With a retention-aged topic and a stale checkpoint the requested
        # offset can be gone; failing hard in dev just blocks restarts.
        .option("failOnDataLoss", "false")
    )

    if min_partitions:
        reader = reader.option("minPartitions", min_partitions)

    return reader.load()


def build_spark_session(app_name="watchtower-kafka-source"):
    """Session used when this module is run directly as a smoke test."""
    return (
        SparkSession.builder.appName(app_name)
        .config("spark.sql.session.timeZone", "UTC")
        .getOrCreate()
    )


def main():
    spark = build_spark_session()
    spark.sparkContext.setLogLevel("WARN")

    print(f"Reading topic '{DEFAULT_TOPIC}' from {DEFAULT_BOOTSTRAP_SERVERS}")

    stream = read_kafka_stream(spark)

    print("Kafka source schema:")
    stream.printSchema()

    # Decode value only for readability here -- the real decode is parse.py.
    preview = stream.selectExpr(
        "topic",
        "partition",
        "offset",
        "timestamp AS kafka_timestamp",
        "CAST(value AS STRING) AS raw_value",
    )

    query = (
        preview.writeStream.format("console")
        .outputMode("append")
        .option("truncate", "false")
        .option("numRows", 5)
        .trigger(processingTime="10 seconds")
        .start()
    )

    query.awaitTermination()


if __name__ == "__main__":
    main()
