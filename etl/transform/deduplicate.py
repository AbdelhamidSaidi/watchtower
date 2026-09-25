"""
Transform stage 4: drop events already seen.

The first STATEFUL stage, and the first one that shuffles.

Why it is needed: Kafka is at-least-once. Producer retries, consumer
rebalances and Spark restarts all replay messages. Without this, a restart
re-inflates failed_logins_5m and manufactures an anomaly that never
happened.

Why it forces a watermark: to know whether event_id was seen before, Spark
keeps a state store. Without an eviction rule that store grows until the
executor dies.

    withWatermark(WATERMARK)
        .dropDuplicatesWithinWatermark(["event_id"])

    state:   event_id -> first seen
    evicted: once older than (max event time - WATERMARK)

WATERMARK is a security decision wearing a config value's clothes. Too
tight and genuinely late events get dropped, which is a detection gap. Too
loose and state size and memory grow. Defend the number you pick.
"""

import os


# How late an event may arrive and still be accepted.
DEFAULT_WATERMARK = os.getenv("WATCHTOWER_WATERMARK", "10 minutes")

# Event-time column. Must already be a real timestamp -- clean.py casts it.
EVENT_TIME_COLUMN = "timestamp"


def deduplicate(df, watermark=DEFAULT_WATERMARK):
    """Drop repeat event_ids seen inside the watermark window.

    dropDuplicatesWithinWatermark (Spark 3.5+) is used rather than
    dropDuplicates: the older call requires the event-time column to be
    part of the dedup key, which would make two deliveries of the same
    event look distinct if their timestamps differed by a microsecond.
    """
    return df.withWatermark(EVENT_TIME_COLUMN, watermark).dropDuplicatesWithinWatermark(
        ["event_id"]
    )
