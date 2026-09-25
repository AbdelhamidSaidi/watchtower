"""
deduplicate: repeat event_ids are dropped, keyed on event_id alone.

dropDuplicatesWithinWatermark is STREAMING-ONLY -- Spark 3.5 refuses it on
a batch DataFrame -- so these tests run it the way the pipeline does: a
streaming source, a memory sink, availableNow.
"""

import json
import os
import uuid

import pytest

from transform.deduplicate import deduplicate


@pytest.fixture
def dedup(spark, tmp_path):
    def run(rows):
        source = tmp_path / f"src-{uuid.uuid4().hex}"
        source.mkdir()
        with open(source / "part-0.json", "w") as handle:
            for event_id, ts, ip in rows:
                handle.write(json.dumps({"event_id": event_id, "ts": ts, "source_ip": ip}) + "\n")

        stream = (
            spark.readStream.schema("event_id string, ts string, source_ip string")
            .json(str(source))
            .selectExpr("event_id", "cast(ts as timestamp) as timestamp", "source_ip")
        )
        name = f"dedup_{uuid.uuid4().hex}"
        query = (
            deduplicate(stream)
            .writeStream.format("memory")
            .queryName(name)
            .option("checkpointLocation", os.path.join(tmp_path, f"ck-{name}"))
            .trigger(availableNow=True)
            .start()
        )
        query.awaitTermination(timeout=120)
        assert query.exception() is None, query.exception()
        return spark.sql(f"select * from {name}").collect()

    return run


def test_replayed_event_is_dropped(dedup):
    assert len(dedup([("a", "2026-09-20 14:00:00", "1.1.1.1")] * 3)) == 1


def test_distinct_events_all_survive(dedup):
    rows = dedup([
        ("a", "2026-09-20 14:00:00", "1.1.1.1"),
        ("b", "2026-09-20 14:00:00", "1.1.1.1"),
    ])
    assert len(rows) == 2


def test_redelivery_with_a_different_timestamp_is_still_a_duplicate(dedup):
    # Why dropDuplicatesWithinWatermark and not dropDuplicates: the older call
    # needs the event-time column in the key, so these would both survive.
    rows = dedup([
        ("a", "2026-09-20 14:00:00.000001", "1.1.1.1"),
        ("a", "2026-09-20 14:00:00.000002", "1.1.1.1"),
    ])
    assert len(rows) == 1
