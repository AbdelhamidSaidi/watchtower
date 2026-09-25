"""Engine-free detection logic: plain Python, no Spark, no Flink.

Both engines import from here, so a threshold, a regex or a feature is
defined exactly once:

    Flink (stream/)       per event, the live path
    Spark (transform/)    micro-batches -- replays and backfills

tests/unit/test_parity.py runs the same events through both and requires
identical output.
"""
