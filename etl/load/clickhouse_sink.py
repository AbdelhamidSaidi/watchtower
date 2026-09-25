"""
Load stage: write finished rows into ClickHouse.

Structured Streaming has no native ClickHouse sink, so this goes through
foreachBatch. Inside that callback the micro-batch is an ordinary static
DataFrame, which can be written with anything.

    writeStream.foreachBatch(make_events_writer())

DELIVERY SEMANTICS
------------------
foreachBatch is AT-LEAST-ONCE. If the driver dies after the insert but
before the offset commit, that batch is replayed and written twice. This is
why security_events is a ReplacingMergeTree ordered by
(timestamp, source_ip, event_id) -- exact repeats collapse on merge.

Note that "on merge" is not "immediately": a SELECT run before the parts
merge can still see both copies. Use FINAL, or GROUP BY event_id, when a
query must be exact.

SCALING LIMIT
-------------
foreachBatch runs on the DRIVER, and toPandas() pulls the whole batch to
it. At ~1000 rows per micro-batch that is nothing. If throughput grows by a
couple of orders of magnitude this becomes the bottleneck, and the answer
is the ClickHouse JDBC driver writing from the executors instead.
"""

import clickhouse_connect

from core.columns import EVENT_COLUMNS, REJECTED_COLUMNS, SCORE_COLUMNS  # noqa: F401

from config import (
    CLICKHOUSE_DATABASE,
    CLICKHOUSE_HOST,
    CLICKHOUSE_PORT,
    CLICKHOUSE_USER,
    EVENTS_TABLE,
    REJECTED_TABLE,
    clickhouse_password,
)
from observability.metrics import (
    ACTIONS,
    DETECTION_OUTCOME,
    ROWS_WRITTEN,
    SUSPICIOUS,
    classify_reason,
)


# One client per driver process. Opening a connection per micro-batch would
# mean a new HTTP session every 10 seconds for the life of the job.
_client = None


def get_client():
    global _client

    if _client is None:
        _client = clickhouse_connect.get_client(
            host=CLICKHOUSE_HOST,
            port=CLICKHOUSE_PORT,
            username=CLICKHOUSE_USER,
            # read from a mounted secret file, never a plain env var
            password=clickhouse_password(),
            database=CLICKHOUSE_DATABASE,
        )

    return _client


def _write(batch_df, table, columns, batch_id, label, scorer=None):
    pdf = batch_df.select(*columns).toPandas()

    if pdf.empty:
        return

    if scorer is not None:
        pdf = scorer(pdf)
        pdf = pdf[columns + SCORE_COLUMNS]
        flagged = int(pdf["is_suspicious"].sum())
        blocked = int((pdf["recommended_action"] == "block").sum())
    else:
        flagged = blocked = 0

    get_client().insert_df(table, pdf)

    ROWS_WRITTEN.labels(table).inc(len(pdf))
    if scorer is not None:
        SUSPICIOUS.inc(flagged)
        for outcome, count in pdf["llm_reason"].map(classify_reason).value_counts().items():
            DETECTION_OUTCOME.labels(outcome).inc(int(count))
        for action, count in pdf["recommended_action"].value_counts().items():
            ACTIONS.labels(action).inc(int(count))

    suffix = f", {flagged} suspicious, {blocked} block" if scorer is not None else ""
    print(
        f"[{label}] batch {batch_id}: wrote {len(pdf)} rows to {table}{suffix}",
        flush=True,
    )


def make_events_writer(table=EVENTS_TABLE, scorer=None):
    """foreachBatch callback for the main pipeline output.

    `scorer` takes and returns a pandas frame, adding SCORE_COLUMNS. Pass
    None to store features with zero scores.
    """

    def write_events(batch_df, batch_id):
        _write(batch_df, table, EVENT_COLUMNS, batch_id, "events", scorer)

    return write_events


def make_rejected_writer(table=REJECTED_TABLE):
    """foreachBatch callback for rows clean.py rejected."""

    def write_rejected(batch_df, batch_id):
        _write(batch_df, table, REJECTED_COLUMNS, batch_id, "rejected")

    return write_rejected
