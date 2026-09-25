"""Everything that needs a source's HISTORY, for one event at a time.

    dedup      drop an event_id this source already sent (Kafka is
               at-least-once: producer retries and job restarts replay)
    features   the rolling 5-minute window (core/window.py)
    rules      deterministic detection (core/rules.py)

One SourceState per source_ip. Storage is pluggable: plain Python here
(tests, Spark), Flink keyed state in stream/job.py -- where every
operation touches one state entry, so the per-event cost does not grow
with the window.

DEDUP HORIZON. In memory, an event_id is remembered for DEDUP_MS of the
source's event time -- the same 10 minutes as Spark's watermark. In
Flink, for the source's last 1,024 events (stream/job.RecentIds: a ring of
id hashes inside the summary state, which costs no state call). What dedup
guards against is Kafka producer retries, which come within seconds;
Flink's own restarts replay nothing twice, since windows and offsets are
restored from the same checkpoint. Unlike Spark, nothing is dropped for being late: Spark
discards an event older than the global watermark outright, a detection
gap; here a late event is still scored (as of the newest time seen, see
RollingWindow).
"""

import os
from collections import deque
from datetime import datetime, timedelta, timezone

from core.columns import EVENT_COLUMNS, SCORE_COLUMNS
from core.records import clickhouse_time
from core.rules import score_event
from core.window import RollingWindow, record_of

DEDUP_MS = int(os.getenv("WATCHTOWER_DEDUP_MINUTES", "10")) * 60 * 1000

OUTPUT_COLUMNS = EVENT_COLUMNS + SCORE_COLUMNS

_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
_MS = timedelta(milliseconds=1)


class MemorySeen:
    """Dedup memory in plain Python: event_ids for DEDUP_MS of the source's
    event time. (Flink's equivalent: stream/job.RecentIds.)"""

    def __init__(self):
        self.ids = set()
        self.order = deque()  # (ts_ms, event_id), oldest first
        self.newest_ms = None

    def __contains__(self, event_id):
        return event_id in self.ids

    def __len__(self):
        return len(self.ids)

    def remember(self, event_id, ts_ms):
        self.newest_ms = ts_ms if self.newest_ms is None else max(self.newest_ms, ts_ms)
        self.ids.add(event_id)
        self.order.append((ts_ms, event_id))
        horizon = self.newest_ms - DEDUP_MS
        while self.order and self.order[0][0] < horizon:
            self.ids.discard(self.order.popleft()[1])


class SourceState:
    """One source_ip's window plus the event_ids it sent recently. Storage
    is pluggable: in memory here, Flink keyed state in the job."""

    def __init__(self, window_store=None, seen=None):
        self.window = RollingWindow(window_store)
        self.seen = seen if seen is not None else MemorySeen()

    def process(self, event):
        """Features + rules for one normalized, enriched event.

        Returns the ClickHouse row, or None for a duplicate.
        """
        event_id = event["event_id"].strip(" ")
        if event_id in self.seen:
            return None
        ts = event["_ts"]
        ts_ms = (ts - _EPOCH) // _MS  # exact floor, like Spark's ns // 1e6
        self.seen.remember(event_id, ts_ms)

        event.update(self.window.add(record_of(event, ts_ms)))
        score_event(event)

        row = {name: event.get(name) for name in OUTPUT_COLUMNS}
        row["event_id"] = event_id
        row["timestamp"] = clickhouse_time(ts)
        return row
