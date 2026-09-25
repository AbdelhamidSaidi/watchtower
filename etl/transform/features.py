"""
Transform stage 6: turn events into behaviour.

This is the stage that decides what the model can see. A single
LOGIN_FAILURE is not an anomaly; forty of them from one IP in two minutes
is. The model never sees the log line -- it sees these counters.

THE GRAIN PROBLEM
-----------------
The obvious implementation does not fit the ClickHouse schema:

    df.groupBy(window("timestamp", "5 minutes"), "source_ip").count()

That emits one row per (window, source_ip). security_events is keyed on
event_id with feature columns attached, so the grains do not match, and
joining the aggregate back onto the event stream means a stream-stream
join between two stateful operators -- once per window length.

applyInPandasWithState avoids all of it: Spark hands us the new events for
one hash bucket of source_ips plus that bucket's state, and we emit ONE ROW
PER INPUT EVENT with the counters attached. One shuffle, one state store,
grain preserved. Inside the bucket every source_ip has its own window.

NOTE ON PYTHON
--------------
Unlike from_json, this genuinely runs Python on the executors -- rows cross
into a Python worker as Arrow batches. Each group costs one Python call
with a fixed overhead, which is why the grouping is by bucket (see
FEATURE_BUCKETS), and why the per-event work is O(1) (see RollingWindow).
At 1,000 events/sec, both mattered.

KNOWN GAP
---------
Every feature below is keyed by source_ip. `unique_source_ips_5m` in the
ClickHouse schema is inherently keyed by USER (one account seen from many
IPs = credential stuffing) and cannot be computed from this grouping -- it
is emitted as 0. Either rename that column to unique_users_5m, which this
stage does compute correctly, or add a second user-keyed stateful pass.
"""

import os

import pandas as pd
from pyspark.sql import functions as F
from pyspark.sql.streaming.state import GroupStateTimeout
from pyspark.sql.types import (
    ArrayType,
    FloatType,
    IntegerType,
    LongType,
    StringType,
    StructField,
    StructType,
)


from core.window import (  # noqa: F401  (re-exported for tests)
    FEATURES,
    WINDOW_1M_MS,
    WINDOW_5M_MS,
    RollingWindow,
)

# Drop an IP's state after it has been quiet this long, so idle keys do not
# accumulate. Processing-time based, which keeps it independent of the
# event-time watermark deduplicate already set.
STATE_TIMEOUT_MS = 15 * 60 * 1000

# State is grouped by a HASH BUCKET of source_ip, not by source_ip itself.
# applyInPandasWithState calls Python once per group, with a fixed cost per
# call (Arrow conversion, frame handling on 60+ columns). At 1,000 events/sec
# over ~1,780 sources that was ~1,780 calls and over a minute per batch, for
# ~11 events each. 64 buckets means 64 calls. Every source still lands in
# exactly one bucket and keeps its own window, so results are unchanged.
FEATURE_BUCKETS = int(os.getenv("WATCHTOWER_FEATURE_BUCKETS", "64"))

# A source quiet for longer than the 5-minute window is dropped from its
# bucket's state. Records older than (newest event in the batch - 5 min -
# margin) can never fall inside a future event's window, since future
# events are newer; the margin absorbs clock skew between sources.
PRUNE_MARGIN_MS = 60 * 1000

# Columns this stage appends, in order (core/window.py defines them).
_SPARK_TYPES = {"int": IntegerType(), "long": LongType(), "float": FloatType()}
FEATURE_FIELDS = [(name, _SPARK_TYPES[kind]) for name, kind in FEATURES]

# Rolling history for one source_ip. Parallel arrays rather than a struct
# array: cheaper to serialise, and every read below is a full scan anyway.
#
# CHANGING THIS SCHEMA INVALIDATES EXISTING CHECKPOINTS: Spark refuses to
# restore state written with a different shape. v2 added five arrays, and
# bucketing added `ips`; each needed a checkpoint reset (operations.md §9).
STATE_SCHEMA = StructType(
    [
        StructField("ips", ArrayType(StringType())),
        StructField("ts_ms", ArrayType(LongType())),
        StructField("event_types", ArrayType(StringType())),
        StructField("ports", ArrayType(IntegerType())),
        StructField("users", ArrayType(StringType())),
        StructField("statuses", ArrayType(IntegerType())),
        StructField("sizes", ArrayType(LongType())),
        StructField("paths", ArrayType(StringType())),
        StructField("sensitive", ArrayType(IntegerType())),
        StructField("signatures", ArrayType(IntegerType())),
    ]
)

# The per-record fields; `ips` tags each record with the source it belongs
# to, because one bucket's state holds many sources.
HISTORY_FIELDS = [f.name for f in STATE_SCHEMA.fields if f.name != "ips"]


def build_output_schema(input_schema):
    """Input columns, unchanged, plus the feature columns.

    Derived from the incoming schema rather than hardcoded so an added
    column upstream does not silently desync this stage.
    """
    return StructType(
        list(input_schema.fields)
        + [StructField(name, dtype, True) for name, dtype in FEATURE_FIELDS]
    )


def _column(batch, name, default):
    """One column as a plain list, nulls replaced -- or the default if the
    column is absent (a v1 event has no http_status, say)."""
    if name not in batch.columns:
        return [default] * len(batch)
    return [default if (v is None or v != v) else v for v in batch[name].tolist()]


def _windows_from_state(arrays):
    """{source_ip: RollingWindow} from one bucket's checkpointed state."""
    ips, history = arrays[0], arrays[1:]
    per_ip = {}
    for i, ip in enumerate(ips):
        per_ip.setdefault(ip, []).append(i)
    return {
        ip: RollingWindow.from_state([[column[i] for i in idx] for column in history])
        for ip, idx in per_ip.items()
    }


def _windows_to_state(windows, horizon_ms):
    """One bucket's windows as tagged parallel arrays, pruned to the horizon."""
    columns = [[] for _ in range(len(HISTORY_FIELDS) + 1)]
    for ip in list(windows):
        kept = [r for r in windows[ip].records() if r[0] >= horizon_ms]
        if not kept:
            del windows[ip]  # quiet for longer than the window: forget it
            continue
        columns[0].extend([ip] * len(kept))
        for k, column in enumerate(zip(*kept), start=1):
            columns[k].extend(column)
    return tuple(columns)


def _update_bucket(key, pdfs, state):
    """Called once per bucket per micro-batch; the bucket holds many sources.

    Only the 9 columns the window reads are pulled out as plain lists, and
    the features are ADDED to the frame in one step -- the other 60+ columns
    are never touched. (Converting every row to a dict and back was ~90% of
    the original per-call cost.)
    """
    if state.hasTimedOut:
        state.remove()
        return

    frames = [pdf for pdf in pdfs if not pdf.empty]
    if not frames:
        return

    batch = frames[0] if len(frames) == 1 else pd.concat(frames, ignore_index=True)
    batch = batch.drop(columns=["_feature_bucket"], errors="ignore")

    # Per source, features follow event time -- not Kafka delivery order.
    batch = batch.sort_values(["source_ip", "timestamp"], kind="stable").reset_index(drop=True)

    windows = _windows_from_state(state.get) if state.exists else {}

    ts_ms = [pd.Timestamp(t).value // 1_000_000 for t in batch["timestamp"].tolist()]
    sources = _column(batch, "source_ip", "")
    columns = (
        _column(batch, "event_type", ""),
        _column(batch, "target_port", 0),
        _column(batch, "user", ""),
        _column(batch, "http_status", 0),
        _column(batch, "bytes_sent", 0),
        _column(batch, "url_path", ""),
        _column(batch, "is_sensitive_command", 0),
        _column(batch, "is_attack_signature", 0),
    )

    features = {name: [] for name, _ in FEATURE_FIELDS}
    for i, now_ms in enumerate(ts_ms):
        window = windows.get(sources[i])
        if window is None:
            window = windows[sources[i]] = RollingWindow()
        event_type, port, user, status, size, path, sensitive, signature = (c[i] for c in columns)
        values = window.add((
            now_ms, event_type, int(port), user, int(status), int(size), path,
            int(sensitive), int(signature),
        ))
        for name in features:
            features[name].append(values[name])

    out = pd.concat([batch, pd.DataFrame(features, index=batch.index)], axis=1)

    horizon = max(ts_ms) - WINDOW_5M_MS - PRUNE_MARGIN_MS
    state.update(_windows_to_state(windows, horizon))
    state.setTimeoutDuration(STATE_TIMEOUT_MS)

    yield out


def add_features(df):
    """Attach rolling behavioural features, one row in / one row out.

    Requires a watermark upstream (deduplicate sets it) and `timestamp` to
    already be a real timestamp (clean casts it).
    """
    bucketed = df.withColumn(
        "_feature_bucket", F.pmod(F.xxhash64("source_ip"), F.lit(FEATURE_BUCKETS))
    )
    return bucketed.groupBy("_feature_bucket").applyInPandasWithState(
        _update_bucket,
        build_output_schema(df.schema),
        STATE_SCHEMA,
        "append",
        GroupStateTimeout.ProcessingTimeTimeout,
    )
