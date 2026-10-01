"""The rolling 5-minute window of one runner -- the behavioural features.

Engine-free: Flink keeps one RollingWindow per runner_ip in keyed state
(stream/job.py FlinkWindowStore); the tests use MemoryStore.
"""


WINDOW_1M_MS = 60 * 1000
WINDOW_5M_MS = 5 * 60 * 1000

# (column, ClickHouse-compatible kind), in output order.
FEATURES = [
    ("events_1m", "int"),
    ("failed_builds_1m", "int"),
    ("failed_builds_5m", "int"),
    ("unique_projects_5m", "int"),         # a runner failing across many projects is itself broken
    ("oom_kills_5m", "int"),
    ("distinct_exit_codes_5m", "int"),
    ("compile_steps_5m", "int"),
    ("build_frequency", "float"),
    ("rogue_commands_5m", "int"),
    ("failure_signatures_5m", "int"),      # the infrastructure's errors, not the code's
    ("http_errors_5m", "int"),
    ("dependency_404_1m", "int"),          # a build hunting for artifacts that are not there
    ("distinct_artifacts_5m", "int"),
    ("published_bytes_5m", "long"),        # runaway uploads
    ("slow_steps_5m", "int"),
    ("cache_misses_5m", "int"),
]

# The fields of one window record, in order.
RECORD_FIELDS = [
    "ts_ms", "event_types", "exit_codes", "projects", "statuses", "sizes", "paths",
    "rogue", "signatures", "oom", "slow", "misses",
]

OOM_EXIT_CODE = 137  # 128 + SIGKILL: what the kernel's OOM killer sends


def record_of(event, ts_ms):
    """The window record for one normalized, enriched event."""
    event_type = event.get("event_type") or ""
    exit_code = int(event.get("exit_code") or 0)
    return (
        ts_ms,
        event_type,
        exit_code,
        event.get("project") or "",
        int(event.get("http_status") or 0),
        # Only uploads count towards the bytes a runner pushes at the
        # artifact store; a download is the registry's cost, not the store's.
        int(event.get("bytes_sent") or 0) if event_type == "ARTIFACT_PUBLISH" else 0,
        event.get("url_path") or "",
        int(event.get("is_rogue_command") or 0),
        int(event.get("is_failure_signature") or 0),
        int(event.get("failure_signature") == "oom" or exit_code == OOM_EXIT_CODE),
        int(event.get("is_slow_step") or 0),
        int(event.get("is_cache_miss") or 0),
    )


# The window's scalar state: running sums, sizes, and three positions in
# one append-only record log --
#
#     head5 ........ head1 ........ tail
#     |  in 5m only  |  in 1m and 5m |
#
# The 1-minute window is a SUFFIX of the 5-minute one, so both are pointers
# into the same records rather than two copies of them.
SUMMARY_FIELDS = [
    "head5", "head1", "tail", "newest",
    # the record AT each head, cached: an eviction check costs no store read
    "head1_record", "head5_record",
    "failed_5m", "oom_5m", "compiles_5m", "builds_5m", "rogue_5m",
    "signatures_5m", "errors_5m", "bytes_5m", "slow_5m", "misses_5m",
    "failed_1m", "not_found_1m",
    "n_projects", "n_codes", "n_paths",
]
COUNTED = ("projects", "codes", "paths")


def new_summary():
    summary = dict.fromkeys(SUMMARY_FIELDS, 0)
    summary["newest"] = None
    summary["head1_record"] = summary["head5_record"] = None
    return summary


class MemoryStore:
    """Window storage in plain Python objects, for the tests. stream/job.py has the same interface over Flink keyed state,
    where every operation touches ONE entry -- so per-event cost does not
    grow with the window, and neither does what a checkpoint rewrites."""

    def __init__(self):
        self.summary = new_summary()
        self.records = {}
        self.counts = {kind: {} for kind in COUNTED}

    def get_record(self, i):
        return self.records[i]

    def put_record(self, i, record):
        self.records[i] = record

    def drop_record(self, i):
        del self.records[i]

    def get_count(self, kind, key):
        return self.counts[kind].get(key, 0)

    def set_count(self, kind, key, n):
        if n:
            self.counts[kind][key] = n
        else:
            self.counts[kind].pop(key, None)


class RollingWindow:
    """One runner's last 5 minutes, with RUNNING aggregates.

    Every new event adds itself to the counters; every event that falls out
    of a window subtracts itself. Cost per event is O(1) amortised,
    whatever the history holds -- in time AND in state touched.

    The obvious version -- rescan the whole 5-minute history for every new
    event -- is O(history) per event. It was fine at 100 events/sec (3,600
    rows of history for the busiest host) and collapsed at 1,000: one host's
    20-second batch took 68 s, for a batch due every 20 s. tests/unit/
    test_features.py keeps that brute-force version as a reference and
    checks this one against it on random event streams.

    Assumes per-runner events arrive in event-time order, which the pipeline
    guarantees: the producer keys by runner_ip, so one runner is one Kafka
    partition. A late event is evaluated as of the newest time already seen
    -- the window never moves backwards.
    """

    # records are tuples, in RECORD_FIELDS order
    _TS, _TYPE, _CODE, _PROJECT, _STATUS, _SIZE, _PATH, _ROGUE, _SIG, _OOM, _SLOW, _MISS = range(12)

    def __init__(self, store=None):
        self.store = store if store is not None else MemoryStore()

    def _count(self, m, kind, key, sign):
        n = self.store.get_count(kind, key) + sign
        self.store.set_count(kind, key, n)
        if sign > 0 and n == 1:
            m["n_" + kind] += 1
        elif sign < 0 and n == 0:
            m["n_" + kind] -= 1

    def _apply5(self, m, r, sign):
        kind = r[self._TYPE]
        m["failed_5m"] += sign * (kind == "BUILD_FAILURE")
        m["oom_5m"] += sign * r[self._OOM]
        m["compiles_5m"] += sign * (kind == "COMPILE_STEP")
        m["builds_5m"] += sign * (kind in ("BUILD_SUCCESS", "BUILD_FAILURE"))
        m["rogue_5m"] += sign * r[self._ROGUE]
        m["signatures_5m"] += sign * r[self._SIG]
        m["errors_5m"] += sign * (r[self._STATUS] >= 400)
        m["bytes_5m"] += sign * r[self._SIZE]
        m["slow_5m"] += sign * r[self._SLOW]
        m["misses_5m"] += sign * r[self._MISS]
        if r[self._PROJECT]:
            self._count(m, "projects", r[self._PROJECT], sign)
        if r[self._CODE] > 0:
            self._count(m, "codes", r[self._CODE], sign)
        if r[self._PATH]:
            self._count(m, "paths", r[self._PATH], sign)

    def _apply1(self, m, r, sign):
        m["failed_1m"] += sign * (r[self._TYPE] == "BUILD_FAILURE")
        m["not_found_1m"] += sign * (r[self._STATUS] == 404)

    def add(self, record):
        """Add one event; return its features as of that event."""
        store, m = self.store, self.store.summary
        ts = record[self._TS]
        m["newest"] = ts if m["newest"] is None else max(m["newest"], ts)
        now = m["newest"]

        if m["head1_record"] is None or m["head1"] == m["tail"]:   # window was empty
            m["head1_record"] = record
        if m["head5_record"] is None or m["head5"] == m["tail"]:
            m["head5_record"] = record
        store.put_record(m["tail"], record)
        m["tail"] += 1
        self._apply5(m, record, +1)
        self._apply1(m, record, +1)

        # The 1-minute window first: whatever leaves the 5-minute window has
        # already left the 1-minute one, so head5 never passes head1 and a
        # record is only dropped once neither window needs it. Neither loop
        # can run past the record holding `newest`, so neither empties.
        #
        # The record at each head is kept in the summary, so checking a head
        # needs no store read, and evicting one needs exactly one -- for the
        # next head. (In Flink every store read is a Python -> JVM call; this
        # took window reads from 5.9 to ~2 per event.)
        while now - m["head1_record"][self._TS] > WINDOW_1M_MS:
            self._apply1(m, m["head1_record"], -1)
            m["head1"] += 1
            m["head1_record"] = store.get_record(m["head1"])
        while now - m["head5_record"][self._TS] > WINDOW_5M_MS:
            self._apply5(m, m["head5_record"], -1)
            store.drop_record(m["head5"])
            m["head5"] += 1
            m["head5_record"] = store.get_record(m["head5"])

        return {
            "events_1m": m["tail"] - m["head1"],
            "failed_builds_1m": m["failed_1m"],
            "failed_builds_5m": m["failed_5m"],
            "unique_projects_5m": m["n_projects"],
            "oom_kills_5m": m["oom_5m"],
            "distinct_exit_codes_5m": m["n_codes"],
            "compile_steps_5m": m["compiles_5m"],
            # builds finished per minute across the 5m window
            "build_frequency": float(m["builds_5m"]) / 5.0,
            "rogue_commands_5m": m["rogue_5m"],
            "failure_signatures_5m": m["signatures_5m"],
            "http_errors_5m": m["errors_5m"],
            "dependency_404_1m": m["not_found_1m"],
            "distinct_artifacts_5m": m["n_paths"],
            "published_bytes_5m": int(m["bytes_5m"]),
            "slow_steps_5m": m["slow_5m"],
            "cache_misses_5m": m["misses_5m"],
        }

    def records(self):
        """The 5-minute window's records, oldest first."""
        m = self.store.summary
        return [self.store.get_record(i) for i in range(m["head5"], m["tail"])]

    @classmethod
    def from_state(cls, arrays):
        """Rebuild from checkpointed parallel arrays (RECORD_FIELDS order)."""
        window = cls()
        for r in sorted(zip(*arrays), key=lambda r: r[cls._TS]):
            window.add(r)
        return window

    def to_state(self):
        """The 5-minute window as parallel arrays (RECORD_FIELDS order)."""
        records = self.records()
        columns = list(zip(*records)) if records else [()] * len(RECORD_FIELDS)
        return tuple(list(c) for c in columns)
