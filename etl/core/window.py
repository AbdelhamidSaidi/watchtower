"""The rolling 5-minute window of one source -- the behavioural features.

Engine-free: Flink keeps one RollingWindow per source_ip in keyed state;
Spark keeps them in applyInPandasWithState bucket state. Same class, same
numbers (tests/unit/test_features.py checks it against a brute-force
reference, event by event).
"""


WINDOW_1M_MS = 60 * 1000
WINDOW_5M_MS = 5 * 60 * 1000

# (column, ClickHouse-compatible kind), in output order.
FEATURES = [
    ("requests_1m", "int"),
    ("failed_logins_1m", "int"),
    ("failed_logins_5m", "int"),
    ("unique_source_ips_5m", "int"),  # always 0 -- see KNOWN GAP in transform/features.py
    ("unique_users_5m", "int"),
    ("port_scan_count_5m", "int"),
    ("unique_ports_5m", "int"),
    ("commands_executed_5m", "int"),
    ("login_frequency", "float"),
    # v2 -- read from request / process context, not just counts
    ("sensitive_commands_5m", "int"),  # closes the privilege-escalation gap
    ("attack_signatures_5m", "int"),
    ("http_errors_5m", "int"),
    ("http_404_1m", "int"),             # directory brute force
    ("distinct_paths_5m", "int"),
    ("bytes_sent_5m", "long"),          # exfiltration
]

# The fields of one window record, in order.
RECORD_FIELDS = [
    "ts_ms", "event_types", "ports", "users", "statuses", "sizes", "paths",
    "sensitive", "signatures",
]


def record_of(event, ts_ms):
    """The window record for one normalized, enriched event."""
    return (
        ts_ms,
        event.get("event_type") or "",
        int(event.get("target_port") or 0),
        event.get("user") or "",
        int(event.get("http_status") or 0),
        int(event.get("bytes_sent") or 0),
        event.get("url_path") or "",
        int(event.get("is_sensitive_command") or 0),
        int(event.get("is_attack_signature") or 0),
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
    "failed_5m", "scans_5m", "commands_5m", "logins_5m", "sensitive_5m",
    "signatures_5m", "errors_5m", "bytes_5m", "failed_1m", "not_found_1m",
    "n_users", "n_ports", "n_paths",
]
COUNTED = ("users", "ports", "paths")


def new_summary():
    summary = dict.fromkeys(SUMMARY_FIELDS, 0)
    summary["newest"] = None
    summary["head1_record"] = summary["head5_record"] = None
    return summary


class MemoryStore:
    """Window storage in plain Python objects: for Spark's bucket state and
    the tests. stream/job.py has the same interface over Flink keyed state,
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
    """One source's last 5 minutes, with RUNNING aggregates.

    Every new event adds itself to the counters; every event that falls out
    of a window subtracts itself. Cost per event is O(1) amortised,
    whatever the history holds -- in time AND in state touched.

    The obvious version -- rescan the whole 5-minute history for every new
    event -- is O(history) per event. It was fine at 100 events/sec (3,600
    rows of history for the busiest host) and collapsed at 1,000: one host's
    20-second batch took 68 s, for a batch due every 20 s. tests/unit/
    test_features.py keeps that brute-force version as a reference and
    checks this one against it on random event streams.

    Assumes per-source events arrive in event-time order, which the pipeline
    guarantees: the producer keys by source_ip, so one source is one Kafka
    partition. A late event is evaluated as of the newest time already seen
    -- the window never moves backwards.
    """

    # records are tuples, in RECORD_FIELDS order
    _TS, _TYPE, _PORT, _USER, _STATUS, _SIZE, _PATH, _SENSITIVE, _SIG = range(9)

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
        m["failed_5m"] += sign * (kind == "LOGIN_FAILURE")
        m["scans_5m"] += sign * (kind == "PORT_SCAN")
        m["commands_5m"] += sign * (kind == "COMMAND_EXECUTION")
        m["logins_5m"] += sign * (kind in ("LOGIN_SUCCESS", "LOGIN_FAILURE"))
        m["sensitive_5m"] += sign * r[self._SENSITIVE]
        m["signatures_5m"] += sign * r[self._SIG]
        m["errors_5m"] += sign * (r[self._STATUS] >= 400)
        m["bytes_5m"] += sign * r[self._SIZE]
        if r[self._USER]:
            self._count(m, "users", r[self._USER], sign)
        if r[self._PORT] > 0:
            self._count(m, "ports", r[self._PORT], sign)
        if r[self._PATH]:
            self._count(m, "paths", r[self._PATH], sign)

    def _apply1(self, m, r, sign):
        m["failed_1m"] += sign * (r[self._TYPE] == "LOGIN_FAILURE")
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
            "requests_1m": m["tail"] - m["head1"],
            "failed_logins_1m": m["failed_1m"],
            "failed_logins_5m": m["failed_5m"],
            "unique_source_ips_5m": 0,  # see KNOWN GAP in transform/features.py
            "unique_users_5m": m["n_users"],
            "port_scan_count_5m": m["scans_5m"],
            "unique_ports_5m": m["n_ports"],
            "commands_executed_5m": m["commands_5m"],
            # events per minute across the 5m window
            "login_frequency": float(m["logins_5m"]) / 5.0,
            "sensitive_commands_5m": m["sensitive_5m"],
            "attack_signatures_5m": m["signatures_5m"],
            "http_errors_5m": m["errors_5m"],
            "http_404_1m": m["not_found_1m"],
            "distinct_paths_5m": m["n_paths"],
            "bytes_sent_5m": int(m["bytes_5m"]),
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
