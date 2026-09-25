"""features: the rolling counters, and the per-bucket stateful update."""

import pandas as pd

import random

import pytest

from transform.features import (
    FEATURE_FIELDS,
    WINDOW_1M_MS,
    WINDOW_5M_MS,
    RollingWindow,
    _update_bucket,
)


class FakeState:
    """Enough of pyspark's GroupState to drive the update function."""

    def __init__(self, value=None):
        self._value = value
        self.hasTimedOut = False
        self.removed = False
        self.timeout = None

    @property
    def exists(self):
        return self._value is not None

    @property
    def get(self):
        return self._value

    def update(self, value):
        self._value = value

    def remove(self):
        self.removed = True
        self._value = None

    def setTimeoutDuration(self, ms):
        self.timeout = ms


def _events(rows):
    return pd.DataFrame(
        [
            {
                "source_ip": "45.134.26.7",
                "timestamp": pd.Timestamp(ts, tz="UTC"),
                "event_type": et,
                "target_port": port,
                "user": user,
            }
            for ts, et, port, user in rows
        ]
    )


def _run(rows, state=None):
    state = state or FakeState()
    out = list(_update_bucket((0,), iter([_events(rows)]), state))
    return pd.concat(out) if out else pd.DataFrame(), state


def brute_force_features(history, now_ms):
    """REFERENCE: the original O(history)-per-event algorithm, kept here to
    prove RollingWindow exact. history: records inside 5 minutes."""
    in_1m = [r for r in history if now_ms - r[0] <= WINDOW_1M_MS]
    return {
        "requests_1m": len(in_1m),
        "failed_logins_1m": sum(r[1] == "LOGIN_FAILURE" for r in in_1m),
        "failed_logins_5m": sum(r[1] == "LOGIN_FAILURE" for r in history),
        "unique_source_ips_5m": 0,
        "unique_users_5m": len({r[3] for r in history if r[3]}),
        "port_scan_count_5m": sum(r[1] == "PORT_SCAN" for r in history),
        "unique_ports_5m": len({r[2] for r in history if r[2] > 0}),
        "commands_executed_5m": sum(r[1] == "COMMAND_EXECUTION" for r in history),
        "login_frequency": sum(r[1] in ("LOGIN_SUCCESS", "LOGIN_FAILURE") for r in history) / 5.0,
        "sensitive_commands_5m": sum(r[7] for r in history),
        "attack_signatures_5m": sum(r[8] for r in history),
        "http_errors_5m": sum(r[4] >= 400 for r in history),
        "http_404_1m": sum(r[4] == 404 for r in in_1m),
        "distinct_paths_5m": len({r[6] for r in history if r[6]}),
        "bytes_sent_5m": sum(r[5] for r in history),
    }


def _random_stream(seed, n):
    rng = random.Random(seed)
    t, out = 1_790_000_000_000, []
    types = ["LOGIN_FAILURE", "LOGIN_SUCCESS", "PORT_SCAN", "COMMAND_EXECUTION", "HTTP_REQUEST", "FILE_ACCESS"]
    for _ in range(n):
        # gaps from 0 ms to 90 s, so events cross BOTH window edges often
        t += rng.choice([0, 0, 5, 250, 2_000, 30_000, 61_000, 90_000])
        out.append((
            t, rng.choice(types), rng.choice([0, 0, 22, 80, 443, 3389]),
            rng.choice(["", "alice", "bob", "root"]), rng.choice([0, 200, 404, 404, 500]),
            rng.choice([0, 150, 90_000_000]), rng.choice(["", "/", "/.env", "/admin"]),
            rng.choice([0, 0, 1]), rng.choice([0, 0, 1]),
        ))
    return out


@pytest.mark.parametrize("seed", range(12))
def test_rolling_window_matches_brute_force_exactly(seed):
    """The O(1) window must agree with the reference on EVERY feature of
    EVERY event -- including at both window edges."""
    window, history = RollingWindow(), []
    for record in _random_stream(seed, 1500):
        now = record[0]
        history = [r for r in history + [record] if now - r[0] <= WINDOW_5M_MS]
        assert window.add(record) == brute_force_features(history, now)


def test_state_round_trip_resumes_identically():
    """Checkpoint mid-stream, restore, continue: same answers as never stopping."""
    stream = _random_stream(99, 2000)
    straight = RollingWindow()
    expected = [straight.add(r) for r in stream]

    first = RollingWindow()
    for r in stream[:1000]:
        first.add(r)
    resumed = RollingWindow.from_state(first.to_state())
    assert [resumed.add(r) for r in stream[1000:]] == expected[1000:]


def test_state_holds_only_the_5_minute_window():
    window = RollingWindow()
    for r in _random_stream(7, 3000):
        window.add(r)
    ts = window.to_state()[0]
    assert max(ts) - min(ts) <= WINDOW_5M_MS


def test_one_row_out_per_event_in():
    rows = [(f"2026-09-20 14:00:0{i}", "LOGIN_FAILURE", 0, "root") for i in range(5)]
    out, _ = _run(rows)
    assert len(out) == 5


def test_brute_force_counter_accumulates_in_event_order():
    # delivered out of order -- features must follow event time
    rows = [
        ("2026-09-20 14:00:03", "LOGIN_FAILURE", 0, "root"),
        ("2026-09-20 14:00:01", "LOGIN_FAILURE", 0, "root"),
        ("2026-09-20 14:00:02", "LOGIN_FAILURE", 0, "root"),
    ]
    out, _ = _run(rows)
    assert list(out["failed_logins_1m"]) == [1, 2, 3]


def test_state_carries_across_micro_batches():
    _, state = _run([("2026-09-20 14:00:00", "LOGIN_FAILURE", 0, "root")])
    out, _ = _run([("2026-09-20 14:00:10", "LOGIN_FAILURE", 0, "root")], state)
    assert out.iloc[0]["failed_logins_5m"] == 2


def test_history_older_than_five_minutes_is_evicted():
    _, state = _run([("2026-09-20 14:00:00", "LOGIN_FAILURE", 0, "root")])
    out, state = _run([("2026-09-20 14:06:00", "LOGIN_SUCCESS", 0, "root")], state)
    assert out.iloc[0]["failed_logins_5m"] == 0
    assert len(state.get[1]) == 1  # the old event is gone from state too
    assert WINDOW_5M_MS == 300_000


def test_port_scan_counts_distinct_ports():
    rows = [(f"2026-09-20 14:00:0{i}", "PORT_SCAN", p, "x") for i, p in enumerate([22, 22, 80, 443])]
    out, _ = _run(rows)
    last = out.iloc[-1]
    assert (last["port_scan_count_5m"], last["unique_ports_5m"]) == (4, 3)


def test_spray_counts_distinct_users():
    rows = [(f"2026-09-20 14:00:0{i}", "LOGIN_FAILURE", 0, u) for i, u in enumerate("abcde")]
    out, _ = _run(rows)
    assert out.iloc[-1]["unique_users_5m"] == 5


def test_timed_out_state_is_removed_and_emits_nothing():
    state = FakeState((["45.134.26.7"], [1], ["LOGIN_FAILURE"], [0], ["root"]))
    state.hasTimedOut = True
    out, state = _run([], state)
    assert state.removed and out.empty


def _v2_events(rows):
    """rows: dicts with ts plus any v2 fields."""
    base = {"source_ip": "45.134.26.7", "event_type": "HTTP_REQUEST", "target_port": 0,
            "user": "-", "http_status": 0, "bytes_sent": 0, "url_path": "",
            "is_sensitive_command": 0, "is_attack_signature": 0}
    out = []
    for r in rows:
        e = dict(base, **r)
        e["timestamp"] = pd.Timestamp(e.pop("ts"), tz="UTC")
        out.append(e)
    return pd.DataFrame(out)


def _run_v2(rows, state=None):
    state = state or FakeState()
    out = list(_update_bucket((0,), iter([_v2_events(rows)]), state))
    return pd.concat(out), state


def test_directory_brute_force_counts_404s_per_minute():
    rows = [{"ts": f"2026-09-20 14:00:{i:02d}", "http_status": 404, "url_path": f"/p{i}"} for i in range(30)]
    out, _ = _run_v2(rows)
    last = out.iloc[-1]
    assert last["http_404_1m"] == 30
    assert last["distinct_paths_5m"] == 30
    assert last["http_errors_5m"] == 30


def test_sensitive_commands_accumulate():
    """The privilege-escalation gap: 144 routine commands looked the same as
    144 hostile ones. Now the hostile ones are counted on their own."""
    rows = [{"ts": f"2026-09-20 14:00:0{i}", "event_type": "COMMAND_EXECUTION",
             "is_sensitive_command": 1 if i % 2 == 0 else 0} for i in range(6)]
    out, _ = _run_v2(rows)
    assert out.iloc[-1]["sensitive_commands_5m"] == 3


def test_exfiltration_volume_sums_bytes():
    rows = [{"ts": f"2026-09-20 14:00:0{i}", "http_status": 200, "bytes_sent": 90_000_000} for i in range(4)]
    out, _ = _run_v2(rows)
    assert out.iloc[-1]["bytes_sent_5m"] == 360_000_000


def test_widened_state_round_trips_across_batches():
    _, state = _run_v2([{"ts": "2026-09-20 14:00:00", "http_status": 404, "url_path": "/a"}])
    assert len(state.get) == 10  # ips + 9 record fields
    out, _ = _run_v2([{"ts": "2026-09-20 14:00:05", "http_status": 404, "url_path": "/b"}], state)
    assert out.iloc[0]["http_404_1m"] == 2


# --- bucketing: many sources share one state, each keeps its own window ----

def _mixed(rows):
    """rows: (source_ip, ts_ms, event_type) -- several sources in one bucket."""
    return pd.DataFrame([
        {"source_ip": ip, "timestamp": pd.Timestamp(ts, unit="ms", tz="UTC"),
         "event_type": et, "target_port": 0, "user": "root", "_feature_bucket": 0}
        for ip, ts, et in rows
    ])


def _run_bucket(rows, state=None):
    state = state or FakeState()
    out = list(_update_bucket((0,), iter([_mixed(rows)]), state))
    return (pd.concat(out) if out else pd.DataFrame()), state


def test_sources_sharing_a_bucket_keep_separate_windows():
    t = 1_790_000_000_000
    rows = [("1.1.1.1", t + i, "LOGIN_FAILURE") for i in range(5)]
    rows += [("2.2.2.2", t + i, "LOGIN_SUCCESS") for i in range(3)]
    out, _ = _run_bucket(rows)
    by_ip = out.groupby("source_ip")["failed_logins_5m"].max()
    assert by_ip["1.1.1.1"] == 5
    assert by_ip["2.2.2.2"] == 0
    assert out.groupby("source_ip")["requests_1m"].max().to_dict() == {"1.1.1.1": 5, "2.2.2.2": 3}


def test_bucket_column_is_not_emitted():
    out, _ = _run_bucket([("1.1.1.1", 1_790_000_000_000, "LOGIN_FAILURE")])
    assert "_feature_bucket" not in out.columns


def test_quiet_source_is_pruned_but_active_one_is_kept():
    t = 1_790_000_000_000
    _, state = _run_bucket([("1.1.1.1", t, "LOGIN_FAILURE"), ("2.2.2.2", t, "LOGIN_FAILURE")])
    # only 2.2.2.2 speaks again, 7 minutes later: 1.1.1.1 is past the horizon
    _, state = _run_bucket([("2.2.2.2", t + 7 * 60_000, "LOGIN_FAILURE")], state)
    assert set(state.get[0]) == {"2.2.2.2"}


@pytest.mark.parametrize("seed", range(4))
def test_bucketed_update_matches_one_window_per_source(seed):
    """Random interleaved sources, split into random micro-batches: every
    event's features equal those of a dedicated per-source RollingWindow."""
    rng = random.Random(seed)
    ips = [f"10.0.0.{i}" for i in range(6)]
    t, stream = 1_790_000_000_000, []
    for _ in range(600):
        t += rng.choice([0, 5, 400, 3_000, 20_000])
        stream.append((rng.choice(ips), t, rng.choice(["LOGIN_FAILURE", "LOGIN_SUCCESS", "PORT_SCAN"])))

    reference, expected = {}, []
    for ip, ts, et in stream:
        w = reference.setdefault(ip, RollingWindow())
        expected.append((ip, ts, w.add((ts, et, 0, "root", 0, 0, "", 0, 0))))

    state, got, i = FakeState(), [], 0
    while i < len(stream):
        n = rng.randint(1, 80)
        out, state = _run_bucket(stream[i:i + n], state)
        got.append(out)
        i += n
    got = pd.concat(got)

    names = [name for name, _ in FEATURE_FIELDS]
    actual = sorted(
        (r.source_ip, pd.Timestamp(r.timestamp).value // 1_000_000, tuple(getattr(r, n) for n in names))
        for r in got.itertuples()
    )
    wanted = sorted((ip, ts, tuple(f[n] for n in names)) for ip, ts, f in expected)
    assert actual == wanted
