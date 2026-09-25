"""DetectPerSource's state handling, driven directly with stand-ins for
Flink's state, timers and metrics -- to control processing time, which a
mini-cluster run cannot.

Background: window records once carried a state TTL of their own and
expired under a summary that still pointed at them; the live job crashed
('NoneType' object is not subscriptable). The window now has no TTL and a
timer clears a source's state all at once. These stand-ins do not model
Flink's TTL, so they pin the REPLACEMENT: an active source loses nothing,
an idle one loses everything, together.
"""

from datetime import datetime, timedelta, timezone

import pytest

from conftest import make_event

pytest.importorskip("pyflink")

from core.records import enrich, normalize, reject_reason  # noqa: E402
from stream.job import IDLE_MS, TIMER_BUCKET_MS, DetectPerSource, _idle_check_at  # noqa: E402

pytestmark = pytest.mark.flink

MIN = 60 * 1000
T0 = datetime(2026, 9, 20, 14, 0, 0, tzinfo=timezone.utc)


class Value:
    def __init__(self):
        self.v = None

    def value(self):
        return self.v

    def update(self, v):
        self.v = v

    def clear(self):
        self.v = None


class Map(dict):
    def put(self, k, v):
        self[k] = v

    def remove(self, k):
        self.pop(k, None)

    def contains(self, k):
        return k in self


class Metrics:
    def add_group(self, _):
        return self

    def counter(self, _):
        class C:
            n = 0

            def inc(self, k=1):
                self.n += k

            def dec(self, k=1):
                self.n -= k

        return C()

    def gauge(self, *_):
        raise AssertionError(
            "no Python gauges: in thread mode the reporter thread calls back "
            "into the interpreter and crashes the TaskManager (see PushedGauge)"
        )


class Runtime:
    """One source's state (the key is implicit, as in Flink)."""

    def __init__(self):
        self.states = {}

    def get_state(self, d):
        return self.states.setdefault(d.name, Value())

    def get_map_state(self, d):
        return self.states.setdefault(d.name, Map())

    def get_metrics_group(self):
        return Metrics()


class Ctx:
    def __init__(self, key="45.134.26.7"):
        self.key = key
        self.now = 0
        self.timers = set()
        svc = self

        class Timers:
            def current_processing_time(self):
                return svc.now

            def register_processing_time_timer(self, ts):
                svc.timers.add(ts)

        self.service = Timers()

    def timer_service(self):
        return self.service

    def get_current_key(self):
        return self.key


def event(seconds, **kw):
    e = {k: v for k, v in make_event(
        source_ip="45.134.26.7", event_type="LOGIN_FAILURE",
        timestamp=(T0 + timedelta(seconds=seconds)).isoformat(), **kw).items() if k != "scenario"}
    assert reject_reason(e) is None
    e = enrich(normalize(e))
    e["_kafka_ms"] = 0
    return e


@pytest.fixture
def op():
    fn, rt, ctx = DetectPerSource(), Runtime(), Ctx()
    fn.clock = lambda ctx: ctx.now          # drive processing time from the test
    fn.open(rt)
    return fn, rt, ctx


def feed(fn, ctx, e):
    return list(fn.process_element(e, ctx))


def test_a_source_kept_alive_past_15_minutes_keeps_its_whole_window(op):
    """The crash: events every 4 minutes of event time, arriving over 40
    minutes of wall time. Each record is needed until 5 minutes of EVENT
    time pass; nothing may disappear because of WALL time."""
    fn, rt, ctx = op
    for i in range(10):
        ctx.now = i * 4 * MIN
        out = feed(fn, ctx, event(i * 240))
        assert len(out) == 1
    for ts in sorted(ctx.timers):          # every idle check fires: none may clear
        if ts <= ctx.now:
            fn.on_timer(ts, ctx)
    assert rt.states["window_summary"].value() is not None
    ctx.now += MIN
    assert feed(fn, ctx, event(10 * 240))  # would crash if a record vanished


def test_an_idle_source_is_cleared_completely(op):
    fn, rt, ctx = op
    for i in range(5):
        ctx.now = i * 1000
        feed(fn, ctx, event(i))
    assert rt.states["window_records"] and rt.states["window_summary"].value()["recent_ids"]

    fn.on_timer(ctx.now + IDLE_MS + MIN, ctx)
    assert rt.states["window_summary"].value() is None
    assert not rt.states["window_records"]
    assert not any(rt.states[f"window_{k}"] for k in ("users", "ports", "paths"))

    # and it starts over cleanly
    ctx.now += IDLE_MS + 2 * MIN
    import json
    row = json.loads(feed(fn, ctx, event(10_000))[0])
    assert row["failed_logins_5m"] == 1


def test_an_early_timer_does_not_clear_an_active_source(op):
    fn, rt, ctx = op
    ctx.now = 0
    feed(fn, ctx, event(0))
    ctx.now = 10 * MIN
    feed(fn, ctx, event(600))
    fn.on_timer(16 * MIN, ctx)             # set by the first event; source touched since
    assert rt.states["window_summary"].value() is not None


def test_timers_are_coalesced_per_minute(op):
    fn, rt, ctx = op
    for i in range(300):                   # 300 events inside one minute
        ctx.now = i * 100
        feed(fn, ctx, event(i))
    assert len(ctx.timers) == 1


def test_latency_gauges_are_pushed_not_called_back(op):
    fn, rt, ctx = op
    for i in range(3):
        ctx.now = i * 1000
        feed(fn, ctx, event(i))
    # Pushes are rate-limited to once per second of wall time; force one
    # rather than depend on how fast the events above ran.
    fn._push_metrics(fn.pushed_at + 10**6)
    window, p50, p95, top = fn.latency_gauges[1]
    assert p50._counter.n == window.quantile(0.5) and top._counter.n == window.max()


def test_idle_checks_are_spread_over_the_minute_not_on_its_boundary():
    """All sources on the same boundary fired ~1,800 timers at once, once a
    minute: a latency spike. Each source gets its own offset."""
    now = 1_790_000_000_000
    offsets = {_idle_check_at(now, f"10.0.{i // 250}.{i % 250}") % TIMER_BUCKET_MS for i in range(1780)}
    assert len(offsets) > 1500
    for key in ("1.2.3.4", "45.134.26.7"):
        at = _idle_check_at(now, key)
        assert now + IDLE_MS < at <= now + IDLE_MS + TIMER_BUCKET_MS
        # stable: same key, same minute -> same timer (so timers coalesce)
        assert at == _idle_check_at(now + 1000, key) or at + TIMER_BUCKET_MS == _idle_check_at(now + 1000, key)


def test_counters_are_batched_and_flushed(op):
    """counter.inc() is a JVM call per event; counts accumulate in Python
    and reach Flink on the once-a-second push."""
    fn, rt, ctx = op
    for i in range(5):
        ctx.now = i * 1000
        feed(fn, ctx, event(i))
    fn._push_metrics(fn.pushed_at + 10**6)
    assert fn.scored._counter.n == 5 and fn.scored._pending == 0


def test_an_idle_timer_is_registered_once_per_minute_not_per_event(op):
    fn, rt, ctx = op
    calls = []
    real = ctx.service.register_processing_time_timer
    ctx.service.register_processing_time_timer = lambda ts: (calls.append(ts), real(ts))
    for i in range(300):                   # 300 events in one minute
        ctx.now = i * 100
        feed(fn, ctx, event(i))
    assert len(calls) == 1


def test_recent_ids_catch_a_redelivery_and_stay_bounded(op):
    from stream.job import RecentIds

    fn, rt, ctx = op
    first = event(0)
    assert feed(fn, ctx, dict(first))
    assert feed(fn, ctx, dict(first)) == []          # redelivered: dropped
    for i in range(1, RecentIds.SIZE + 5):
        ctx.now = i
        feed(fn, ctx, event(i))
    ring = rt.states["window_summary"].value()["recent_ids"]
    assert len(ring) == RecentIds.SIZE * 8           # bounded: 8 bytes per id
    assert feed(fn, ctx, dict(first))                # beyond the horizon: scored again
