"""scaling/executors: the executor autoscaling policy, and the autoscaler
driving a fake actuator from real-shaped progress events."""

import time

import pytest

from observability import metrics
from scaling.executors import ExecutorAutoscaler, ScalingPolicy


def policy(**kw):
    return ScalingPolicy(**{"min_executors": 1, "max_executors": 4, "trigger_seconds": 20.0, **kw})


def feed(p, current, batches):
    """Run (batch_seconds, lag) pairs through the policy, following its
    decisions like the autoscaler does; return the counts over time."""
    seen = []
    for seconds, lag in batches:
        desired = p.decide(current, seconds, lag)
        if desired is not None:
            current = desired
        seen.append(current)
    return seen


def test_steady_load_under_the_trigger_changes_nothing():
    assert feed(policy(), 1, [(10.0, 500)] * 20) == [1] * 20


def test_one_slow_batch_is_not_enough_to_scale():
    assert feed(policy(), 1, [(19.0, 0), (5.0, 0), (19.0, 0)]) == [1, 1, 1]


def test_sustained_overload_scales_up_proportionally():
    # 2 batches at 3x the trigger: 1 executor * 3.0 / 0.6 = 5 -> capped at 4
    assert feed(policy(), 1, [(60.0, 0), (60.0, 0)]) == [1, 4]


def test_mild_overload_adds_at_least_one():
    assert feed(policy(), 2, [(17.0, 0), (17.0, 0)]) == [2, 3]


def test_growing_lag_scales_up_even_when_batches_look_on_time():
    """maxOffsetsPerTrigger caps batch size: batches stay short while the
    backlog grows. Lag alone must trigger the scale-up."""
    assert feed(policy(), 1, [(8.0, 50_000), (8.0, 60_000)]) == [1, 2]


def test_cooldown_ignores_batches_right_after_a_change():
    p = policy(cooldown=3)
    seen = feed(p, 1, [(20.0, 0), (20.0, 0)] + [(40.0, 0)] * 3 + [(40.0, 0)] * 2)
    # up at batch 2; the next 3 are ignored; 2 more hot batches -> up again
    assert seen == [1, 2, 2, 2, 2, 2, 4]


def test_scale_down_is_slow_and_one_at_a_time():
    p = policy(down_after=6, cooldown=3)
    seen = feed(p, 4, [(2.0, 100)] * 20)
    assert seen[:5] == [4] * 5
    assert seen[5] == 3                       # after 6 cold batches
    assert all(b - a in (0, -1) for a, b in zip(seen, seen[1:]))
    assert seen[-1] >= 1


def test_bounds_are_respected():
    assert feed(policy(max_executors=2), 1, [(100.0, 10**6)] * 10)[-1] == 2
    assert feed(policy(min_executors=2), 3, [(0.5, 0)] * 40)[-1] == 2


def test_a_backlog_blocks_scale_down():
    # batches are fast but the lag is not drained: not cold
    assert feed(policy(), 3, [(2.0, 10_000)] * 20) == [3] * 20


def test_invalid_bounds_are_rejected():
    with pytest.raises(ValueError):
        policy(min_executors=0)
    with pytest.raises(ValueError):
        policy(min_executors=5, max_executors=4)


class FakeExecutors:
    def __init__(self, n):
        self.n = n
        self.calls = []

    def ids(self):
        return [str(i) for i in range(1, self.n + 1)]

    def scale_to(self, target):
        self.calls.append(target)
        self.n = target
        return True


def progress(name, batch_ms, lag):
    return {
        "name": name,
        "durationMs": {"triggerExecution": batch_ms},
        "sources": [{"metrics": {"maxOffsetsBehindLatest": str(lag)}}],
    }


def _wait_for(pred, timeout=2.0):
    end = time.time() + timeout
    while time.time() < end:
        if pred():
            return True
        time.sleep(0.01)
    return pred()


def test_autoscaler_acts_on_the_events_query_only():
    fake = FakeExecutors(1)
    scaler = ExecutorAutoscaler(policy(), fake, query_name="events", metrics=metrics)
    for _ in range(3):
        scaler.on_progress(progress("rejected", 60_000, 0))
    assert fake.calls == []

    scaler.on_progress(progress("events", 60_000, 0))
    scaler.on_progress(progress("events", 60_000, 0))
    assert _wait_for(lambda: fake.calls == [4])
    assert scaler.target == 4
    assert _wait_for(lambda: metrics.EXECUTORS_ACTIVE._value.get() == 4)
    assert metrics.EXECUTORS_TARGET._value.get() == 4
