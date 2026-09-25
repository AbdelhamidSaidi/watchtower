"""Rolling latency percentiles, cheap enough to update on every event.

Flink's Python metrics offer counters and gauges but no histogram that
reaches Prometheus, so the operator keeps the last N samples here and
exposes p50/p95/max as gauges, computed only when Prometheus scrapes.
"""

from collections import deque


class LatencyWindow:
    def __init__(self, size=2000):
        self.samples = deque(maxlen=size)

    def add(self, ms):
        self.samples.append(ms)

    def quantile(self, q):
        if not self.samples:
            return 0
        ordered = sorted(self.samples)
        return ordered[min(len(ordered) - 1, int(q * len(ordered)))]

    def max(self):
        return max(self.samples, default=0)
