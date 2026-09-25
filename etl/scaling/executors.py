"""
Executor autoscaling for the streaming query: executor pods are added when
the pipeline falls behind the live stream, and removed when it idles.

WHY NOT spark.dynamicAllocation
-------------------------------
Spark's dynamic allocation scales on TASK BACKLOG and releases an executor
only after it has been idle for executorIdleTimeout. A streaming query
never lets that happen: every micro-batch schedules a task on every
executor -- Kafka tasks prefer the executor holding their cached consumer,
stateful tasks prefer the executor holding their state store -- so no
executor is ever idle and the pool only grows. (Upstream: SPARK-24815,
"Structured Streaming should support dynamic allocation", still open.)
DStreams solved this with a policy on batch time vs batch interval;
Structured Streaming never got one. This module is that policy.

THE SIGNAL
----------
load = last batch duration / trigger interval. Every trigger, Spark reads
whatever arrived since the last one; a batch that takes longer than the
trigger means data arrives faster than it is processed. Kafka lag (read
from the same progress event) catches the other case: batches capped by
maxOffsetsPerTrigger, which look on time while the backlog grows.

    hot  : load >= up_load  OR  lag >= lag_high      (for up_after batches)
    cold : load <= down_load AND lag <= lag_low      (for down_after batches)

Up is proportional (like the Kubernetes HPA): a batch at 3x the trigger
asks for enough executors to bring it to the target, not for one more.
Down is ONE executor at a time: each removal moves its state stores to the
survivors (they reload from the checkpoint), so shrinking is the expensive
direction. After any change, `cooldown` batches are ignored -- new
executors start cold, and the first batch after a change is not
representative.

ACTUATION
---------
SparkContext.requestTotalExecutors / killExecutors, the developer API the
built-in allocation manager uses, which requires dynamic allocation OFF.
On Kubernetes, the driver then creates or deletes the executor pods.
Executors that cannot be scheduled stay Pending -- the cluster's size is
the real ceiling, `max_executors` only the configured one.
"""

import json
import math
import queue
import threading
from dataclasses import dataclass, field


@dataclass
class ScalingPolicy:
    min_executors: int
    max_executors: int
    trigger_seconds: float
    target_load: float = 0.6
    up_load: float = 0.8
    down_load: float = 0.3
    lag_high: int = 20_000
    lag_low: int = 2_000
    up_after: int = 2
    down_after: int = 6
    cooldown: int = 3

    _hot: int = field(default=0, init=False)
    _cold: int = field(default=0, init=False)
    _quiet: int = field(default=0, init=False)

    def __post_init__(self):
        if not 1 <= self.min_executors <= self.max_executors:
            raise ValueError(
                f"need 1 <= min <= max executors, got {self.min_executors}..{self.max_executors}"
            )

    def decide(self, current, batch_seconds, lag):
        """Given one finished batch, return the executor count to run, or
        None to leave it alone."""
        if self._quiet > 0:
            self._quiet -= 1
            return None

        load = batch_seconds / self.trigger_seconds
        hot = load >= self.up_load or lag >= self.lag_high
        cold = load <= self.down_load and lag <= self.lag_low
        self._hot = self._hot + 1 if hot else 0
        self._cold = self._cold + 1 if cold else 0

        desired = None
        if self._hot >= self.up_after and current < self.max_executors:
            desired = max(current + 1, math.ceil(current * load / self.target_load))
        elif self._cold >= self.down_after and current > self.min_executors:
            desired = current - 1

        if desired is None:
            return None
        desired = min(self.max_executors, max(self.min_executors, desired))
        if desired == current:
            return None
        self._hot = self._cold = 0
        self._quiet = self.cooldown
        return desired


class SparkExecutors:
    """The actuator: adds and removes executors of a running SparkContext."""

    def __init__(self, spark_context):
        self._sc = spark_context._jsc.sc()
        self._utils = spark_context._jvm.org.apache.spark.api.python.PythonUtils

    def ids(self):
        """Registered executor ids -- not counting pods still Pending."""
        seq = self._sc.getExecutorIds()
        return sorted((str(seq.apply(i)) for i in range(seq.size())), key=int)

    def scale_to(self, target):
        ids = self.ids()
        if target < len(ids):
            # Remove the NEWEST executors: the oldest hold the most
            # warmed-up state stores and Kafka consumers. Their running
            # tasks are retried elsewhere, not counted as failures.
            self._sc.killExecutors(self._utils.toSeq(ids[target:]))
        # Then set the exact total -- which also cancels pods still Pending
        # from an earlier scale-up that the cluster never had room for.
        return bool(self._sc.requestTotalExecutors(target, 0, self._utils.toScalaMap({})))


class ExecutorAutoscaler:
    """Feeds one query's progress to the policy; applies decisions off the
    listener thread, so a slow pod deletion never blocks Spark's event bus."""

    def __init__(self, policy, executors, query_name="events", metrics=None):
        self.policy = policy
        self.executors = executors
        self.query_name = query_name
        self.metrics = metrics
        self.target = policy.min_executors
        self._decisions = queue.Queue()
        threading.Thread(target=self._apply_loop, name="executor-autoscaler", daemon=True).start()
        self._publish()

    def on_progress(self, progress):
        if progress.get("name") != self.query_name:
            return
        batch_ms = (progress.get("durationMs") or {}).get("triggerExecution") or 0
        lag = 0
        for source in progress.get("sources") or []:
            behind = (source.get("metrics") or {}).get("maxOffsetsBehindLatest")
            lag = max(lag, int(float(behind))) if behind is not None else lag

        desired = self.policy.decide(self.target, batch_ms / 1000.0, lag)
        self._publish()
        if desired is None:
            return
        print(
            f"[autoscaler] batch {batch_ms / 1000:.1f}s of {self.policy.trigger_seconds:.0f}s trigger,"
            f" lag {lag:,} -> executors {self.target} -> {desired}",
            flush=True,
        )
        direction = "up" if desired > self.target else "down"
        self.target = desired
        if self.metrics:
            self.metrics.SCALING_DECISIONS.labels(direction).inc()
        self._decisions.put(desired)

    def _apply_loop(self):
        while True:
            target = self._decisions.get()
            try:
                self.executors.scale_to(target)
            except Exception as exc:  # scaling must never kill the stream
                print(f"[autoscaler] scale_to({target}) failed: {exc}", flush=True)
            self._publish()

    def _publish(self):
        if not self.metrics:
            return
        self.metrics.EXECUTORS_TARGET.set(self.target)
        self.metrics.EXECUTORS_MAX.set(self.policy.max_executors)
        try:
            self.metrics.EXECUTORS_ACTIVE.set(len(self.executors.ids()))
        except Exception:
            pass

    def listener(self):
        from pyspark.sql.streaming import StreamingQueryListener

        scaler = self

        class _Listener(StreamingQueryListener):
            def onQueryStarted(self, event):
                pass

            def onQueryProgress(self, event):
                try:
                    scaler.on_progress(json.loads(event.progress.json))
                except Exception as exc:
                    print(f"[autoscaler] progress ignored: {exc}", flush=True)

            def onQueryIdle(self, event):
                pass

            def onQueryTerminated(self, event):
                pass

        return _Listener()
