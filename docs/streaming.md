# Watchtower — the streaming path (Flink)

Every build-farm event is decided **the moment it arrives**, not at the next
micro-batch. This document covers what that changed, what latency remains
and where it comes from, and how the path scales.

> **Measured on the earlier workload.** The latency, per-event cost and
> throughput figures below were taken when the events were security logs
> (logins, requests, commands). On 2026-10-01 the events became build logs: a
> different set of fields and features, the same path -- Kafka, one keyed Flink
> operator, the ClickHouse Kafka engine -- and per-event work of the same
> shape. They should carry over; they have not been re-measured.

## 1. Why the engine changed

The first pipeline ran on Spark Structured Streaming: events were collected
for a trigger interval (20 s) and processed together. An event therefore
waited up to a whole interval before anything looked at it, then for the
batch to run:

| | Spark, 20 s trigger |
|---|---|
| wait for the trigger | 0–20 s (10 s on average) |
| batch processing | 4.6 s at 100 events/s |
| **end to end** | **~5–25 s, typically ~15 s** |
| at 1,000 events/s | fell behind: batches 13 s → 229 s, latency unbounded |

Shortening the trigger shrinks the wait but not the model: every event
still waits for the batch it lands in. Spark's per-event modes (Continuous
Processing, and Spark 4.1's Real-Time Mode) only support stateless
queries, and detection needs per-runner state (dedup, rolling windows).
Apache Flink processes one event at a time with keyed state as a
first-class feature, so the live path moved to Flink.

The detection logic did **not** change. It moved into `etl/core/` — plain
Python, no engine — and both engines run it:

```
etl/core/     vocab, indicators, records (decode/validate/normalize/enrich),
              window (RollingWindow), rules, ml (the model, compiled),
              dq (checks between steps), processor (dedup+features+rules+model)
etl/stream/   the Flink job, and models.py (the active model, from ClickHouse)
```

The Spark job that preceded Flink was removed on 2026-09-28: one engine.

## 2. The job

```
Kafka security-logs
  -> parse + validate + normalize + enrich        per event, stateless
       \-> dead letters -> Kafka security-logs-rejected -> rejected_events
  -> keyBy(runner_ip)                             one network hop
  -> dedup + rolling features + rules             per event, keyed state
  -> Kafka security-events-scored
  -> ClickHouse Kafka engine (50 ms blocks) -> MV -> security_events
```

- **Order.** Features assume a runner's events arrive in event-time order.
  The producer keys Kafka messages by `runner_ip`, so a runner is one
  partition, read by one source subtask; parsing is chained to the source
  (same parallelism, no rebalance), so every event of a runner reaches the
  keyed operator through one path.
- **State.** Per runner: a small summary (running sums, sizes, three
  positions in a record log), the window's records, the distinct
  project/exit-code/artifact counts, and the event_ids seen in the last 10 minutes —
  each as its own Flink state, so an event touches a handful of entries,
  never the whole window. (The first version stored one pickled object per
  runner and fell behind once windows filled: every event re-serialised its
  runner's entire window, 12,000 records for a 30-events/s failure storm.)
- **Forgetting a runner.** A processing-time timer clears ALL of a runner's
  state at once after 15 idle minutes. Not a state TTL: a TTL expires each
  entry on its own, and a window record can outlive its write time by more
  than 15 minutes while the summary pointing at it is fresh (a backlog
  replays hours of event time in minutes of wall time, and the reverse).
  That happened once, live: a record expired under a live summary and the
  job crashed on the next event of that runner.
- **Python in the JVM.** PyFlink runs in *thread* mode: Python is embedded
  in the TaskManager JVM and every state access is an in-process call. In
  the default *process* mode each state read that misses a cache is a gRPC
  round trip to a separate Python worker; at 1,000 events/s those round
  trips, not the detection code, capped the job at ~600 events/s.
- **One slot per TaskManager.** In thread mode every slot of a TaskManager
  shares one interpreter and its GIL, so slots do not add capacity -- they
  subtract it: 1 slot ~2,000 events/s (full windows), 2 slots ~1,150/s,
  4 slots ~450/s. Capacity is added with TaskManagers.
- **Delivery.** At-least-once end to end. Kafka offsets are checkpointed
  with the keyed state every 10 s (`AT_LEAST_ONCE` checkpoints: no barrier
  alignment, so a checkpoint never holds events back); the Kafka sink
  flushes on every checkpoint; ClickHouse's Kafka engine commits only after
  inserting. A replay can repeat rows; `security_events` is a
  ReplacingMergeTree, so they collapse on merge.
- **Why Kafka, not a direct ClickHouse insert.** ClickHouse wants inserts
  in blocks. Its Kafka engine does that batching on its side, commits only
  what it inserted, and keeps a ClickHouse outage from back-pressuring
  detection. A row it cannot parse goes to `rejected_events` as
  `sink_parse_error` instead of stalling the consumer.
- **The model.** A LightGBM model scores every event after the rules, in
  the same operator, compiled to plain Python when loaded: ~5 µs per
  event. It is picked up from ClickHouse within 5 minutes of promotion,
  without a restart; `WATCHTOWER_ML=off` switches it off. The LLM (Groq)
  never scores live — a remote call per event would stall the stream — it
  reviews passed events hourly, offline ([`orchestration.md`](orchestration.md)).

### Data quality between the steps

Every event is checked at each boundary it crosses (`etl/core/dq.py`),
without being changed or dropped:

| after | counted as `dq_<step>_<issue>` | meaning |
|---|---|---|
| validate | the reject reason | refused (dead-letter), by reason |
| normalize | `severity_defaulted`, `missing_project`, `missing_hostname` | kept, but a field was blank or unknown |
| enrich | `unknown_region`, `future_timestamp`, `stale_timestamp` | an external runner the inventory cannot place; event time > 5 min ahead or > 1 day behind the job's clock |
| features | `window_inconsistent` | a 1-minute count above its 5-minute one: a bug or corrupted state |
| rules | `score_out_of_range`, `action_mismatch` | the decision contradicts its score: a bug |

The checks are comparisons on fields already in hand, counted with the
job's batched counters (pushed once a second). Estimated at 1–2 µs per
event against ~173 µs, not measured separately. Clean synthetic traffic
keeps every counter at 0.

Watched three ways: the Grafana panel *Data quality between steps*; the
alerts `StreamDataQualityDegraded` (> 1% of events doubtful for 10 min)
and `StreamLogicInconsistent` (any contradiction, critical); and the
Airflow pipeline DAG's `transform` stage (`doubtful_share` warns,
`logic_inconsistent` fails).

## 3. Latency

### Capacity (one TaskManager, one slot, one interpreter)

| | events/s |
|---|---|
| detection logic alone (`etl/core`, no Flink) | 6,300 (158 µs/event) |
| whole job, empty state (mini-cluster benchmark) | 3,800 (263 µs/event) |
| whole job live, windows filling | ~3,400 |
| whole job live, only Kafka + Flink running | ~4,300 |
| whole job live, with ClickHouse running too | ~2,500–4,000 |

At 1,000 events/s one TaskManager has 2.5–4x headroom. (Earlier figures
of ~1,150–1,300/s were the job starved by a swapping VM, see below.)

### Measured end to end (dev, 1,000 events/s, 24 minutes of steady state)

Event **created** by the producer → row **stored** in ClickHouse
(`ingested_at - timestamp`), 48 consecutive 30-second samples, every
runner's 5-minute window full:

| | median | p95 | p99 | worst event |
|---|---|---|---|---|
| **end to end** | **194 ms** (samples 186–204) | **346 ms** (335–436) | 440 ms | 1.3 s |
| of which: Kafka → decision (the job) | **5 ms** | 16 ms | | |

Against the Spark pipeline: ~15 s typical at 100 events/s, and unbounded
at 1,000/s. Most of what remains is the ClickHouse insert block
(`kafka_flush_interval_ms=250`); the decision itself is in the
`security-events-scored` topic within milliseconds.

**What the numbers needed from the machine.** The first measurements
swung between 0.3 s and several seconds, and none of it was the job: the
~4 GB Docker VM was out of memory and swapping. Fixed in dev:

- ClickHouse capped (`clickhouse/config/dev-limits.xml`): a 64 MB mark
  cache instead of 5 GB, 4 concurrent merges instead of 16, a 1.6 GB
  backstop (checked against RSS, which runs ~2x tracked memory -- a 768 MB
  cap made it refuse its own merges).
- ClickHouse's internal `metric_log` (and similar diagnostic logs)
  switched off: one column per metric, over a thousand, and merging it
  needed more memory than the VM had -- it failed and retried endlessly.
  Prometheus scrapes the same metrics.
- Kafka's healthcheck is a port check; `kafka-broker-api-versions.sh`
  started a ~200 MB JVM every 10 s.
- Flink sized to use: JobManager 640 MB, TaskManager 1,280 MB with 5%
  managed memory (thread mode and heap state use none).

Two other suspects were tested and ruled out: checkpoints (58 MB every
10 s; 60 s made no difference) and the idle-check timers (spreading them
over the minute made no difference, but is kept: 1,800 timers on one
millisecond is a burst worth avoiding).

Where the remaining time goes, in order:

| stage | setting | bound |
|---|---|---|
| producer → Kafka | `linger_ms=5` | ≤ 5 ms |
| Flink network buffers | `WATCHTOWER_BUFFER_TIMEOUT_MS=5` (default 100) | ≤ 5 ms per hop |
| JVM → Python | thread mode: no bundles | — |
| Flink → Kafka | `linger.ms=5` | ≤ 5 ms |
| Kafka → ClickHouse | `kafka_flush_interval_ms=50`, `kafka_poll_timeout_ms=10` (was 250/100) | ≤ ~60 ms |

The ClickHouse block interval is the largest remaining wait, and it is
deliberate: smaller blocks mean more parts for ClickHouse to merge. The
*decision* itself (Kafka → scored) is available before that, in the
`security-events-scored` topic, for anything that must react faster than
storage.

Measure it:

```bash
make latency        # dev: p50/p95/p99 over the last minute, from ClickHouse
```

`watchtower_kafka_to_scored_p50_ms` / `_p95_ms` (Flink TaskManager metrics)
give the job's own share; `watchtower_event_age_*` include the source's delay
before Kafka.

### Toward 100 ms (50 ms ClickHouse blocks)

With the ClickHouse Kafka consumer flushing every 50 ms (was 250) and
polling every 10 ms, the end-to-end median measured **66-84 ms** in 30-second
windows while the machine was not swapping, against ~194 ms before.

On the ~3.8 GB Docker VM it does not hold: 20 inserts/s into the
re-laid-out table raised ClickHouse's resident memory to ~1.3-1.4 GB, the VM
swapped again (TaskManager 254 MB and ClickHouse 174 MB in swap), and
whenever a swapped page was needed the job fell seconds behind -- the
3-minute median was 2.7 s. The configuration is right for a machine with
~2 GB more for Docker; on this one, sub-100 ms is not stable.

### Per-event cost, and sizing for 10,000 events/s

Where a single event's time goes (one TaskManager, full 5-minute windows):

| part | µs/event |
|---|---|
| the transformation itself -- decode 10.7, validate 1.0, normalize 1.8, enrich 2.5, dedup+window+rules 12.5, JSON 7.5 | **~36** |
| PyFlink plumbing -- each record crossing Python ↔ JVM, the keyBy hop | ~85 |
| Flink state and runtime calls from Python, each ~5-30 µs | ~70 → ~50 |

The Python itself is cheap (~28,000 events/s per core); PyFlink's per-call
overhead is what costs. Measured per call: a TTL map `contains` 30 µs, a
map `remove` 23 µs, a TTL map `put` 16 µs, a map `get` 9 µs, the timer
service's clock 7 µs, `counter.inc()` ~13 µs. So the optimisation was to
make fewer calls, not faster Python:

| change | effect |
|---|---|
| each window's head record cached in the summary | window reads 5.9 → 1.9 per event |
| distinct project/exit-code/artifact counts inside the summary until one exceeds 64 entries | 4.7 map calls → 0 for ordinary runners |
| counters batched, pushed once a second | 2 JVM calls → 0 per event |
| idle timer registered once per runner-minute, not per event | 1 → ~0 |
| dedup from a ring of the last 1,024 id hashes in the summary, not a TTL'd map | 2 TTL calls (~46 µs) → 0 |
| wall clock read in Python | 1 → 0 |

State calls per event went from 16.5 to ~8; the whole job, isolated on a
mini-cluster, from 189 to 173 µs per event (~5,100 → ~5,800 events/s). Not
done: fusing parse into the keyed operator (key by the Kafka message key)
measured another -18 µs (~10%), but makes "every producer keys by
runner_ip" a hard requirement; the windows would silently mix runners if one
did not.

**Capacity per TaskManager, reading from Kafka** (`tools/drain_test.sh`,
Kafka + Flink only):

| TaskManagers | events/s decided |
|---|---|
| 1 | ~4,100 |
| 2 | ~5,500 (on one 8-vCPU laptop VM shared with Kafka; not a clean 2x) |

**Sizing for 10,000 events/s** (prod overlay): 10,000 / (4,100 × 0.6
target utilisation) ≈ 4.1 → the job starts at **5 TaskManagers**
(1 slot, 1 CPU, 2 GiB each); the autoscaler may take it to **24**, the
input topic's partition count (24 in prod). Kafka brokers 3–6 (HPA),
ClickHouse 4 GiB / 2 CPU. Latency at that rate should stay near the
~70–90 ms measured without swap, because each TaskManager runs at ≤60% --
**not measured**: this laptop cannot run 10,000 events/s (its RAM caps the
full stack at ~1,200/s). Linear scaling across TaskManagers is expected on
separate nodes (keyed state is partitioned, nothing is shared) but was only
measured up to 2, on one machine.

## 4. Scaling

Two independent autoscalers, both on Kubernetes (staging and prod):

| what | who scales it | signal | bounds (staging / prod) |
|---|---|---|---|
| Flink TaskManagers | Flink Kubernetes Operator's job autoscaler | each operator's busy time + the Kafka source's backlog; target 60% busy, backlog cleared within 2 min | 1–3 / 5–24 |
| Kafka brokers | HorizontalPodAutoscaler on the broker KafkaNodePool | broker CPU, 70% of request | 1–2 / 3–6 |

- The Flink autoscaler sizes each operator separately; with one slot per
  TaskManager, pods follow parallelism one for one. The source never goes
  above the topic's partition count.
- A new broker joins empty. Cruise Control's auto-rebalance moves
  partitions onto it after it joins and **off** a broker before Strimzi
  removes it — without the second half, a scale-down would delete the
  only copy of what the broker held.

```bash
make watch-scaling     # TaskManagers, parallelism, brokers, lag, latency
make load RATE=3000    # change the load without a redeploy
```

## 5. Running it

Dev (docker compose): `make dev-up`, then `docker compose --profile sim up -d
producer`. Flink UI on http://localhost:8082, job metrics on :9250.
Existing ClickHouse volumes need `make ch-migrate` once for
`03_streaming_ingest.sql`.

The JobManager resumes from the newest completed checkpoint on restart
(`docker/flink/run-job.sh`); on Kubernetes the operator does the same with
Kubernetes HA (`upgradeMode: last-state`).

**A state-layout change needs a checkpoint reset** — Flink cannot map old
state onto new descriptors. Dev: `docker compose stop flink-jobmanager
flink-taskmanager`, empty the `flink-checkpoints` volume, start again. The
job resumes from the consumer group's committed offsets, so no event is
skipped; only the rolling windows start empty.

## 6. Model scoring cost (`tools/bench_model.py`, Flink image, one event per call)

| backend | 200 trees × 31 leaves: p50 / p99 | 100 trees × 15 leaves: p50 / p99 | notes |
|---|---|---|---|
| `lightgbm` Booster.predict | 24.7 / 339 µs | 19.5 / 322 µs | built for batches: a 300 µs tail on single rows |
| ONNX Runtime | 10.4 / 12.8 µs | 6.8 / 9.5 µs | its converter upgrades protobuf and cloudpickle past what PyFlink needs |
| **compiled to Python** (`core/ml.py`) | 16.2 / 21.7 µs | **5.4 / 7.7 µs** | no library at scoring time; identical output to LightGBM |
| tl2cgen (C) | — | — | no wheel for arm64; builds from source only |

Training is sized for the stream (≤ 120 trees × 15 leaves), so the model
costs ~3% of the job's ~173 µs per event.

## 7. Known limits

- **Image size.** The Flink image is ~3 GB: PyFlink pulls Apache Beam,
  PyArrow and pandas. Most of it is unused by the job.
- **Java 11.** Thread mode needs it (PEMJA reads a JDK field removed after
  11); Flink 2.2 supports 11, 17 and 21. It also needs the shared
  libpython (Ubuntu's python3 binary is statically linked).
- **One interpreter per TaskManager.** See §2: scale with TaskManagers,
  never with slots.
- **No Python gauges in thread mode.** A PyFlink gauge is read by calling
  back into the embedded interpreter from the metrics reporter's thread;
  a Prometheus scrape did exactly that while the task thread was running
  Python, and the TaskManager died with SIGSEGV in libpython. Metrics the
  job computes (the latency percentiles) are pushed into counters from
  the task thread instead (`PushedGauge` in `stream/job.py`); the tests
  fail if a gauge is registered.
- **One node.** Checkpoints and HA metadata sit on a ReadWriteOnce volume,
  which works because every pod shares the k3d node. Across nodes they
  belong in object storage (s3://).
