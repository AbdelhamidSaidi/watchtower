# Watchtower — project context

Build-log (compilation log) processing pipeline built around ClickHouse, for
the Sekera Services internship: *"Conception d'un pipeline de traitement des
logs … avec ClickHouse."* It began as a security-log pipeline; on 2026-10-01
the domain was switched to the compilation logs of a build farm -- the
data-center runners that compile, test and publish applications. The Kafka
topics, ClickHouse tables and registry subject kept their original names
(`security-logs`, `security_events`, ...); events, columns, rules and incidents
are new. Sections marked *(earlier workload)* describe measurements and
events from the security-log period.

This document is the full context: what exists, why it was built this way,
what has been measured, and what is still missing. Companion documents:

| document | for |
|---|---|
| [`../README.md`](../README.md) | the entry point: what it is, how to run it, every command |
| [`streaming.md`](streaming.md) | the live Flink path in depth: latency, per-event cost, scaling, model cost |
| [`orchestration.md`](orchestration.md) | Airflow: every DAG, the learning loop, the promotion gate, first runs |
| [`operations.md`](operations.md) | runbook: run, deploy, scale, migrate, recover, alerts |
| [`capacity-report.md`](capacity-report.md) | load-test results on the development machine |
| [`prod-readiness.md`](prod-readiness.md) | the 38 tasks between this and production |
| [`../NOTE_TO_BUILD_ENGINEER.md`](../NOTE_TO_BUILD_ENGINEER.md) | using and tuning the detector |

*Last updated 2026-10-01.*

---

## 1. What it does

Three layers. An **online path** decides every build-farm event as it
arrives; an **analytical (OLAP) store** keeps everything; an **MLOps loop**
improves the online path from what the analytical side learns.

```
 ONLINE (per event, milliseconds)
  build agents / simulator     1,780-runner farm at 1,000 events/s (Avro,
       |                       keyed by runner_ip)
       v
  Kafka  security-logs
       |
       v
  Flink job (etl/stream/job.py)                      ~5 ms from Kafka to decision
       +-- decode Avro (every registered schema version)
       +-- validate           bad events -> dead-letter topic
       +-- normalize          one canonical spelling per value
       +-- enrich             indicators, region, time of day
       +-- keyBy(runner_ip)
       +-- dedup              drop re-delivered event_ids        (STATE)
       +-- features           rolling 1- and 5-minute windows    (STATE)
       +-- rules              17 rules -> rule score
       +-- model              LightGBM, compiled, ~10 us -> ml score
       +-- decide             ok / alert / quarantine
       |   (between every step: data-quality counters, core/dq.py)
       v
  Kafka  security-events-scored        security-logs-rejected
       |                                      |
       v                                      v
 OLAP  ClickHouse Kafka engine (50 ms blocks) -> security_events / rejected_events
       |                                       -> suspicious_events (MV)
       |
 MLOps |  hourly (Airflow): an LLM (Groq) reviews a sample of the decisions
       |  -> confident disagreements become training labels
       |  -> new labels start a retraining -> promoted only if it measures better
       +-> Flink picks up the promoted model within 5 min, no restart
```

**Measured end to end** *(earlier workload)* (event created → row stored), dev stack, 1,000
events/s, 24 minutes of steady state: **median 194 ms, p95 346 ms**; the
decision itself ~5 ms after the event reaches Kafka. With 50 ms ClickHouse
blocks the median reached 66–84 ms while the machine was not short of
memory. Details and caveats: [`streaming.md`](streaming.md) §3.

**Airflow orchestrates the whole pipeline** without putting events into
batches: every 10 minutes it walks the path an event takes — Kafka, the
Flink job, ClickHouse — checks each stage and records the verdict; hourly
it checks the stored data and runs the AI review; it retrains the model
when the review produces labels; daily it rolls up the closed day
([`orchestration.md`](orchestration.md)).

**One engine.** The project began on Spark micro-batches; Flink replaced it
for the live path, and Spark was removed entirely on 2026-09-28 — one
engine, one image, one test suite. The Groq LLM, once a live grey-zone
judge on the Spark path, became the offline reviewer at the same time.

---

## 2. Design decisions, and why

### ETL, not ELT

Transformation happens *before* storage. Detection consumes rolling
behavioural features (failed builds in the last minute, OOM kills and slow
compile steps in five) that must be computed over the stream as events arrive; computed
after storage, detection is always a query behind.

### Kafka does not collect logs

Kafka is a broker; something must produce into it. Today that is the
simulator; in production it would be an agent on each runner (or the CI
system's webhook) shipping structured events outbound. The dashboard never
connects back into the build network.

### Flink, not Spark, for the live path

Spark Structured Streaming processes **micro-batches**: at a 20 s trigger an
event waited up to 20 s before anything looked at it, then for the batch
(~15 s typical end to end at 100 events/s), and at 1,000 events/s the
batches fell behind without bound. Spark's per-event modes (Continuous
Processing, Spark 4.1 Real-Time Mode) only support stateless queries, and
detection needs per-runner state. Flink processes one event at a time with
keyed state as a first-class feature. See [`streaming.md`](streaming.md) §1.
Spark stayed for replays for a while, then went: two engines meant two
images and two test suites for one set of logic.

### The logic is engine-free

Everything that decides — field contract, validation, normalization,
indicators, the rolling window, the rules, the model's scorer, the
data-quality checks — lives in **`etl/core/`**, plain Python with no Flink
imports. The job wires it into operators; the tests run it without a
cluster. A threshold or regex is defined once.

### Detection: rules, a model, and an LLM that reviews them

**Rules** (`etl/core/rules.py`) score every event: signatures (a compiler
crash, a corrupt cache entry, a full disk, a rogue command, an untrusted
fetch) and behaviour (failure storms, a broken toolchain, OOM-kill storms,
repeated slow steps, dependency 404 storms, runaway artifacts).
`>= 0.85` quarantines the runner, `>= 0.65` alerts, else `ok`.

**A LightGBM model** (`etl/core/ml.py`) scores the same event on 35
features — the numbers the rules see — in the same pass. It is compiled to
nested `if` statements when the job loads it: no library at scoring time,
identical to LightGBM's own output. Single-row cost, measured in the Flink
image (`tools/bench_model.py`): LightGBM's own `predict` 19.5 µs p50 but
**322 µs p99** (built for batches); ONNX Runtime 6.8 µs, but its converter
breaks PyFlink's dependencies; **compiled, 5.4 µs p50 / 7.7 µs p99** for
100 trees. The production model (120 trees) adds ~10 µs per event to the
job's ~173 µs (`tools/bench_detection.py`).

The final score is the higher of the two, but **the model alone can only
alert**; to quarantine, a rule must agree (`WATCHTOWER_ML_CAN_QUARANTINE`) —
a quarantine nobody can explain in rule terms is one nobody can defend. When the model
changes a decision, `ml_reason` names the features that drove it.
`WATCHTOWER_ML=off` switches it off without a code change.

**An LLM reviews, offline.** A remote call per event would stall the
stream, so the LLM (Groq, `openai/gpt-oss-safeguard-20b` — a classifier
built to judge content against a policy you write) never scores live.
Every hour it reviews up to 150 events of the closed hour: passed (`ok`)
near-misses, passed unusual ones, a passed random sample (the honest
miss-rate estimate), and the model's own alerts. Its confident verdicts
that disagree with the pipeline become training labels in both
directions — a missed incident (1), a false alarm (0).

### The learning loop, and what keeps it safe

New labels start a retraining at once (an Airflow asset), not the next
night. A candidate is **promoted only if**, against the active model:

- it ranks incidents at least as well on a holdout the reviewer never
  touched (judging a model on the reviewer's own opinions would reward
  agreeing with it);
- its false alarms on that holdout stay within what chance explains (a
  95% Poisson margin: 0 → up to 4.9, 10 → 18.1) — a strict "no more than
  before" once refused a model that caught 99.98% of incidents instead of
  77.8%, over 2 false alarms in 1,496;
- it gets no more of the reviewer's relabelled events wrong;
- **the shadow check:** scoring the last 6 hours of real traffic, at most
  50 events per runner, it would raise alerts on its own for ≤ 0.5% of
  events, ≤ 1.5× the active model's, **on ≤ 1.5× as many runners** — a model
  wrong about a whole group of runners alerts on many runners, a few times each.

After promotion, a **guard** rolls the model back if the reviewer calls
more than half of its own alerts normal. **Training labels are sampled per
runner** — every incident event, at most 5 normal events per runner per hour,
each weighted by how many it stands for — so every runner is in the data
and the weights still add up to the real traffic. A uniform 2% sample
tried first (on the security workload) left the remote-staff hosts so thin
that a model learned "external IP + data volume" as an incident and alerted
on every VPN user; the per-runner sample and the shadow check are the fix
([`orchestration.md`](orchestration.md) §5).

### Getting results into ClickHouse through Kafka

The Flink job writes finished rows to a Kafka topic; ClickHouse's Kafka
engine inserts them in 50 ms blocks. ClickHouse wants inserts in blocks,
not per event; the engine batches on ClickHouse's side, commits offsets
only after inserting, and keeps a ClickHouse outage from back-pressuring
detection — while ClickHouse is down, scored events wait in Kafka and are
inserted on restart. A row it cannot parse lands in `rejected_events` as
`sink_parse_error` rather than stalling the consumer.

### Delivery: at-least-once, duplicates collapse in storage

Kafka offsets and every runner's state are checkpointed together every
10 s; the Kafka sink flushes on each checkpoint; ClickHouse commits after
inserting. A replay after a failure can repeat rows; `security_events` is a
`ReplacingMergeTree`, so repeats collapse on merge (use `FINAL` when a
query must be exact; the daily rollup merges them away).

### How the load is spread

There is no load-balancer box; each stage spreads load itself, and the key
is `runner_ip`:

- **Kafka**: the producer keys by `runner_ip`, Kafka hashes the key to a
  partition (6 in dev, 24 in prod) — one host's events stay in order in one
  partition. Partitions are divided among brokers; Cruise Control moves
  them onto new brokers and off leaving ones.
- **Flink**: source subtasks divide the partitions; `keyBy(runner_ip)`
  hashes each source into one of 24 key groups (`pipeline.max-parallelism`),
  divided among the subtasks — one per TaskManager. A rescale restores the
  state from a checkpoint and redistributes the key groups, state and all.
- **ClickHouse**: one server, one Kafka consumer per intake table. With
  replicas, their consumers would share the partitions as a consumer group.
- **Kubernetes Services** spread connections for the registry and Airflow's
  API; Kafka clients bootstrap through a Service, then talk to each
  partition's leader directly.

The limits: one very busy host cannot be split (its state must stay in one
place); 24 key groups over 5 subtasks divide 5/5/5/5/4; parallelism is
capped at 24 by both partitions and key groups.

### Airflow for the batch side, not the stream

The stream is never scheduled: Flink runs it continuously and the Flink
operator keeps it alive. Airflow supervises it — one DAG checks every
stage end to end and restarts a stopped job on Kubernetes — and runs what
IS scheduled: checking a closed hour, the AI review, training, rolling up
a closed day, measuring detection. That work is tied to a data interval,
needs retries and a history, and must be re-runnable for any past day.
The DAGs only wire plain-Python functions (`orchestration/ops/`) that are
tested without Airflow.

### PyFlink in thread mode, one slot per TaskManager

Detection is Python. PyFlink's *thread* mode embeds the interpreter in the
TaskManager JVM, so every state access is an in-process call — about 3x the
throughput of the default *process* mode, whose state reads were gRPC round
trips. The price: all slots of a TaskManager share one interpreter and its
GIL, so extra slots *reduce* throughput (1 slot ~2,000 events/s at full
windows in a shared VM, 2 slots ~1,150, 4 slots ~450). Capacity is added
with TaskManagers, one slot each.

---

## 2b. The simulated network

The producer models a mid-sized company's build farm. Runner counts scale with
the rate (`HOSTS_SCALE = rate / 100`) so per-runner behaviour stays realistic;
at the default 1,000 events/s:

| Role | Runners | Range | Notes |
|---|---|---|---|
| workstation | 1,200 | `192.168.x.x` | developer machines, one project each |
| build-server | 240 | `10.0.10–19.x` | shared build servers, two projects each |
| ci-farm | 40 | `10.0.20.x` | very high volume (~12 events/s each), very healthy; containers often run as root |
| cloud | 250 | `102.67.x.x` | spot runners on public IPs, legitimately external |
| vendor | 50 | `196.200.x.x` | vendor build agents |

**Traffic is deliberately uneven** (the CI farm runners send ~60 times what a
workstation does). High volume, external IPs and root are therefore *not*
evidence on their own, and incidents strike **ordinary runners** that carry on
with their normal work -- there is no "bad IP" to learn, only behaviour. Nine
incident types run episodically (retry storm, broken toolchain, OOM-kill
storm, slow compile, dependency not found, cache corruption, compiler crash,
rogue build step, artifact bloat); their rates are fixed, so at 100 events/s
they are a much larger share of traffic than at 1,000. `make evaluate`
measures the live stack against them; `tools/replay_offline.py` replays them
through the per-event path without any infrastructure.

Events are sent continuously across each second (not one burst per second)
and timestamped at send, so measured latency is the pipeline's, not the
simulator's.

---

## 3. Repository layout

```
Watchtower/
├── README.md                     start here
├── Makefile                      every workflow -- `make help`
├── docker-compose.yml            DEV: Kafka, Karapace, ClickHouse, Flink (JM + TMs),
│                                 simulator (profile sim), Airflow + Postgres
│                                 (profile airflow)
├── schemas/
│   ├── build_event.avsc          the wire contract (Avro)
│   └── registry.py               wire format + registry client
├── producer/                     build-farm simulation, Avro, keyed by runner_ip
├── etl/
│   ├── core/                     ENGINE-FREE logic, run by the Flink job:
│   │   ├── vocab.py  indicators.py    field contract, regexes, region table
│   │   ├── records.py                 decode / validate / normalize / enrich
│   │   ├── window.py                  RollingWindow (1m + 5m, O(1) per event)
│   │   ├── rules.py  processor.py     rules; dedup+features+rules+model per runner
│   │   ├── ml.py                      the LightGBM model, compiled to Python; the policy
│   │   ├── dq.py                      data quality between the steps
│   │   └── columns.py  latency.py  startup.py
│   ├── stream/job.py             THE LIVE PATH: the Flink job
│   ├── stream/models.py          the active model, fetched from ClickHouse, hot-swapped
│   └── config.py                 settings; secrets read from files
├── orchestration/
│   ├── dags/                     Airflow: pipeline, data quality, daily rollup,
│   │                             detection quality, AI review, training
│   ├── ops/                      what the DAGs do, plain Python
│   └── assets.py                 the asset that starts training on new labels
├── clickhouse/
│   ├── init/01_schema.sql        tables (query-optimised layout, skip indexes)
│   ├── init/01b_ml_columns.sql   llm_* -> ml_* on an existing install
│   ├── init/02_*.sql  03_*.sql   v2 columns; Kafka-engine ingest + views
│   ├── init/04_orchestration.sql the tables Airflow writes
│   ├── init/05_ml.sql            labels, reviews, models, the active model, ML views
│   └── config/                   streaming.xml (broker macro), dev-limits.xml
├── tools/
│   ├── schema_registry.py        the only path a schema reaches the registry
│   ├── evaluate_detection.py     detection vs ground truth (`make evaluate`, and Airflow)
│   ├── bench_queries.py          SQL workload benchmark (`make ch-bench`)
│   ├── bench_model.py            single-event model scoring, by backend
│   ├── bench_detection.py        per-event detection cost with / without a model
│   ├── relayout_security_events.py   move data to the new table layout
│   └── load_test.py  swap_bounded_test.py  drain_test.sh   capacity tests
├── tests/                        unit (engine-free), Flink job (mini-cluster),
│                                 orchestration (ops, ML, reviewer, evaluator, DAGs)
├── docker/{flink,producer,airflow}/Dockerfile
├── deploy/
│   ├── k3d/cluster.yaml
│   ├── k8s/base/                 Strimzi Kafka (+ Cruise Control, broker HPA),
│   │                             registry, ClickHouse, FlinkDeployment
│   │                             (autoscaled), producer, Prometheus, Grafana
│   ├── k8s/components/airflow/   Airflow (scheduler, DAG processor, API server, Postgres)
│   ├── k8s/overlays/{staging,prod}/
│   ├── k8s/scripts/              Strimzi + Flink operator install, secrets,
│   │                             smoke test, watch-scaling, replica keeper
│   └── observability/            alert rules, scrape config, dashboard
├── .github/workflows/ci.yml      lint + unit + Flink tests, Airflow tests, schema gate
├── secrets/                      git-ignored; `make secrets`
└── docs/
```

---

## 4. The pipeline, stage by stage

The Flink job runs these per event, in this order (`etl/core/records.py`
for decode → enrich, `etl/core/processor.py` for dedup → decide):

| Stage | State | Does |
|---|---|---|
| decode | — | Confluent frame → Avro with the schema version its header names |
| validate | — | first failing check wins → `reject_reason`, event goes to the dead-letter topic |
| normalize | — | canonical case and spelling; nulls → the column defaults |
| enrich | — | `failure_signature`, rogue command, untrusted fetch, slow step, cache miss, privileged, internal IP, hour, night, region |
| keyBy `runner_ip` | — | the one network hop |
| dedup | **per runner** | drop an event_id this runner already sent |
| features | **per runner** | rolling 1- and 5-minute window, 16 features |
| rules | — | rule score and hits |
| model | — | LightGBM probability; `ml_reason` when it changed the decision |
| decide | — | `final = max(rule, model)` (model alone capped at alert) → `recommended_action` (`ok` / `alert` / `quarantine`) |

Between the steps, `etl/core/dq.py` counts doubtful events (defaulted
severity, missing project, unplaced external runner, clock skew) and
contradictions (a 1-minute count above its 5-minute one, an action that
does not follow its score) — a few comparisons per event, never changing
or dropping one.

### Why the order is fixed

- validate before normalize — do not canonicalise garbage
- normalize before dedup and features — `"John "` and `"john"` would
  otherwise split one culprit across several counters
- dedup before features — a replayed event would inflate counters and
  manufacture an anomaly
- enrich before features — features count indicators (rogue commands,
  failure signatures, slow steps)
- features before rules and model — both judge the runner's history

### Ordering per runner

Features assume a runner's events arrive in event-time order. It holds
because the producer keys Kafka messages by `runner_ip` (one runner = one
partition = one source subtask) and parsing runs chained to the source, so
each runner's events reach the keyed operator through a single path. A late
event is scored as of the newest time seen; nothing is dropped for being
late (a micro-batch engine with a watermark would drop them).

### State per runner

A small summary (running sums, window positions, the record at each window
head, the distinct project/exit-code/artifact counts while small, the ids of the last
1,024 events for dedup), plus the window's records as a map. Each state
call from Python costs 5–30 µs, so the layout minimises them: ~8 per event.
A runner idle for 15 minutes is forgotten — all of its state at once, by a
processing-time timer (a per-entry TTL once expired records under a live
summary and crashed the job).

---

## 5. Data

### Raw event (producer → Kafka)

Avro in the Confluent wire format (magic byte, 4-byte schema id, Avro
binary), keyed by `runner_ip`, schema `schemas/build_event.avsc`
registered at BACKWARD compatibility. Every registered version decodes; a
field a version lacks arrives null.

Each event carries who and what (`runner_ip`, `hostname`, `project`,
`build_id`, `triggered_by`, `event_type`, `outcome`, `log_source`), the step
(`command`, `step`, `file_path`, `exit_code`, `duration_ms`, `peak_memory_mb`,
`cache_status`, `error_message`, `reason`), the registry call (`dest_ip`,
`dest_port`, `protocol`, `http_method`, `url_path` (undecoded), `http_status`,
`user_agent`, `bytes_sent`, `response_time_ms`) and the process
(`process_name`, `process_id`, `parent_process`, `process_uid` (-1 = unknown,
never assumed root)).

`scenario` is **simulation ground truth**, never read by the pipeline; it
exists for `make evaluate` and for the simulator's training labels.

### Features

`events_1m`, `failed_builds_1m`, `failed_builds_5m`, `unique_projects_5m`,
`oom_kills_5m`, `distinct_exit_codes_5m`, `compile_steps_5m`,
`build_frequency`, `rogue_commands_5m`, `failure_signatures_5m`,
`http_errors_5m`, `dependency_404_1m`, `distinct_artifacts_5m`, `published_bytes_5m`,
`slow_steps_5m` and `cache_misses_5m`. The model's 35 inputs are these
plus the indicators, a few raw fields and the event type
(`etl/core/ml.py` `FEATURES`).

### ClickHouse tables

| Table | Engine | Holds |
|---|---|---|
| `security_events` | `ReplacingMergeTree` | every event: fields, indicators, features, rule and model scores, `ingested_at` |
| `suspicious_events` | `MergeTree` | `is_suspicious = 1`, via materialized view |
| `rejected_events` | `MergeTree` | refused messages: reason, schema id, original bytes (base64), Kafka coordinates |
| `security_events_queue`, `rejected_events_queue` | `Kafka` | the streaming path's intake, feeding the tables above through views |
| `pipeline_health` | `MergeTree` | the pipeline's end-to-end verdict every 10 minutes, per stage (Airflow) |
| `data_quality_checks` | `MergeTree` | every hourly check result (Airflow) |
| `daily_summary`, `daily_rule_hits`, `daily_top_sources` | `MergeTree`, a partition per day | the daily rollup, rebuilt idempotently (Airflow) |
| `detection_quality` | `MergeTree` | every detection evaluation, with its full report (Airflow) |
| `training_labels` | `ReplacingMergeTree` | what each event really was, who said so, and its weight |
| `event_reviews`, `label_changes` (view) | `MergeTree`, view | the AI's verdicts; the ones that disagree with the pipeline |
| `ml_models`, `ml_model_active` | `MergeTree` | every trained model (dump + metrics); which one is live (newest row) |
| `ml_decisions_hourly`, `ml_model_review` | views | what each model version did, hour by hour; how it fared under review |

`security_events` is sorted by
`(toStartOfTenMinutes(timestamp), runner_ip, timestamp, event_id)` with a
bloom-filter index on `event_id` and min/max indexes on `timestamp` and
`ingested_at`. Measured on 43M events against the earlier
`(timestamp, runner_ip, event_id)` key: one event by id 683 MB → 3 MB read;
one source's whole history 1 GB → 5 MB; one source ±15 min 101 MB → 1 MB;
the table 31% smaller. `make ch-bench` re-runs the workload.

`ingested_at − timestamp` is the end-to-end latency of every row.

---

## 6. Infrastructure

### Versions, and why they are pinned

| Component | Version | Reason |
|---|---|---|
| Kafka | 4.3.1 (KRaft) | what Strimzi 1.2.0 runs; dev matches it |
| Strimzi | 1.2.0 (`kafka.strimzi.io/v1`) | Kafka on Kubernetes; Cruise Control auto-rebalance |
| Flink | 2.2.1, **Java 11** | newest line with a Kafka connector (5.0.0-2.2); Java 11 because PyFlink thread mode (PEMJA) fails on 17 |
| PyFlink | 2.2.1, Python 3.12, thread mode | the job is Python; compiled from source on arm64 |
| Flink Kubernetes Operator | 1.16.1 | job lifecycle, HA, job autoscaler |
| Schema registry | Karapace 6.2.3 | Confluent-API-compatible, a quarter of cp-schema-registry's image size |
| ClickHouse | 25.8.33 | LTS line |
| LightGBM | 4.7.0 | the model: trained in Airflow, scored compiled (no library) in Flink |
| Airflow | 3.3.2 (slim image, Python 3.12) | orchestration; installed against its own constraints file |
| Postgres | 18.6 | Airflow's metadata only |
| Groq | `openai/gpt-oss-safeguard-20b` | the offline reviewer; free tier 8,000 tokens/min, 1,000 requests/day |
| k3s (via k3d 5.9.0) | 1.36.4 | lightest local control plane |
| Prometheus / Grafana | 3.14.0 / 13.2.2 | |

### Images

- **`docker/flink`** — Flink + PyFlink without the 298 MB
  `apache-flink-libraries` duplicate of `/opt/flink`, the Kafka connector,
  the shared `libpython` thread mode embeds, and the code. ~3 GB (Beam,
  PyArrow, pandas come with PyFlink). `test` stage adds pytest, ruff and
  LightGBM: every unit test, the job's tests, and lint run here.
- **`docker/producer`** — the simulator; also runs `schema-init`.
- **`docker/airflow`** — Airflow slim + the postgres provider, LightGBM,
  the Kafka client, `etl/core` (training uses the job's own features and
  scorer) and the DAGs; `test` stage adds pytest.

### Kafka addresses and topics

From the Mac `localhost:9092`, from containers `kafka:29092`, in Kubernetes
`watchtower-kafka-bootstrap:9092`. Topics: `security-logs` (input,
**broker-append timestamps**, so the job's latency metric starts at Kafka),
`security-events-scored`, `security-logs-rejected`. 6 partitions in dev and
staging; 24 / 12 / 6 in prod.

### Restarts

In compose every long-running service has `restart: unless-stopped` —
Kafka, the registry and ClickHouse only since 2026-09-29: before, a memory
kill left them down until started by hand. On Kubernetes, pods restart and
the Flink operator restores the job from its last checkpoint.

---

## 7. Running it

```bash
make secrets && make dev-up                    # Kafka, registry, ClickHouse, Flink
docker compose --profile sim up -d producer    # 1,000 events/s
make latency                                   # end-to-end p50/p95/p99, last minute
make evaluate                                  # detection vs ground truth
make test                                      # unit + Flink job + Airflow suites
make airflow-up                                # + Airflow on :8080, producer at 100/s
make cluster-up && make deploy ENV=staging     # k3d: Strimzi + Flink operator
```

The AI reviewer needs a Groq key in `secrets/groq_api_key`; unpause
`watchtower_review` and `watchtower_training`. Everything else —
migrations, scaling, recovery, alerts — is in [`operations.md`](operations.md)
and the [`README`](../README.md).

---

## 8. Current state

Verified by running, not just written. *Everything in this section was
measured on the earlier security-log workload, before 2026-10-01; the event
shape changed, the path did not, and nothing here has been re-measured on build
logs except what is marked.*

**Build-log detection, offline** (2026-10-01, `tools/replay_offline.py`, rules
only, two 15-minute replays of 900,000 events each)
- 111 of 111 incidents caught, across all nine kinds; 0 of 1.76 million
  normal events flagged on runners that had no incident. Per-kind table in
  [`../NOTE_TO_BUILD_ENGINEER.md`](../NOTE_TO_BUILD_ENGINEER.md) §1
- The live stack, the model and the reviewer have not run on build logs yet

**Streaming path**
- Kafka → Flink → Kafka → ClickHouse at 1,000 events/s from the 1,780-host
  simulation: end-to-end median 194 ms, p95 346 ms over 24 minutes;
  66–84 ms median with 50 ms ClickHouse blocks while memory was free
- Checkpoint resume: restarted jobs restore windows and dedup memory and
  continue from their Kafka offsets
- Per-event cost reduced from ~189 to ~173 µs (state calls 16.5 → ~8 per
  event, batched metrics, once-a-minute timers, in-summary dedup); one
  TaskManager decides ~4,100 events/s reading from Kafka
- With the model: ~183 µs per event — 18% of the 1 ms each event has at
  1,000 events/s. Measured live at 100 events/s without Airflow
  (2026-09-29): Kafka → decision p50 4 ms / p95 6–17 ms with the model,
  p50 4 ms / p95 6–7 ms without; checkpoints 82 vs 88 ms median. The
  multi-second p95 seen the day before came from memory pressure (Airflow
  and training on the same VM), not the model

**Detection** *(earlier workload)* (`make evaluate`, rules only, 1,000 events/s, 15 minutes,
879,721 events)
- Every event decided (coverage 100%, no copies); 29 of 29 incidents caught,
  99.3% of incident events quarantined; the first flag 0.4–1.6 s into an incident
  from a new source, at once for a source already seen affected
- 297 normal events quarantined (0.034%): 290 were compromised workstations'
  own traffic during or just after their incident (containment), **7** were
  real false positives — busy remote VPN hosts whose ordinary failed logins
  reach 20 in 5 minutes, so their next success trips
  `login_after_brute_force`

**The learning loop** *(earlier workload)* (2026-09-28, [`orchestration.md`](orchestration.md) §5)
- The AI reviewer made real calls: 94 events of one hour judged; its 3
  confident "false alarm" verdicts started a retraining by themselves
- Along the way: Groq's firewall refused Python's default User-Agent (403)
  and the free tier's 8,000 tokens/min refused unpaced calls (429) — fixed
  with a User-Agent and paginated requests
- A promotion that exposed a stale model: the active one caught 77.8% of
  incidents at the alert line on newer traffic, the retrained one 99.98%
- A promoted model then alerted on its own on 2.1% of live events, all
  remote-staff VPN hosts — the uniform label sample had left them out.
  With per-source labels and the shadow check, the next model: **0.12%**
  model-only alerts over 66,624 live events, **none on remote staff** after
  a restart's first minutes; the rest port scans from culprit IPs and
  internal scans / SSH, flagged before a rule could fire
- Against ground truth (2026-09-29, 6 min at 100 events/s, 36,004 events):
  **all 35 of the model's own alerts were incidents**, 11 of 11 incidents
  caught, 100% of incident events flagged, and **no block made by the model**
  — every block had a block-level rule behind it
- Flink swapped models without restarting, and kept the previous model
  when ClickHouse was unreachable

**Storage and queries**
- New `security_events` layout: drill-downs 20–600x less data read
- Dead-letter routing for every wire and validation error; parse errors at
  the ClickHouse intake routed there too

**Orchestration**
- Airflow 3.3 in dev, six DAGs: the pipeline DAG green on a live stack, red
  at `extract` with the producer stopped, red at `stream_job` with no
  TaskManager; hourly checks; a daily rollup backfilled for a real day
  (2,144,887 events, summary = stored); detection quality passing; the
  review → training loop above; ~0.5 GB with a task running

**Engineering**
- Tests: 85 in the Flink image (engine-free unit tests, the compiled model
  against LightGBM and within its time budget, the real job on a local
  Flink mini-cluster), 113 in the Airflow image (ops, training, the gate
  and shadow check, the paginated reviewer, evaluator, DAG structure);
  lint clean
- 8 alert rules (the 11 Spark ones went with Spark), a Grafana dashboard
  with streaming, data-quality and model panels
- Secrets as mounted files; CI workflow for lint, both test suites, the
  schema gate and manifests

**Capacity on this machine** ([`capacity-report.md`](capacity-report.md))
- ~1,000 events/s sustained with low latency; ~1,200 events/s maximum
  sustained throughput; above that the backlog grows. The ceiling is the
  3.8 GB Docker VM, not the job

**Kubernetes**
- Earlier: staging deployed, Kafka scaled 1 → 3 → 1 brokers with every
  topic rebalanced and no data lost
- Now: FlinkDeployment with the operator's autoscaler, broker HPA with
  Cruise Control auto-rebalance, prod sized for 10,000 events/s (5–24
  TaskManagers, 24 partitions), the Airflow component. Manifests render
  and are validated; **none of it has run on a cluster yet** (§9)

---

## 9. Known gaps

**The development machine cannot run everything together.** 8 GB of RAM
and a 3.8 GB Docker VM: the stack at 1,000 events/s alone fills it; with
Airflow the producer must run at 100 events/s, and even then ClickHouse
was killed for memory twice on 2026-09-28 when the hourly jobs and a
training run overlapped. Nothing was lost (Kafka holds what arrives
meanwhile), and ClickHouse now restarts on its own, but long runs need a
bigger machine.

**Kubernetes scaling not run end to end.** The Flink autoscaler, the broker
HPA with Cruise Control, the Airflow component and the 10,000 events/s
prod sizing are configured and rendered but untested on a cluster.
Whether Strimzi accepts Cruise Control with a single broker (staging's
minimum) is also unconfirmed.

**10,000 events/s is a projection.** Per-TaskManager capacity is measured;
linear scaling across TaskManagers is expected (state is partitioned by
source) but was only measured up to two, on one machine.

**The model learns the simulator.** Its labels are the producer's ground
truth plus the reviewer's corrections; on real traffic, until engineers'
verdicts become labels, it can only be as good as the reviewer. That is
why it may alert but not quarantine on its own. Its perfect holdout scores say
the simulator's incidents are easy to separate, not that the model is
perfect.

**The reviewer is an LLM on a free tier.** Its reasons are hypotheses; its
labels weigh half an event and need ≥ 80% confidence. 8,000 tokens/min
makes a 150-event review take minutes. It sends event details (runner IPs,
project names, URLs, command lines, error text) to Groq — confirm that is acceptable before
using real logs.

**A restart's first minutes are noisy for the model**: replayed events are
scored against windows still filling. The model's alerts in that window
are not a verdict on it.

**Dedup horizon.** Flink remembers a runner's last 1,024 event ids (~10
minutes for an ordinary runner, ~90 s for a CI-farm runner sending 12 events/s).
Producer-retry duplicates arrive within seconds, so it catches them.

**A bad commit is invisible per runner.** Features are keyed by runner; a
broken commit fails a few builds on *many* runners, so no one runner crosses
the line (the old security design had the same shape of gap: credential
stuffing). It needs a project-keyed pass.

**Behavioural rules miss an incident's first events** (1–4% of a retry
storm) — the model may catch some of them — and quarantine the whole runner
while it misbehaves: containment, but a policy choice.

**Slow incidents are invisible.** Windows are 1 and 5 minutes.

**Single ClickHouse replica, no backups**; checkpoints on a ReadWriteOnce
volume (fine on one node, object storage needed across nodes); a ~3 GB
Flink image. Replication (2 replicas + 3 ClickHouse Keeper nodes, on
separate machines) belongs on real nodes: on this VM it would only crash
sooner.

**Old table kept.** `security_events_before_relayout` (2.85 GB) holds the
data in the previous layout until someone decides it can be dropped.

**Nobody is notified.** Alerts and failed Airflow runs show in their UIs
only; no Alertmanager receiver or failure callback is configured.

**CI has never run on GitHub** — `make ci` runs locally.

---

## 10. Roadmap

The full list, in order, is [`prod-readiness.md`](prod-readiness.md) (38
tasks). The next steps:

1. A cloud staging cluster (3 × 8 GB nodes), a container registry, CI on
   GitHub, GitOps deploys — then verify the Flink autoscaler and broker
   HPA under `make load`, and measure 10,000 events/s on 5 TaskManagers
2. Don't lose data: ClickHouse replicas + Keeper, backups with a tested
   restore, Flink checkpoints in object storage
3. Alerts that reach a person: Alertmanager, Airflow failure callbacks,
   SLOs
4. Retention (90 days raw / 1 year suspicious, `ttl_only_drop_parts`) once
   signed off
5. A project-keyed feature pass for bad commits; re-measure detection on the
   live stack with build traffic (`make evaluate`), and the thresholds against
   a real farm
6. Real build-log sources (the CI system's webhooks, the build tools' logs),
   and engineers' verdicts as labels so the model learns real traffic
