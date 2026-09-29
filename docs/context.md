# Watchtower — project context

Security log processing pipeline built around ClickHouse, for the Sekera
Services internship: *"Conception d'un pipeline de traitement des logs de
sécurité avec ClickHouse."*

This document is the full context: what exists, why it was built this way,
what has been measured, and what is still missing. Companion documents:

| document | for |
|---|---|
| [`streaming.md`](streaming.md) | the live Flink path in depth: latency, per-event cost, scaling |
| [`operations.md`](operations.md) | runbook: run, deploy, scale, migrate, recover, alerts |
| [`orchestration.md`](orchestration.md) | Airflow: data-quality checks, daily rollups, detection quality |
| [`capacity-report.md`](capacity-report.md) | load-test results on the development machine |
| [`../NOTE_TO_SOC_ANALYST.md`](../NOTE_TO_SOC_ANALYST.md) | using and tuning the detector |

*Last updated 2026-09-27.*

---

## 1. What it does

Security events are streamed through Kafka, validated, enriched, given
rolling per-source behaviour features and a detection decision **one event
at a time in Apache Flink**, and stored in ClickHouse for analysis.

```
  log sources / simulator      1,780-host company at 1,000 events/s (Avro,
       |                       keyed by source_ip)
       v
  Kafka  security-logs
       |
       v
  Flink job (etl/stream/job.py)                      ~5 ms per event
       +-- decode Avro (every registered schema version)
       +-- validate           bad events -> dead-letter topic
       +-- normalize          one canonical spelling per value
       +-- enrich             indicators, GeoIP, time of day
       +-- keyBy(source_ip)
       +-- dedup              drop re-delivered event_ids        (STATE)
       +-- features           rolling 1- and 5-minute windows    (STATE)
       +-- rules              score -> allow / alert / block
       |   (between every step: data-quality counters, core/dq.py)
       |
       v
  Kafka  security-events-scored        security-logs-rejected
       |                                      |
       v                                      v
  ClickHouse Kafka engine (50 ms blocks) -> security_events / rejected_events
       |                                   -> suspicious_events (MV)
       v
  analytics, Grafana, the SOC analyst
```

**Measured end to end** (event created → row stored), dev stack, 1,000
events/s, 24 minutes of steady state: **median 194 ms, p95 346 ms**; the
decision itself ~5 ms after the event reaches Kafka. With 50 ms ClickHouse
blocks the median reached 66–84 ms while the machine was not short of
memory. Details and caveats: [`streaming.md`](streaming.md) §3.

**Airflow orchestrates the whole pipeline** without putting events into
batches: every 10 minutes it walks the path an event takes — Kafka, the
Flink job, ClickHouse — checks each stage, restarts the stream job if it
has stopped for good, and records the verdict. Around that, hourly
data-quality checks, a daily rollup (deduplicate, summarize, reconcile)
and a 6-hourly detection-quality evaluation —
[`orchestration.md`](orchestration.md).

**Detection learns.** Rules and a LightGBM model score every event in
the stream (~5 µs for the model). Every hour a Groq LLM reviews a sample
of what was *allowed*; where it disagrees confidently, its verdict becomes
a training label, and the daily retraining promotes a new model only if it
measures better (§2, [`orchestration.md`](orchestration.md)).

**One engine.** The project began on Spark micro-batches; Flink replaced it
for the live path, and Spark has since been removed entirely
(2026-09-28): one engine, one image, one test suite.

---

## 2. Design decisions, and why

### ETL, not ELT

Transformation happens *before* storage. Detection consumes rolling
behavioural features (failed logins in the last minute, distinct ports in
five) that must be computed over the stream as events arrive; computed
after storage, detection is always a query behind.

### Kafka does not collect logs

Kafka is a broker; something must produce into it. Today that is the
simulator; in production it would be an agent on each host shipping
structured events outbound. The dashboard never connects back into a
monitored network.

### Flink, not Spark, for the live path

Spark Structured Streaming processes **micro-batches**: at a 20 s trigger an
event waited up to 20 s before anything looked at it, then for the batch
(~15 s typical end to end at 100 events/s), and at 1,000 events/s the
batches fell behind without bound. Spark's per-event modes (Continuous
Processing, Spark 4.1 Real-Time Mode) only support stateless queries, and
detection needs per-source state. Flink processes one event at a time with
keyed state as a first-class feature. See [`streaming.md`](streaming.md) §1.

### The logic is engine-free

Everything that decides — field contract, validation, normalization,
indicators, the rolling window, the rules, the model's scorer — lives in
**`etl/core/`**, plain Python with no Flink imports. The job wires it into
operators; the tests run it without a cluster. A threshold or regex is
defined once.

### Detection: rules, a model, and an LLM that reviews them

**Rules** (`etl/core/rules.py`) score every event: signatures (SQL
injection, traversal, scanner User-Agents, reverse shells, sensitive
commands as root) and behaviour (brute force, password spray, port scans,
web scans, exfiltration volume). `>= 0.85` blocks, `>= 0.65` alerts.

**A LightGBM model** (`etl/core/ml.py`) scores the same event on the same
features, in the same pass. It is compiled to plain Python when the job
loads it: ~5 µs per event, identical to LightGBM's own output, where
`lightgbm.predict` on one row has a 300 µs tail and ONNX Runtime's
converter breaks PyFlink's dependencies (`tools/bench_model.py`). The
final score is the higher of the two, but the model alone can only
**alert**; to **block**, a rule must agree (`WATCHTOWER_ML_CAN_BLOCK`). When
the model changes a decision, `ml_reason` names the features that drove it.

**An LLM reviews, offline.** A remote call per event would stall the
stream, so the LLM (Groq) never scores live: every hour it reviews a
sample of *allowed* events — near-misses, unusual ones, a random sample —
and of the model's own alerts, and its confident disagreements become
training labels, both ways (missed attacks, false alarms). New labels
start a retraining at once. A new model is promoted only if it is at
least as good on a holdout the reviewer never touched, within
statistical noise, **and** — the shadow check — would not raise many more
alerts on its own, or on many more hosts, than the active model when
both score the last 6 hours of real traffic. The job picks it up within
5 minutes, no restart; a guard rolls it back if the reviewer calls most
of its alerts benign; `WATCHTOWER_ML=off` turns the model off.

### Getting results into ClickHouse through Kafka

The Flink job writes finished rows to a Kafka topic; ClickHouse's Kafka
engine inserts them in 50 ms blocks. ClickHouse wants inserts in blocks,
not per event; the engine batches on ClickHouse's side, commits offsets
only after inserting, and keeps a ClickHouse outage from back-pressuring
detection. A row it cannot parse lands in `rejected_events` as
`sink_parse_error` rather than stalling the consumer.

### Delivery: at-least-once, duplicates collapse in storage

Kafka offsets and every source's state are checkpointed together every
10 s; the Kafka sink flushes on each checkpoint; ClickHouse commits after
inserting. A replay after a failure can repeat rows; `security_events` is a
`ReplacingMergeTree`, so repeats collapse on merge (use `FINAL` when a
query must be exact).

### Airflow for the batch side, not the stream

The stream is never scheduled: Flink runs it continuously and the Flink
operator keeps it alive. Airflow supervises it — one DAG checks every
stage end to end and restarts a stopped job — and runs what IS scheduled:
checking a closed hour, rolling up a closed day, measuring detection. That
work is tied to a data interval, needs retries and a history, and must be
re-runnable for any past day. The DAGs only wire plain-Python functions
(`orchestration/ops/`) that are tested without Airflow.

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

The producer models a mid-sized company. Host counts scale with the rate
(`HOSTS_SCALE = rate / 100`) so per-host behaviour stays realistic; at the
default 1,000 events/s:

| Role | Hosts | Range | Notes |
|---|---|---|---|
| workstation | 1,200 | `192.168.x.x` | one primary user each |
| server | 240 | `10.0.10–19.x` | service accounts + root |
| automation | 40 | `10.0.20.x` | monitoring, backup, CI — very high volume |
| remote staff | 250 | `102.67.x.x` | public IPs, legitimately external |
| partner | 50 | `196.200.x.x` | branch offices |
| hostile | 4 | various | attacks only, never baseline |

**Traffic is deliberately uneven** (measured at scale 1: the top 4 hosts —
all automation — sent 46.7% of events; the median host 5 events). High
volume and external IPs are therefore *not* evidence on their own, and
`lateral_movement` and `data_exfiltration` start from compromised internal
workstations. Nine attack types run episodically at 5–10% of traffic.

Events are sent continuously across each second (not one burst per second)
and timestamped at send, so measured latency is the pipeline's, not the
simulator's.

---

## 3. Repository layout

```
Watchtower/
├── Makefile                      every workflow -- `make help`
├── docker-compose.yml            DEV: Kafka, Karapace, ClickHouse, Flink (JM + TMs),
│                                 simulator (profile sim), Airflow + Postgres
│                                 (profile airflow)
├── schemas/
│   ├── security_event.avsc       the wire contract (Avro, v2)
│   └── registry.py               wire format + registry client
├── producer/                     company simulation, Avro, keyed by source_ip
├── etl/
│   ├── core/                     ENGINE-FREE logic, run by the Flink job:
│   │   ├── vocab.py  indicators.py    field contract, regexes, GeoIP table
│   │   ├── records.py                 decode / validate / normalize / enrich
│   │   ├── window.py                  RollingWindow (1m + 5m, O(1) per event)
│   │   ├── rules.py  processor.py     rules; dedup+features+rules+model per source
│   │   ├── ml.py                      the LightGBM model, compiled to Python
│   │   ├── dq.py                      data quality between the steps
│   │   └── columns.py  latency.py  startup.py
│   ├── stream/job.py             THE LIVE PATH: the Flink job
│   ├── stream/models.py          the active model, fetched from ClickHouse
│   └── config.py                 settings; secrets read from files
├── orchestration/
│   ├── dags/                     Airflow: the pipeline end to end, data quality,
│   │                             daily rollup, detection quality, LLM review,
│   │                             model training
│   └── ops/                      what the DAGs do, plain Python
├── clickhouse/
│   ├── init/01_schema.sql        tables (query-optimised layout, skip indexes)
│   ├── init/02_*.sql  03_*.sql   v2 columns; Kafka-engine ingest + views
│   ├── init/01b_ml_columns.sql   llm_* -> ml_* on an existing install
│   ├── init/04_orchestration.sql the tables Airflow writes
│   ├── init/05_ml.sql            labels, reviews, models, the active model
│   └── config/                   streaming.xml (broker macro), dev-limits.xml
├── tools/
│   ├── schema_registry.py        the only path a schema reaches the registry
│   ├── evaluate_detection.py     detection vs ground truth (`make evaluate`, and Airflow)
│   ├── bench_queries.py          SQL workload benchmark (`make ch-bench`)
│   ├── bench_model.py            per-event cost of model scoring, by backend
│   ├── relayout_security_events.py   move data to the new table layout
│   └── load_test.py  swap_bounded_test.py  drain_test.sh   capacity tests
├── tests/                        unit (engine-free), Flink job (mini-cluster),
│                                 orchestration (ops, ML, evaluator, DAG structure)
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
for decode → enrich, `etl/core/processor.py` for dedup → rules):

| Stage | State | Does |
|---|---|---|
| decode | — | Confluent frame → Avro with the schema version its header names |
| validate | — | first failing check wins → `reject_reason`, event goes to the dead-letter topic |
| normalize | — | canonical case and spelling; nulls → the column defaults |
| enrich | — | `request_signature`, scanner UA, sensitive path/command, privileged, internal IP, hour, night, country |
| keyBy `source_ip` | — | the one network hop |
| dedup | **per source** | drop an event_id this source already sent |
| features | **per source** | rolling 1- and 5-minute window, 15 features |
| rules | — | score, hits, `recommended_action` |

### Why the order is fixed

- validate before normalize — do not canonicalise garbage
- normalize before dedup and features — `"John "` and `"john"` would
  otherwise split one attacker across several counters
- dedup before features — a replayed event would inflate counters and
  manufacture an anomaly
- enrich before features — features count indicators (sensitive commands,
  attack signatures)

### Ordering per source

Features assume a source's events arrive in event-time order. It holds
because the producer keys Kafka messages by `source_ip` (one source = one
partition = one source subtask) and parsing runs chained to the source, so
each source's events reach the keyed operator through a single path. A late
event is scored as of the newest time seen; nothing is dropped for being
late (a micro-batch engine with a watermark would drop them).

### State per source

A small summary (running sums, window positions, the record at each window
head, the distinct user/port/path counts while small, the ids of the last
1,024 events for dedup), plus the window's records as a map. Each state
call from Python costs 5–30 µs, so the layout minimises them: ~8 per event.
A source idle for 15 minutes is forgotten — all of its state at once, by a
processing-time timer (a per-entry TTL once expired records under a live
summary and crashed the job).

---

## 5. Data

### Raw event (producer → Kafka)

Avro in the Confluent wire format (magic byte, 4-byte schema id, Avro
binary), keyed by `source_ip`, schema `schemas/security_event.avsc`
registered at BACKWARD compatibility. Every registered version decodes;
v1 messages arrive with the v2 fields null.

v2 carries request, network, process and file context: `log_source`,
`outcome`, `session_id`, `dest_ip`, `dest_port`, `protocol`, `auth_method`,
`http_method`, `url_path` (undecoded), `http_status`, `user_agent`,
`bytes_sent`, `response_time_ms`, `process_name`, `process_id`,
`parent_process`, `process_uid` (-1 = unknown, never assumed root),
`file_path`, `file_operation`.

`scenario` is **simulation ground truth**, never read by the pipeline; it
exists only for `make evaluate`.

### Features

`requests_1m`, `failed_logins_1m`, `failed_logins_5m`, `unique_users_5m`,
`port_scan_count_5m`, `unique_ports_5m`, `commands_executed_5m`,
`login_frequency`, `sensitive_commands_5m`, `attack_signatures_5m`,
`http_errors_5m`, `http_404_1m`, `distinct_paths_5m`, `bytes_sent_5m`, and
`unique_source_ips_5m` (always 0 — see §9).

### ClickHouse tables

| Table | Engine | Holds |
|---|---|---|
| `security_events` | `ReplacingMergeTree` | every event: fields, indicators, features, scores, `ingested_at` |
| `suspicious_events` | `MergeTree` | `is_suspicious = 1`, via materialized view |
| `rejected_events` | `MergeTree` | refused messages: reason, schema id, original bytes (base64), Kafka coordinates |
| `security_events_queue`, `rejected_events_queue` | `Kafka` | the streaming path's intake, feeding the tables above through views |
| `pipeline_health` | `MergeTree` | the pipeline's end-to-end verdict every 10 minutes, per stage (Airflow) |
| `data_quality_checks` | `MergeTree` | every hourly check result (Airflow) |
| `daily_summary`, `daily_rule_hits`, `daily_top_sources` | `MergeTree`, a partition per day | the daily rollup, rebuilt idempotently (Airflow) |
| `detection_quality` | `MergeTree` | every detection evaluation, with its full report (Airflow) |

`security_events` is sorted by
`(toStartOfTenMinutes(timestamp), source_ip, timestamp, event_id)` with a
bloom-filter index on `event_id` and min/max indexes on `timestamp` and
`ingested_at`. Measured on 43M events against the earlier
`(timestamp, source_ip, event_id)` key: one event by id 683 MB → 3 MB read;
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
| k3s (via k3d 5.9.0) | 1.36.4 | lightest local control plane |
| Prometheus / Grafana | 3.14.0 / 13.2.2 | |
| Airflow | 3.3.2 (slim image, Python 3.12) | orchestration; installed against its own constraints file |
| Postgres | 18.6 | Airflow's metadata only |

### Images

- **`docker/flink`** — Flink + PyFlink without the 298 MB
  `apache-flink-libraries` duplicate of `/opt/flink`, the Kafka connector,
  the shared `libpython` thread mode embeds, and the code. ~3 GB (Beam,
  PyArrow, pandas come with PyFlink). `test` stage adds pytest, ruff and
  LightGBM: every unit test, the job's tests, and lint run here.
- **`docker/producer`** — the simulator.
- **`docker/airflow`** — Airflow slim + the postgres provider, the Kafka
  client for the evaluator, and the DAGs; `test` stage adds pytest.

### Kafka addresses and topics

From the Mac `localhost:9092`, from containers `kafka:29092`, in Kubernetes
`watchtower-kafka-bootstrap:9092`. Topics: `security-logs` (input,
**broker-append timestamps**, so the job's latency metric starts at Kafka),
`security-events-scored`, `security-logs-rejected`. 6 partitions in dev and
staging; 24 / 12 / 6 in prod.

---

## 7. Running it

```bash
make secrets && make dev-up                    # Kafka, registry, ClickHouse, Flink
docker compose --profile sim up -d producer    # 1,000 events/s
make latency                                   # end-to-end p50/p95/p99, last minute
make test                                      # unit + Flink job + Airflow suites
make airflow-up                                # + Airflow on :8080, producer at 100/s
make cluster-up && make deploy ENV=staging     # k3d: Strimzi + Flink operator
```

Everything else — migrations, scaling, recovery, alerts — is in
[`operations.md`](operations.md).

---

## 8. Current state

Verified by running, not just written.

**Streaming path**
- Kafka → Flink → Kafka → ClickHouse at 1,000 events/s from the 1,780-host
  simulation: end-to-end median 194 ms, p95 346 ms over 24 minutes;
  66–84 ms median with 50 ms ClickHouse blocks while memory was free
- Checkpoint resume: restarted jobs restore windows and dedup memory and
  continue from their Kafka offsets; state-layout changes documented
- Per-event cost reduced from ~189 to ~173 µs (state calls 16.5 → ~8 per
  event, batched metrics, once-a-minute timers, in-summary dedup); one
  TaskManager decides ~4,100 events/s reading from Kafka, two ~5,500 on
  one shared laptop VM

**Detection** (`make evaluate`, Flink path, 1,000 events/s, 15 minutes,
879,721 events)
- Every event decided (coverage 100%, no copies); 29 of 29 attacks caught,
  99.3% of attack events blocked; the first flag 0.4–1.6 s into an attack
  from a new source, at once for a source already seen attacking
- 297 normal events blocked (0.034%): 290 were compromised workstations'
  own traffic during or just after their attack (containment), **7** were
  real false positives — busy remote VPN hosts whose ordinary failed logins
  reach 20 in 5 minutes, so their next success trips
  `login_after_brute_force`
- The ML layer (LightGBM in the stream, Groq review, daily retraining) is
  built and tested; its first live measurements are in
  [`orchestration.md`](orchestration.md) §5

**Storage and queries**
- New `security_events` layout: analyst drill-downs 20–600x less data read
- Dead-letter routing for every wire and validation error; parse errors at
  the ClickHouse intake routed there too

**Orchestration** ([`orchestration.md`](orchestration.md))
- Airflow 3.3 in dev: the pipeline DAG green on a live stack, red at
  `extract` with the producer stopped, red at `stream_job` with no
  TaskManager; hourly checks; a daily rollup backfilled for a real day
  (2,144,887 events, summary = stored); detection quality passing (6/6
  attacks, 1.02 s median first flag); ~0.5 GB with a task running

**Engineering**
- Tests: 83 in the Flink image (engine-free unit tests, the compiled model
  against LightGBM and within its time budget, and the real job on a local
  Flink mini-cluster), 113 in the Airflow image (ops, training, the gate
  and shadow check, the paginated reviewer, evaluator, DAG structure);
  lint clean
- Metrics, 8 alert rules (the 11 Spark ones went with Spark), a Grafana dashboard with a streaming-path row and
  a between-step data-quality panel
- Secrets as mounted files; CI workflow for lint, both test suites, the
  schema gate and manifests

**Capacity on this machine** ([`capacity-report.md`](capacity-report.md))
- ~1,000 events/s sustained with low latency; ~1,200 events/s maximum
  sustained throughput; above that the backlog grows. The ceiling is the
  3.8 GB Docker VM swapping, not the job

**Kubernetes**
- Earlier: staging deployed, Kafka scaled 1 → 3 → 1 brokers with every
  topic rebalanced and no data lost
- Now: FlinkDeployment with the operator's autoscaler, broker HPA with
  Cruise Control auto-rebalance, prod sized for 10,000 events/s (5–24
  TaskManagers, 24 partitions). Manifests render and are validated; **none
  of it has run on the cluster yet** (§9)

---

## 9. Known gaps

**The development machine cannot run the full stack for long.** 8 GB of
RAM and a 3.8 GB Docker VM: the stack alone needs ~3.5–3.8 GB, so it swaps
within minutes at any rate, and swap stalls produce multi-second latency
spikes. Measured numbers above come from runs kept short or tuned for it.

**Kubernetes scaling not run end to end.** The Flink autoscaler, the broker
HPA with Cruise Control, and the 10,000 events/s prod sizing are configured
and rendered but untested on a cluster: the full staging stack does not fit
the k3d node on this machine, and a full-stack attempt once crashed the
Docker VM. Whether Strimzi accepts Cruise Control with a single broker
(staging's minimum) is also unconfirmed.

**10,000 events/s is a projection.** Per-TaskManager capacity is measured;
linear scaling across TaskManagers is expected (state is partitioned by
source) but was only measured up to two, on one machine.

**The model learns the simulator.** Its labels are the producer's ground
truth plus the reviewer's corrections; on real traffic, until analysts'
verdicts become labels, it can only be as good as the reviewer. That is
why it may alert but not block on its own.

**The reviewer has never made a live call** — no Groq key is set
(`secrets/groq_api_key`); the review DAG skips until one is.

**Dedup horizon.** Flink remembers a source's last 1,024 event ids (~10
minutes for an ordinary host, ~25 s for one sending 40 events/s).
Producer-retry duplicates arrive within seconds, so it catches them.

**`unique_source_ips_5m` is always 0.** Features are keyed by source IP;
credential stuffing (one account from many IPs) needs a user-keyed pass.

**Behavioural rules miss an attack's first events** (2–6% of a brute
force), and block the whole source while it misbehaves — containment, but a
policy choice.

**Slow attacks are invisible.** Windows are 1 and 5 minutes.

**Single ClickHouse replica**, checkpoints on a ReadWriteOnce volume (fine
on one node, object storage needed across nodes), a ~3 GB Flink image.

**Old table kept.** `security_events_before_relayout` (2.85 GB) holds the
data in the previous layout until someone decides it can be dropped.

**CI has never run on GitHub** — `make ci` runs locally.

**Orchestration**: no failure notifications, one admin user, the Kubernetes
component not yet run on a cluster ([`orchestration.md`](orchestration.md) §6).

---

## 10. Roadmap

1. Run staging on a machine with room for it (≥ 8 GB for Docker) and
   verify the Flink autoscaler and broker HPA under `make load`
2. Measure 10,000 events/s on real nodes (5 TaskManagers) and confirm
   latency stays under 200 ms
3. Set a Groq key; measure the reviewer's cost and how often it is right
4. A user-keyed feature pass for credential stuffing; review
   `login_after_brute_force` for remote staff (7 false positives, above)
5. Replays: a bounded run of the Flink job over a Kafka time range,
   launched from Airflow; send Airflow failures somewhere a person sees them
6. Analysts' verdicts as labels, so the model learns real traffic
