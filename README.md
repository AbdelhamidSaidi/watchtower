# Watchtower

**A real-time security log pipeline: every event decided in milliseconds, stored for analysis, and a detector that learns from an AI's second opinion.**

Watchtower streams security logs through **Kafka**, decides each event as it arrives in **Apache Flink** — rules plus a **LightGBM** model, ~0.2 s from event to stored row — and keeps everything in **ClickHouse** for analysis. **Airflow** runs the batch side: data-quality checks, daily rollups, and an hourly **MLOps loop** in which an LLM (Groq) reviews a sample of the pipeline's decisions, its corrections become training labels, and a new model goes live only if it measures better.

Built for the Sekera Services internship *« Conception d'un pipeline de traitement des logs de sécurité avec ClickHouse »*.

---

## Contents

1. [At a glance](#1-at-a-glance)
2. [Architecture](#2-architecture)
3. [The life of an event](#3-the-life-of-an-event)
4. [Detection: rules, a model, and an AI reviewer](#4-detection-rules-a-model-and-an-ai-reviewer)
5. [Orchestration and MLOps (Airflow)](#5-orchestration-and-mlops-airflow)
6. [Data model (ClickHouse)](#6-data-model-clickhouse)
7. [Technology stack](#7-technology-stack)
8. [Repository layout](#8-repository-layout)
9. [Getting started](#9-getting-started)
10. [Everyday commands](#10-everyday-commands)
11. [Configuration](#11-configuration)
12. [Kubernetes](#12-kubernetes)
13. [Observability](#13-observability)
14. [Testing and CI](#14-testing-and-ci)
15. [Performance](#15-performance)
16. [Security and secrets](#16-security-and-secrets)
17. [Troubleshooting](#17-troubleshooting)
18. [Known limitations](#18-known-limitations)
19. [Documentation](#19-documentation)

---

## 1. At a glance

| | |
|---|---|
| **Traffic** | a simulated company of 1,780 hosts at 1,000 events/s (Avro, keyed by source IP), with 9 kinds of attack |
| **Latency** | event created → row stored: **median 194 ms, p95 346 ms** at 1,000 events/s; the decision itself ~5 ms after Kafka |
| **Per-event cost** | ~183 µs in the Flink job with the model (~10 µs of it) — 18% of the 1 ms each event has at 1,000/s; ~5,450 events/s per TaskManager |
| **Detection** (15 min, 879,721 events) | 29 of 29 attacks caught, 99.3% of attack events blocked, every event decided; 7 of 868,112 normal events wrongly blocked on uninvolved hosts |
| **Learning loop** | hourly AI review → labels → retraining starts on new labels → promoted only if better → picked up by Flink within 5 min, no restart |
| **The model, live** | its own alerts: 35 of 35 were real attacks (6 min vs ground truth); ~0.1% of events; adds a few ms at p95 at most |
| **Orchestration** | 6 Airflow DAGs: end-to-end pipeline check (10 min), data quality (hourly), AI review (hourly), training (on new labels + nightly), rollup (daily), detection quality (6-hourly) |
| **Scaling** | Kubernetes: Flink TaskManagers (5–24 in prod) and Kafka brokers (3–6) autoscale |
| **Tests** | 85 in the Flink image, 113 in the Airflow image; lint clean |

---

## 2. Architecture

Three layers: an **online path** that decides every event as it arrives, an **analytical (OLAP) store**, and an **MLOps loop** that improves the online path from what the analytical side learns.

```
 ONLINE (per event, milliseconds)
 ─────────────────────────────────
  log sources / simulator
        │  Avro, keyed by source_ip
        ▼
  Kafka ─ security-logs ──────────────► Flink job (etl/stream/job.py)
                                          decode → validate → normalize → enrich
                                          → keyBy(source_ip) → dedup → rolling 1m/5m features
                                          → rules → LightGBM model (compiled, ~10 µs)
                                          + data-quality counters between every step
                                                │                     │
                        security-events-scored ◄┘                     └► security-logs-rejected
                                │                                          │
                                ▼   ClickHouse Kafka engine (50 ms blocks) ▼
 OLAP                   security_events ── suspicious_events (MV)   rejected_events
 ─────                          │
                                │  hourly / daily (Airflow)
 MLOps                          ▼
 ─────   watchtower_review: Groq judges a sample ──► event_reviews ──► training_labels
                  ▲                                                          │ new labels
                  │                                                          ▼
         Flink loads the promoted model ◄── ml_model_active ◄── watchtower_training
         within 5 min, no restart                               (holdout + shadow gate)
```

Why each piece — in short (the full reasoning is in [`docs/context.md`](docs/context.md) §2):

- **Kafka** decouples sources from processing, keeps a day of raw events for replays and evaluation, and carries results to ClickHouse.
- **Flink, not Spark.** The project began on Spark micro-batches: a 20 s trigger meant events waited up to 20 s, and at 1,000/s batches fell behind. Flink processes one event at a time with keyed state; Spark was removed entirely.
- **ClickHouse** is a columnar OLAP store: billions of rows, sub-second analyst queries. It takes inserts in blocks, so its Kafka engine batches on its side (50 ms) and a ClickHouse outage never back-pressures detection.
- **Airflow** runs what is scheduled — checks, rollups, the AI review, training — tied to data intervals, with retries, history and backfills. It supervises the stream; it never puts events into batches.

---

## 3. The life of an event

| step | where | what happens |
|---|---|---|
| **produce** | `producer/security_log_producer.py` | Avro, Confluent wire format, schema looked up in the registry (never registered by the producer); keyed by `source_ip` so one source stays on one partition |
| **decode** | `etl/core/records.py` | every registered schema version is decodable; unreadable messages → dead-letter with the original bytes |
| **validate** | `etl/core/records.py` | UUID, timestamp, event type, ports, HTTP status; failures → `rejected_events` with a reason |
| **normalize** | `etl/core/records.py` | one spelling per value (case, whitespace, known severities) |
| **enrich** | `etl/core/records.py`, `indicators.py` | attack signatures in URLs, scanner user agents, sensitive paths/commands, privilege, internal vs external IP, GeoIP, time of day |
| **dedup** | `etl/core/processor.py` | a source's last 1,024 event ids (Kafka is at-least-once) |
| **features** | `etl/core/window.py` | rolling 1- and 5-minute windows per source: failed logins, distinct users/ports/paths, 404s, bytes, commands… O(1) per event |
| **rules** | `etl/core/rules.py` | 16 rules → `rule_score`, `rule_hits` |
| **model** | `etl/core/ml.py` | LightGBM, compiled to plain Python → `ml_score`, and `ml_reason` when it changed the decision |
| **decide** | `etl/core/ml.py` | `final = max(rule score, model score)`; ≥ 0.85 block, ≥ 0.65 alert; the model alone can alert, not block |
| **store** | `clickhouse/init/03_streaming_ingest.sql` | Kafka engine → `security_events` in 50 ms blocks; unparseable rows → `rejected_events` |
| **check** | `etl/core/dq.py` | between every step: counters for defaulted fields, unplaced IPs, clock skew, inconsistent windows or decisions |

**Delivery is at-least-once, end to end.** Kafka offsets and every source's state are checkpointed together every 10 s; the sink flushes on checkpoints; ClickHouse commits offsets only after inserting. A replay can repeat rows — `security_events` is a `ReplacingMergeTree`, so they collapse.

All decision logic lives in **`etl/core/`**: plain Python, no Flink imports, tested without a cluster. The Flink job only wires it into operators.

---

## 4. Detection: rules, a model, and an AI reviewer

### Rules (`etl/core/rules.py`)

16 deterministic rules, strongest first:

| kind | rules | score |
|---|---|---|
| signatures — bad in themselves | `reverse_shell`, `sensitive_command_as_root`, `sqli`, `path_traversal`, `xss`, `sensitive_command`, `scanner_agent`, `sensitive_path_probe` | 0.70–1.00 |
| behaviour — the source's recent history | `login_after_brute_force`, `brute_force`, `password_spray`, `port_scan`, `lateral_movement`, `web_scan`, `data_exfiltration`, `repeated_attack_signatures` | 0.85–1.00 |

Behavioural rules key on the **source**, so a compromised host's ordinary traffic is blocked with it while it misbehaves (containment — a policy choice, see [`NOTE_TO_SOC_ANALYST.md`](NOTE_TO_SOC_ANALYST.md)).

### The model (`etl/core/ml.py`)

A LightGBM classifier on 30 features — the same numbers the rules see. It is **compiled to nested `if` statements** when the job loads it: no library at scoring time, output identical to LightGBM's.

| way to score one event (Flink image, 1 row per call) | p50 | p99 |
|---|---|---|
| `lightgbm` `Booster.predict` | 19.5 µs | **322 µs** (built for batches) |
| ONNX Runtime | 6.8 µs | 9.5 µs — but its converter breaks PyFlink's dependencies |
| **compiled to Python** (used) | **5.4 µs** | **7.7 µs** |

(100 trees × 15 leaves, `tools/bench_model.py`; the production model, 120 trees, costs ~8 µs p50 / 18 µs p99.)

Policy: `final = max(rule score, model score)`, but **the model alone can only alert** — to block, a rule must agree (`WATCHTOWER_ML_CAN_BLOCK`). When the model changes a decision, `ml_reason` names the features that drove it (e.g. `ml: failed_logins_5m, unique_users_5m`). `WATCHTOWER_ML=off` switches it off without a code change.

### The AI reviewer (`orchestration/ops/review.py`)

An LLM call per event would stall the stream, so the LLM never scores live. Every hour, Groq's **`openai/gpt-oss-safeguard-20b`** — a classifier built to judge content against a policy you write — reviews a sample of the closed hour:

| sample | from | a confident disagreement (≥ 80%) becomes |
|---|---|---|
| `near_miss` | allowed, the highest model scores | label 1 — an attack the model let through |
| `unusual` | allowed, the hour's top 0.1% on a behaviour feature | label 1 |
| `random` | allowed, uniform (served first: the honest miss-rate estimate) | label 1 |
| `model_alert` | alerted by the model alone | label 0 — a false alarm to unlearn |

At most 150 events a run, 3,000 a day. Requests are **paginated** to the free tier's 8,000 tokens per minute: pages of ≤ 10 events and ≤ half the minute's budget, a one-minute token ledger, and `Retry-After` honoured. An allowed event judged malicious at ≥ 90% fails the run at once — someone should look now.

### The learning loop

```
new AI labels ──► training starts (Airflow asset) ──► candidate model
                                                          │
          ┌───────────────────────────────────────────────┘
          ▼  promoted only if, against the active model:
   ranking      average precision no lower (holdout the AI never touched)
   false alarms within what chance explains (Poisson 95% margin)
   corrections  wrong on no more of the AI-relabelled events
   shadow       on the last 6 h of real traffic (≤ 50 events per host): alerts it would
                raise alone ≤ 0.5% of events, ≤ 1.5× the active model's, on ≤ 1.5× as many hosts
          │
          ▼
   ml_model_active ──► Flink loads it within 5 min, no restart
          │
          ▼  guard: if the AI calls > half of its own alerts benign (≥ 20 in 24 h) → previous model back
```

**Training labels** keep every attack event and up to 5 normal events per source per hour, each weighted by how many it stands for — every host is represented, and the model still learns the real base rate. (A uniform 2% sample once left remote staff so thin that a model alerted on every VPN user; the per-source sample and the shadow check are the fix — see [`docs/orchestration.md`](docs/orchestration.md) §5.)

---

## 5. Orchestration and MLOps (Airflow)

Airflow 3.3 (`orchestration/dags/`); the work itself is plain Python in `orchestration/ops/`, tested without Airflow.

| DAG | schedule | does | writes | fails when |
|---|---|---|---|---|
| `watchtower_pipeline` | every 10 min | Kafka, registry, ClickHouse → Flink job RUNNING (restarts a stopped one on Kubernetes) → samples the flow → judges extract / transform / load | `pipeline_health` | a service is down, the job is not running, a stage is stalled or behind — **the graph turns red at the broken stage** |
| `watchtower_data_quality` | hourly | 7 checks on the closed hour: volume, rejected share, missing fields, latency, unmerged copies, block-rate jump, model-score drift (PSI) | `data_quality_checks` | a *fail* check fails (warnings are recorded only) |
| `watchtower_review` | hourly | collect the simulator's labels; select candidates; **Groq judges them**; learn; alert on sure misses; guard the model | `event_reviews`, `training_labels` | the AI is sure an allowed event was malicious; or the guard rolled a model back |
| `watchtower_training` | **when the AI adds labels**, and nightly | train LightGBM, evaluate, shadow-check, promote if better | `ml_models`, `ml_model_active` | training errors (a worse model is simply not promoted) |
| `watchtower_daily` | daily | wait for the day to close → merge away replayed copies → rebuild the day's rollups → reconcile to the event | `daily_summary`, `daily_rule_hits`, `daily_top_sources` | the rollup does not count exactly the day's events |
| `watchtower_detection_quality` | every 6 h | detection vs the simulator's ground truth, once the pipeline is verified healthy | `detection_quality` | an attack was missed, detection got slow, coverage dropped, or uninvolved hosts were blocked |

Every check records its result before it can fail, so a broken run keeps its evidence. Full description: [`docs/orchestration.md`](docs/orchestration.md).

---

## 6. Data model (ClickHouse)

| table / view | holds |
|---|---|
| `security_events` | every event: fields, indicators, features, rule and model scores, decision, `ingested_at` — `ReplacingMergeTree`, sorted by `(10-min bucket, source_ip, timestamp, event_id)`, bloom filter on `event_id` |
| `suspicious_events` | alerts and blocks only (materialized view) |
| `rejected_events` | refused messages: reason, schema id, the original bytes (base64), Kafka coordinates |
| `pipeline_health` | the end-to-end verdict every 10 minutes, per stage |
| `data_quality_checks` | every hourly check result |
| `daily_summary`, `daily_rule_hits`, `daily_top_sources` | daily rollups, a partition per day, rebuilt idempotently |
| `detection_quality` | every detection evaluation, with its full report |
| `training_labels` | what each event really was, and who said so (simulator / reviewer) |
| `event_reviews`, `label_changes` (view) | the AI's verdicts; the ones that disagree with the pipeline |
| `ml_models`, `ml_model_active` | every trained model (dump + metrics); which one is live |
| `ml_decisions_hourly`, `ml_model_review` (views) | what each model version did, hour by hour; how it fared under review |

The sort key makes analyst drill-downs cheap — measured on 43M events: one event by id 683 MB → 3 MB read; one source's whole history 1 GB → 5 MB (`make ch-bench`).

Schema files: `clickhouse/init/01…05_*.sql`, applied in order by `make ch-migrate` (idempotent).

---

## 7. Technology stack

| component | version | role |
|---|---|---|
| Apache Kafka | 4.3.1 (KRaft) | transport; Strimzi 1.2.0 on Kubernetes |
| Karapace | 6.2.3 | schema registry (Confluent API) |
| Apache Flink / PyFlink | 2.2.1, Java 11, Python 3.12 (thread mode) | the online path; Flink Kubernetes Operator 1.16.1 |
| LightGBM | 4.7.0 | the model — trained in Airflow, scored compiled in Flink |
| ClickHouse | 25.8.33 (LTS) | storage and analytics |
| Apache Airflow | 3.3.2, Postgres 18.6 for its metadata | orchestration and MLOps |
| Groq API | `openai/gpt-oss-safeguard-20b` | the offline AI reviewer |
| Prometheus / Grafana | 3.14.0 / 13.2.2 | metrics, alerts, dashboard (Kubernetes) |
| k3s via k3d | 1.36.4 / 5.9.0 | local Kubernetes |

---

## 8. Repository layout

```
Watchtower/
├── Makefile                      every workflow — `make help`
├── docker-compose.yml            dev stack: Kafka, Karapace, ClickHouse, Flink;
│                                 profiles: sim (producer), airflow (Airflow + Postgres)
├── schemas/                      the Avro contract + registry client (stdlib only)
├── producer/                     the company simulation
├── etl/
│   ├── core/                     ENGINE-FREE logic, run per event by Flink:
│   │                             records, indicators, window, rules, ml, dq, processor
│   ├── stream/job.py             the Flink job; stream/models.py fetches the active model
│   └── config.py                 settings from the environment; secrets from files
├── orchestration/
│   ├── dags/                     the six Airflow DAGs
│   └── ops/                      what they do, plain Python
├── clickhouse/
│   ├── init/                     01 schema, 01b ml columns, 02 views, 03 Kafka intake,
│   │                             04 orchestration tables, 05 ML lifecycle
│   └── config/                   broker macro, dev memory limits
├── tools/                        schema CLI, evaluator, query/model/detection benchmarks,
│                                 load and capacity tests, table relayout
├── tests/                        unit (engine-free), flink (mini-cluster), orchestration
├── docker/{flink,producer,airflow}/
├── deploy/
│   ├── k3d/                      local cluster
│   ├── k8s/base/                 Strimzi Kafka, registry, ClickHouse, FlinkDeployment, producer,
│   │                             Prometheus, Grafana
│   ├── k8s/components/airflow/   Airflow (scheduler, DAG processor, API server, Postgres)
│   ├── k8s/overlays/{staging,prod}/
│   └── observability/            alert rules, scrape config, dashboard
├── .github/workflows/ci.yml
└── docs/                         context, streaming, orchestration, operations, capacity,
                                  production readiness
```

---

## 9. Getting started

### Prerequisites

- **Docker** with at least **4 GB** for its VM (Docker Desktop → Settings → Resources). The dev stack at 1,000 events/s uses ~3 GB; with Airflow, run the producer at 100 events/s (see below). 8 GB or more makes everything comfortable.
- **GNU Make**, and **Python 3.10+** on the host (only for `make evaluate` / `make produce`: `pip install kafka-python fastavro`).
- For Kubernetes: `k3d` and `kubectl`.

### 1. Secrets

```bash
make secrets
```

Generates random passwords into `secrets/` (git-ignored, mode 600): ClickHouse, Grafana, Airflow's database, admin and signing key. `secrets/groq_api_key` starts empty — see step 4.

### 2. The online path

```bash
make dev-up
```

Builds the images and starts Kafka, the registry, ClickHouse and Flink. Then start traffic:

```bash
docker compose --profile sim up -d producer
```

The simulator sends 1,000 events/s (`LOGS_PER_SECOND` to change it). After a minute:

```bash
make latency
```

prints event → row latency (p50 / p95 / p99) over the last minute.

| | URL |
|---|---|
| Flink UI | http://localhost:8082 |
| job metrics (Prometheus format) | http://localhost:9250/metrics |
| ClickHouse HTTP | http://localhost:8123 (user `watchtower`, password in `secrets/clickhouse_password`) |
| schema registry | http://localhost:8081 |
| Kafka (from the host) | `localhost:9092` |

An existing ClickHouse volume from an older version needs its schema brought up to date once:

```bash
make ch-migrate
```

```bash
make ch-recreate-ingest
```

### 3. Airflow

```bash
make airflow-up
```

Starts the stack with Airflow and the producer at 100 events/s. UI: http://localhost:8080 — user `admin`, password in `secrets/airflow_admin_password`. DAGs start **paused** in dev: unpause what you are working on (`watchtower_pipeline` first).

### 4. The AI reviewer (optional)

Put a Groq API key in the file (never in chat, never as an exported variable):

```bash
printf '%s' 'gsk_your_key' > secrets/groq_api_key
```

Then unpause `watchtower_review` and `watchtower_training`. Without a key the review is skipped; detection is unaffected.

### 5. Measure detection

```bash
make evaluate
```

joins the simulator's ground truth (read back from Kafka) to the pipeline's decisions: per attack type, per attack, time to first flag, false positives (split into containment and uninvolved hosts), the model's own alerts, coverage.

### Stop

```bash
make dev-down
```

Keeps every volume (data, checkpoints, Airflow's database).

---

## 10. Everyday commands

`make help` lists them all. The ones you will use most:

| command | does |
|---|---|
| `make dev-up` / `make dev-down` | start / stop the dev stack |
| `make airflow-up` | the stack + Airflow, producer at 100/s |
| `make latency` | end-to-end latency, last minute |
| `make evaluate` | detection vs ground truth |
| `make pipeline-health` | the latest end-to-end verdict from Airflow, stage by stage |
| `make ch-migrate` | apply `clickhouse/init/*.sql` (idempotent) |
| `make ch-bench` | benchmark the analyst queries |
| `make test` | every test suite (unit, Flink job, DAGs) |
| `make lint` | ruff |
| `make ci` | lint + tests + render the Kubernetes overlays |
| `make cluster-up`, `make deploy ENV=staging` | local Kubernetes |
| `make load RATE=10000`, `make watch-scaling` | load a cluster and watch it scale |

Benchmarks that run without the stack:

```bash
python3 tools/bench_detection.py --dump model.json
```

per-event detection cost with and without a model (`--dump`: a `ml_models.model` value saved to a file);

```bash
python3 tools/bench_model.py
```

single-event scoring cost by backend.

---

## 11. Configuration

Everything is an environment variable (Kubernetes: the `pipeline-env` ConfigMap; dev: `docker-compose.yml`). The ones you are most likely to change:

| variable | default | meaning |
|---|---|---|
| `LOGS_PER_SECOND` | `1000` | the simulator's rate |
| `WATCHTOWER_BLOCK_THRESHOLD` | `0.85` | score at or above which an event is blocked |
| `WATCHTOWER_THRESHOLD` | `0.65` | score at or above which an event is alerted |
| `WATCHTOWER_ML` | `on` | `off` scores with rules alone |
| `WATCHTOWER_ML_CAN_BLOCK` | `false` | let the model block without a rule agreeing |
| `WATCHTOWER_MODEL_POLL_SECONDS` | `300` | how often Flink checks for a newly promoted model |
| `WATCHTOWER_ML_MAX_ALERT_SHARE` | `0.005` | shadow check: most events a candidate may alert on alone |
| `WATCHTOWER_DEDUP_RECENT` | `1024` | event ids each source remembers for dedup |
| `WATCHTOWER_SOURCE_IDLE_MS` | 15 min | a silent source is forgotten after this |
| `WATCHTOWER_CHECKPOINT_INTERVAL_MS` | `10000` | Flink checkpoint interval |
| `WATCHTOWER_SYNTHETIC_TRAFFIC` | `true` in dev | `false` on real logs: no ground truth, no simulator labels |
| `GROQ_MODEL` | `openai/gpt-oss-safeguard-20b` | the reviewer's model |
| `GROQ_REASONING_EFFORT` | `medium` | how long it thinks per page |
| `GROQ_TOKENS_PER_MINUTE` | `8000` | your Groq plan's limit; pagination follows it |
| `WATCHTOWER_FLINK_RESTART` | `none` (dev), `operator` (k8s) | whether Airflow may restart a stopped stream job |

Secrets are never environment variables: each is a mounted file, read through `*_FILE` variables (`CLICKHOUSE_PASSWORD_FILE`, `GROQ_API_KEY_FILE`, …).

---

## 12. Kubernetes

`deploy/k8s` is a Kustomize base with `staging` and `prod` overlays; everything runs the same images as dev.

| | Kafka | Flink TaskManagers | purpose |
|---|---|---|---|
| staging | 1 controller + 1–2 brokers (autoscaled) | 1–3 (autoscaled) | production-shaped traffic, the promotion gate |
| prod | 3 controllers + 3–6 brokers, replication factor 3 | 5–24 (autoscaled; 5 ≈ 10,000 events/s) | the real shape |

- **Flink**: the Flink Kubernetes Operator's job autoscaler adds and removes TaskManager pods (one slot each) from busy time and Kafka backlog; checkpoints, HA and `upgradeMode: last-state` resume a restarted or rescaled job from its state.
- **Kafka**: Strimzi; a HorizontalPodAutoscaler on the broker pool, Cruise Control moving partitions onto new brokers and off leaving ones.
- **Airflow**: `components/airflow` — scheduler, DAG processor, API server, Postgres; a service account allowed only to restart the `stream` FlinkDeployment.

```bash
make cluster-up
```

```bash
make deploy ENV=staging
```

```bash
make smoke ENV=staging
```

`make promote` is the CD pipeline: CI → staging → smoke test → prod → smoke test. The manifests render and validate (`make render`); the full stack has not yet run on a real multi-node cluster — see [`docs/prod-readiness.md`](docs/prod-readiness.md).

---

## 13. Observability

- **Metrics**: the Flink job exports decisions per second by action, Kafka → decision latency (p50/p95/max), events scored, duplicates, rejects by reason, data-quality counters between every step (`dq_<step>_<issue>`), and decisions raised by the model.
- **Alerts** (`deploy/observability/alerts.yml`, 8 rules): `StreamJobDown`, `StreamFallingBehind`, `StreamLatencyHigh`, `StreamRejectingEvents`, `StreamDataQualityDegraded`, `StreamLogicInconsistent` (critical), `KafkaUnderReplicatedPartitions`, `KafkaBrokerDown`.
- **Grafana dashboard**: latency, backlog, decisions per second, TaskManagers, data quality between steps, model-raised decisions, Kafka and ClickHouse.
- **In ClickHouse**: `pipeline_health` (is it broken, and where?), `data_quality_checks`, `detection_quality`, `ml_decisions_hourly`, `ml_model_review`.

---

## 14. Testing and CI

| suite | runs in | proves |
|---|---|---|
| `tests/unit` | Flink test image | every per-event stage and reject reason; each rule; the compiled model equals LightGBM and stays inside its time budget; data-quality checks; secrets handling; the wire format |
| `tests/flink` | Flink test image | the real job on a local Flink mini-cluster: operators, keyed state, side outputs, both execution modes |
| `tests/orchestration` | Airflow test image | the DAGs parse and are wired as documented; checks, rollups, the pipeline verdict; training, the gate and shadow check; the paginated reviewer against a stand-in Groq; the evaluator |

```bash
make test
```

```bash
make ci
```

The GitHub Actions workflow (`.github/workflows/ci.yml`) runs the same targets, plus a schema-compatibility gate and a manifest render.

---

## 15. Performance

Measured on the development machine (8 GB RAM, Docker VM 3.8 GB) — details in [`docs/streaming.md`](docs/streaming.md) and [`docs/capacity-report.md`](docs/capacity-report.md).

| | result |
|---|---|
| end to end at 1,000 events/s (24 min) | median 194 ms, p95 346 ms; 66–84 ms median with 50 ms ClickHouse blocks and free memory |
| decision latency (Kafka → decided) | ~5 ms |
| per event in Flink | ~173 µs rules only, ~183 µs with the model |
| one TaskManager | ~4,100 events/s from Kafka (rules only), ~5,450/s estimated with the model on the detection code alone |
| this machine | ~1,000 events/s sustained with low latency, ~1,200 maximum — the limit is the Docker VM's memory, not the job |
| queries after the table relayout | 20–600× less data read for analyst drill-downs |

At 1,000 events/s each event has 1 ms; detection uses ~18% of it on one core.

---

## 16. Security and secrets

- Secrets are generated locally (`make secrets`), never committed, never written into images, manifests or environment variables: containers read mounted files. `make secrets` never overwrites; rotating is deliberate.
- The Airflow UI requires a login (generated password); Kubernetes RBAC limits Airflow to restarting one FlinkDeployment.
- **The AI reviewer sends event details to a third party (Groq)** — source IPs, usernames, URL paths, commands of up to 3,000 events a day. Confirm this is acceptable under your data policy before setting the key on real logs.
- Not yet: TLS and authentication on Kafka and ClickHouse, a secrets manager, multi-user Airflow — see [`docs/prod-readiness.md`](docs/prod-readiness.md) Phase 4.

---

## 17. Troubleshooting

| symptom | cause and fix |
|---|---|
| a container exits with code 137, `OOMKilled=true` | the Docker VM is out of memory. Give Docker more, lower `LOGS_PER_SECOND`, or pause the producer while Airflow trains. Kafka, the registry and ClickHouse restart on their own; nothing is lost (Kafka keeps what arrives meanwhile) |
| latency p95 in seconds, checkpoints taking seconds | memory pressure (swap full) — same fixes |
| `rejected_events` fills with `sink_parse_error` after an upgrade | ClickHouse's Kafka intake has old columns: `make ch-migrate` then `make ch-recreate-ingest` |
| the producer refuses to start: schema not registered | `schema-init` registers it; `docker compose up schema-init`, or `python tools/schema_registry.py register` |
| Groq HTTP 403 (`error code: 1010`) | the request had no proper User-Agent (fixed in `review.py`); if it persists, the key is invalid |
| Groq HTTP 429 | the tokens-per-minute limit; set `GROQ_TOKENS_PER_MINUTE` to your plan's value |
| an Airflow DAG is missing from the UI | an import error in the DAG file: `make test-airflow` shows it |
| a backfill does not run | the DAG is paused; backfill runs of a paused DAG wait |
| the model alerts on a whole group of hosts | roll back (`INSERT INTO watchtower.ml_model_active (version, reason) VALUES ('lgbm-…', 'rollback')`) or `WATCHTOWER_ML=off`; the hourly review's guard does it automatically when the AI calls most of its alerts benign |

---

## 18. Known limitations

- **Simulated traffic.** The model learns from the simulator's ground truth plus the AI's corrections; on real logs, analysts' verdicts must become labels before it should block.
- **Kubernetes not run on a real cluster** — manifests render and validate; autoscaling at scale is designed, not measured. 10,000 events/s is a projection from one TaskManager.
- **Single ClickHouse replica**; no backups yet. Replication (2 replicas + 3 ClickHouse Keeper nodes on separate machines) is production task 7.
- **The development machine** cannot run the whole stack, Airflow and the hourly jobs together for long: ClickHouse is killed for memory.
- **Detection gaps**: slow attacks (windows are 1 and 5 minutes); credential stuffing (features are per source IP, not per user).
- **Alerts notify no one** until an Alertmanager receiver and Airflow failure callbacks are configured.

---

## 19. Documentation

| document | for |
|---|---|
| [`docs/context.md`](docs/context.md) | the whole project: design decisions and why, data, current state, gaps, roadmap |
| [`docs/streaming.md`](docs/streaming.md) | the Flink job in depth: latency, per-event cost, scaling, model scoring cost |
| [`docs/orchestration.md`](docs/orchestration.md) | Airflow: every DAG, the learning loop, the gate, first runs |
| [`docs/operations.md`](docs/operations.md) | runbook: environments, tests, deploys, scaling, migrations, secrets, alerts, recovery |
| [`docs/capacity-report.md`](docs/capacity-report.md) | load tests on the development machine |
| [`docs/prod-readiness.md`](docs/prod-readiness.md) | the 38 tasks between this and production |
| [`NOTE_TO_SOC_ANALYST.md`](NOTE_TO_SOC_ANALYST.md) | for the analyst: what each rule means, reading the columns, tuning, investigating an alert |
