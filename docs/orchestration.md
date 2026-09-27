# Watchtower — orchestration (Airflow)

Airflow is where the whole pipeline is run and watched from. Every 10
minutes one DAG walks the path an event takes — Kafka, the Flink job,
ClickHouse — checks each stage, restarts the stream job if it has
stopped for good, and records the verdict. Around it, scheduled DAGs
check what was stored, roll up closed days and measure detection.

The events themselves are never scheduled: Flink decides each one as it
arrives, in milliseconds. Airflow supervises that stream; it does not
replace it with batches.

| | runs | owned by |
|---|---|---|
| per event, continuously | decode → validate → features → rules → ClickHouse | Flink (`etl/stream/job.py`) |
| every 10 minutes | the pipeline end to end: services, stream job, extract → transform → load | **Airflow** `watchtower_pipeline` |
| per hour / day / 6 hours | data-quality checks, daily rollup, detection quality | **Airflow** (`orchestration/dags/`) |
| on a threshold, continuously | job down, falling behind, slow, rejecting | Prometheus alerts (`deploy/observability/alerts.yml`) |

Airflow brings what cron would not: runs tied to a **data interval** (the
hour or day they cover), retries, a record of every run, dependencies
between steps, and **backfills** — rebuild any past day with one command.

*Added 2026-09-27. Airflow 3.3.2, Postgres 18.6 for its metadata.*

---

## 1. The DAGs

| DAG | schedule | steps | writes | the run fails when |
|---|---|---|---|---|
| `watchtower_pipeline` | every 10 min | services → stream_job → sample_flow → extract, transform, load → record → verdict | `pipeline_health` | a service is down, the stream job is not running, or a stage is stalled or behind |
| `watchtower_data_quality` | hourly, for the hour just closed | 6 checks in parallel → record → gate | `data_quality_checks` | a **fail** check fails |
| `watchtower_daily` | daily, for the UTC day just closed | day_closed → deduplicate → summarize → reconcile | `daily_summary`, `daily_rule_hits`, `daily_top_sources` | the summary does not count exactly the day's events |
| `watchtower_detection_quality` | every 6 h (:15) | pipeline_healthy → evaluate → assess → record → gate | `detection_quality` | an attack was missed, detection got slow, coverage dropped, or uninvolved hosts were blocked |

Tables: `clickhouse/init/04_orchestration.sql`.

### The pipeline, every 10 minutes

```
kafka ──────────┐
schema_registry ┼─> stream_job ─> sample_flow ─┬─> extract ───┐
clickhouse ─────┘                             ├─> transform ─┼─> record ─> verdict
                                              └─> load ──────┘
```

The graph follows the data, so a failed run is red **at the stage that is
broken** (`orchestration/ops/pipeline.py`):

| task | checks | fails when |
|---|---|---|
| `kafka`, `schema_registry`, `clickhouse` | each answers; the 3 topics, the registered schema, the 5 pipeline tables exist | one is down or not set up |
| `stream_job` | the Flink job is RUNNING **with every task running** (Flink says RUNNING while tasks still wait for a TaskManager) | not so within 5 min |
| `sample_flow` | each topic's end offsets, 20 s apart, and both consumer groups' committed offsets | Kafka unreachable |
| `extract` | events/s arriving in `security-logs`; share refused (warn) | fewer than `min_input_rate` (1/s) |
| `transform` | Flink's lag in seconds of traffic; results written per event arriving; the job's **between-step data-quality counters** over the 20 s sample (doubtful share warns > 1%, naming the issues) | > 120 s behind; < 0.5 written per arrival; any feature/decision contradiction |
| `load` | ClickHouse's intake lag; rows landed in the last minute; p95 latency (warn); Kafka-engine errors (warn) | > 60 s behind; no rows while events arrive |

**Restarts.** A job that has stopped for good (FAILED, CANCELED) is
restarted: in Kubernetes by bumping the FlinkDeployment's `restartNonce`
— the operator redeploys it from its last checkpoint — with a service
account allowed to patch that one FlinkDeployment and nothing else. The
restart is recorded as a warning, so it stays visible after the job is
back. A job the operator or Flink is already restarting is waited for,
not restarted again. In docker compose, restart policies and
`run-job.sh` bring a crashed job back, and the task says what to run.

`record` runs even after a stage failed (`trigger_rule="all_done"`): each
stage saves its results before it fails, so a broken run keeps its
evidence in `watchtower.pipeline_health`. That makes `record` succeed
either way — and Airflow judges a run by its last tasks, so the first
broken run showed **green** with `extract` red inside it. `verdict`
(`trigger_rule="one_failed"`, downstream of every check) fixes that: it
is skipped when all passed and fails when any did, so the run's own state
is the pipeline's. A healthy `load` marks the
`watchtower_security_events` asset updated (Airflow's **Assets** view),
and `watchtower_detection_quality` waits for a healthy verdict from the
last 20 minutes before it measures — or is skipped.

```sql
-- the latest verdict, stage by stage
SELECT stage, check_name, passed, detail FROM watchtower.pipeline_health
WHERE run_id = (SELECT argMax(run_id, checked_at) FROM watchtower.pipeline_health)
ORDER BY stage;
```

### Hourly data quality

Prometheus watches the **pipeline**; these check the **data** it wrote,
one closed hour at a time (`orchestration/ops/quality.py`):

| check | severity | passes when | why |
|---|---|---|---|
| `volume` | fail | ≥ 1 event stored | an empty hour means the stream stopped |
| `rejected_share` | fail | ≤ 1% of messages refused | a producer or schema problem |
| `missing_identity` | fail | no event without `source_ip` / `event_type` | detection is keyed on them |
| `latency_p95_ms` | warn | p95 event → row ≤ 2 s | a slow hour the alert may have missed |
| `duplicate_share` | warn | ≤ 1% replay copies not yet merged | many means the job keeps restarting |
| `block_share_vs_7d` | warn | block share ≤ 5× the trailing week | an attack wave, or a rule gone wrong |

Every result is recorded, passed or not; **warn** results never fail the
run. Adding a check is one `Check(...)` entry — a name, a severity, a
threshold and one SQL query returning one number.

### Daily rollup

1. **day_closed** (sensor, reschedule mode) — waits until the stream has
   stored events from 2+ minutes after midnight, so the day's own are all
   in; a day that ended over an hour ago counts as closed regardless.
2. **deduplicate** — at-least-once delivery can leave replayed copies until
   ReplacingMergeTree merges them. If the day has any,
   `OPTIMIZE ... PARTITION ... FINAL` folds them.
3. **summarize** — drops the day's partition in each daily table and
   inserts it again, from `security_events FINAL`.
4. **reconcile** — `sum(events)` in `daily_summary` must equal the day's
   stored events, exactly.

Every step is idempotent, so any day can be re-run or backfilled:

```bash
docker exec watchtower-airflow airflow backfill create --dag-id watchtower_daily \
  --from-date 2026-09-01 --to-date 2026-09-26
```

### Detection quality

Runs `tools/evaluate_detection.py` over the last 15 minutes (a
**Trigger DAG w/ config** `{"minutes": N}` changes it) and judges the
report (`orchestration/ops/detection.py`):

| threshold | value | measured, 1,000 events/s, 15 min |
|---|---|---|
| coverage (events in Kafka with a decision) | ≥ 99.9% | 100% |
| attacks never flagged | 0 | 0 of 29 |
| median time from an attack's first event to its first flag (new sources) | ≤ 5 s | 0.4–1.6 s per attack |
| normal events blocked on hosts that were **not** attacking | ≤ 0.01% | 0.0008% (7 of 868,112) |

Deliberately **not** gated: the share of attack *events* flagged. A
behavioural rule needs its first few events (7 for lateral movement, 19 for
a password spray) before it can fire, so that share depends on the mix of
attacks in the window: the first scheduled run held two small attacks and
came out at 91.9% with both caught within 1.5 s. It is recorded in the
table, not used to fail the run.

Defined only where `WATCHTOWER_SYNTHETIC_TRAFFIC=true`: real logs carry no
ground truth.

---

## 2. Where the code lives

```
orchestration/
├── dags/                               schedules and dependencies only
│   ├── watchtower_pipeline.py
│   ├── watchtower_data_quality.py
│   ├── watchtower_daily.py
│   └── watchtower_detection_quality.py
└── ops/                                the work, plain Python
    ├── clickhouse.py                   HTTP client, query parameters, no provider
    ├── pipeline.py                     services, stream job (+ restart), flow, stages
    ├── quality.py  daily.py  detection.py
tools/evaluate_detection.py             also a CLI (`make evaluate`)
docker/airflow/                         Dockerfile, requirements, start.sh
deploy/k8s/components/airflow/          the Kubernetes deployment (+ restart RBAC)
tests/orchestration/                    ops, pipeline, evaluator, DAG structure
```

The DAG files only wire `ops` functions together. The work itself is
tested without Airflow, Flink or ClickHouse — stand-ins record every
statement and script the Flink API and the clock, so waiting, restarting
and giving up are each driven directly — and the DAG files are tested for what the dag-processor does
every minute: parse them. An import error there would otherwise make a DAG
silently vanish from the UI.

---

## 3. Running it

### Dev (docker compose)

```bash
make airflow-up        # dev stack + Airflow; producer at 100 events/s
```

UI on http://localhost:8080 — user `admin`, password in
`secrets/airflow_admin_password`. DAGs start **paused** in dev (Airflow's
default): unpause what you are working on, or every hourly check fails
while the stack is stopped. `orchestration/` is mounted into the
container, so an edited DAG or check is live within a minute.

The producer runs at 100 events/s here, not 1,000: the 1,000/s stack alone
fills this machine's 3.8 GB Docker VM and its swap
([`capacity-report.md`](capacity-report.md)). Airflow needs ~0.3 GB idle
and ~0.5 GB while a task runs; its Postgres ~30 MB.

In dev, the API server, scheduler and DAG processor run in one container
(`docker/airflow/start.sh`). A backfill of a paused DAG waits until it is
unpaused.

### Kubernetes

The component is in both overlays. Four workloads, one image:

| workload | role | memory (request / limit) |
|---|---|---|
| `airflow-db` (StatefulSet) | Postgres, Airflow's metadata | 64 Mi / 256 Mi |
| `airflow-scheduler` | schedules runs; runs their tasks (LocalExecutor); migrates the DB first | 512 Mi / 1 Gi |
| `airflow-dag-processor` | parses the DAG files | 192 Mi / 384 Mi |
| `airflow-api-server` | UI, REST API, the execution API tasks report to | 256 Mi / 512 Mi |

DAGs start **unpaused** there (`AIRFLOW__CORE__DAGS_ARE_PAUSED_AT_CREATION=False`).
`make airflow-ui ENV=staging` port-forwards the UI.

### Secrets

`make secrets` generates `airflow_db_password`, `airflow_admin_password`
and `airflow_jwt_secret` (64 bytes: it signs the tokens the components hand
each other, HS512). They are mounted files. Airflow reads them through
`*_CMD` options (`AIRFLOW__DATABASE__SQL_ALCHEMY_CONN_CMD`,
`AIRFLOW__API_AUTH__JWT_SECRET_CMD`); the admin password is written into the
auth manager's password file at start. No secret sits in an image, a
manifest or an environment variable.

---

## 4. Design choices

- **Airflow 3.3, `airflow.sdk` decorators.** Each DAG sets its timetable
  explicitly: Airflow 3's default for cron schedules has no data interval,
  and the hourly and daily DAGs are defined by the interval they cover
  (`CronDataIntervalTimetable`). Detection quality measures "the minutes
  before now" and uses a trigger timetable.
- **Record, then gate.** Checks never raise; a `record` task stores every
  result and a separate `gate` task fails the run. A failed run still
  leaves its evidence in ClickHouse.
- **LocalExecutor.** Every task but one is a few SQL statements; the
  evaluator holds 15 minutes of ground truth (~300 MB at 1,000 events/s).
  Tasks run in the scheduler's pod, which is sized for that.
- **ClickHouse over HTTP with query parameters,** not a provider: the
  client is ~70 lines, values never reach SQL by string formatting, and a
  day spelled into `ALTER ... PARTITION` (which takes no parameters) must
  parse as a date first.
- **Memory-bounded SQL.** Copies are counted as `count() − count() FINAL`,
  not with `uniqExact(event_id)`: FINAL merges while reading, while
  uniqExact would hold a whole day of ids (~1.4 GB for 43M events, over
  this ClickHouse's 1.6 GiB cap).

---

## 5. First runs (dev, 2026-09-27)

| run | result |
|---|---|
| data quality, 14:00–15:00 | 5 of 6 checks passed; **`latency_p95_ms` warned at 56 s**. Correct: that hour held the evaluator's Kafka read (latency spiked to 16–30 s) and the events left undecided when the stack was stopped, decided at restart |
| daily, backfill of 2026-09-24 | 2,144,887 events summarized = 2,144,887 stored; top sources the four hostile IPs and one compromised workstation |
| daily, 2026-09-26 (no data) | passed: nothing to fold, 0 = 0 |
| detection quality, scheduled | failed on the then-gate "≥ 95% of attack events flagged" (91.9%, two attacks, both caught) — the reason that gate was replaced (§1) |
| detection quality, manual, 10 min | passed: 29,493 events, 6/6 attacks caught, median first flag 1.02 s, coverage 100%, no uninvolved host blocked |

Login with the generated password works; a wrong one gets HTTP 401.

---

## 6. Known gaps

- **Nobody is told when a run fails.** Failures show in the UI and the
  tables; no email, Slack or PagerDuty callback is configured.
- **One admin user** (Airflow's simple auth manager; Airflow itself warns
  it is not meant for production). Several users with roles need the FAB
  or Keycloak auth manager.
- **The Kubernetes component has not run on a cluster** — rendered and
  validated only, like the rest of staging (context.md §9).
- **Replays are not orchestrated.** The Spark path exists for replays and
  backfills of the *stream*; launching it from Airflow (a
  KubernetesPodOperator task) is the obvious next DAG.
- **Tasks share the scheduler's pod.** Fine for SQL; a heavier task would
  want the KubernetesExecutor, one pod per task.
