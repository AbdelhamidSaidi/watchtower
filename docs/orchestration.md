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
| `watchtower_review` | hourly, for the hour just closed | collect_labels, select → judge (Groq) → learn, urgent, guard | `training_labels`, `event_reviews` | the reviewer is ≥ 90% sure an **allowed** event was malicious; or the guard rolled a model back |
| `watchtower_training` | **when the reviewer adds labels**, and nightly 02:30 UTC | train_and_promote | `ml_models`, `ml_model_active` | training errors (a model that is not better is simply not promoted) |

Tables: `clickhouse/init/04_orchestration.sql`, `05_ml.sql`.

### The learning loop: online, OLAP, MLOps

```
 ONLINE    Kafka ─> Flink: rules + LightGBM v(n), ~10 µs/event ─> ClickHouse security_events
                         ^                                                │
 MLOps       deploy: Flink loads the promoted model ≤ 5 min, no restart   │ every hour (a batch)
                         ^                                                v
             promote only if at least as good    OLAP  watchtower_review: the AI (Groq)
             on a holdout the AI never touched         judges a sample of the hour
                         ^                                                │
             watchtower_training  <── starts at once ── training_labels <─┘ confident
             (+ nightly)               (asset)                              disagreements
                         │
             guard: the AI calls most of v(n+1)'s own alerts benign -> back to v(n)
```

**Speed.** The model adds ~10 µs per event (120 trees, compiled; p99
18 µs) — with the job's ~173 µs, ~183 µs of the 1 ms each event has at
1,000/s, or ~5,450 events/s per TaskManager (`tools/bench_detection.py`;
`tests/unit/test_ml.py` fails the build if the model ever costs 100 µs).

**The reviewer (`watchtower_review`).** At 1,000/s an hour is 3.6 million
events, so it samples, at most 150 a run and 3,000 a day:

| sample | from | a confident verdict that disagrees becomes |
|---|---|---|
| `near_miss` | allowed, the highest model scores | label 1: an attack the model let through |
| `unusual` | allowed, the hour's top 0.1% on a behaviour feature | label 1 |
| `random` | allowed, uniform — served first, so the miss-rate estimate stays honest | label 1 |
| `model_alert` | alerted by the **model alone** (no rule fired) | label 0: a false alarm the model must unlearn |

The AI is Groq's `openai/gpt-oss-safeguard-20b` (`GROQ_MODEL`), a
classifier built to judge content against a policy you write — here, the
SOC review policy in `orchestration/ops/review.py` — with
`reasoning_effort=medium`, no streaming: a batch job needs the answer,
not the tokens as they come.

*Pagination.* The free tier allows **8,000 tokens a minute**
(`GROQ_TOKENS_PER_MINUTE`), and a page of reasoning costs thousands. So
requests are paginated: each page holds at most 10 events and at most
half the minute (prompt + the longest answer allowed, 600 + 150 tokens
per event); a one-minute ledger books each page's worst case before it is
sent and waits until it fits under 90% of the limit, then corrects the
booking to what the page really cost. A full run of 150 events is 15
pages, 2–8 minutes. A 429 still waits for Groq's `Retry-After`; verdicts
already obtained survive a failure. (Requests also carry a User-Agent:
Groq's firewall refuses Python's default one with 403, error 1010.)

Every verdict is kept in `event_reviews`; the view `label_changes` lists
the disagreements. At ≥ 80% confidence a disagreement becomes a label,
weighted at half a typical sampled event — a second opinion, not an
oracle — and marks the
`watchtower_training_labels` asset updated, which **starts a retraining
at once**. At ≥ 90% and *malicious* on an allowed event, the run fails:
someone should look now. Without a Groq key the review is skipped; the
simulator's labels are still collected, and the nightly run still trains.

**The guard.** A promoted model is watched through the reviewer's eyes: if
more than half of its own alerts in 24 h (at least 20 reviewed) are
judged benign, the previous model is promoted back and the review run
fails, so someone sees it.

**OLAP over the model** (ClickHouse views, `05_ml.sql`):

```sql
-- what each model did, hour by hour
SELECT * FROM watchtower.ml_decisions_hourly ORDER BY hour DESC, ml_model LIMIT 24;
-- how each model fares under review: false alarms, missed attacks
SELECT * FROM watchtower.ml_model_review ORDER BY hour DESC LIMIT 24;
```

**Drift.** The hourly data-quality DAG checks `ml_score_drift_psi`: the
population stability of the model's scores this hour against the past
week (warn above 0.25). It needs a week of history to mean anything: on
the first day it compares against minutes, and warns.

**Training (`watchtower_training`)** runs whenever the reviewer adds
labels, and nightly. It uses 14 days of labels — the simulator's ground
truth, collected hourly from Kafka, plus the reviewer's confident
corrections — joined to the features the pipeline stored.

*Labels, sampled per source.* Every attack event is kept. Normal events
are ~97% of traffic, so at most 5 per source per hour are kept (a
reservoir sample), each weighted by how many of that source's events it
stands for. A uniform 2% sample was tried first and left quiet hosts —
the remote staff — so thin that a model learned "external IP + data
volume" as an attack and alerted on every VPN user; per source, every
host is in the data, and the weights still add up to the real traffic.

*The gate.* The holdout is chosen by a hash of the event (a rerun splits
the same way) and never contains a reviewer label: judging a model on
the reviewer's own opinions would reward agreeing with it. The candidate
is registered either way, and **promoted** only if, against the active
model:

| check | on | passes when |
|---|---|---|
| ranking | the holdout | average precision no lower (within 0.005) |
| false alarms | the holdout's normal events | no more than chance explains: the active model's count plus a 95% Poisson margin (0 → up to 4.9, 10 → 18.1) |
| corrections | events the reviewer relabelled | wrong on no more of them than the active model |
| **shadow** | up to 20,000 real events from the last 6 hours, at most 50 per source (every host represented) | alerts it would raise on its own (no rule behind them): ≤ 0.5% of events, ≤ 1.5× the active model's, **on ≤ 1.5× as many hosts** |

The shadow check scores real traffic the way the stream would, so a
model that would flood the SOC is refused before it goes live, not
rolled back after. The model is sized for the stream (≤ 120 trees × 15
leaves: ~10 µs per event, `tools/bench_detection.py`).

**Rolling back** is inserting an older version into `ml_model_active`;
`WATCHTOWER_ML=off` on the Flink job scores with rules alone.

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
    ├── training.py                     labels, dataset, LightGBM, evaluation, promotion
    ├── review.py                       candidates, the Groq reviewer, labels from it
    ├── quality.py  daily.py  detection.py
tools/evaluate_detection.py             also a CLI (`make evaluate`)
docker/airflow/                         Dockerfile, requirements, start.sh
deploy/k8s/components/airflow/          the Kubernetes deployment (+ restart RBAC)
tests/orchestration/                    ops, pipeline, training, reviewer, evaluator, DAGs
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

### The first learning cycles (dev, 2026-09-28)

| step | result |
|---|---|
| first model, 16 min of labels | promoted; ~4 alerts/min on its own at 100 events/s |
| Groq, first calls | 403 (firewall: Python's default User-Agent), then 429 (8,000 tokens/min) — fixed by a User-Agent and paginated requests |
| review of 15:00–16:00 | 94 events judged; 3 model-only alerts on a partner's sync traffic judged benign at 95% → 3 "false alarm" labels → retraining started by itself (asset) |
| retraining, old gate | candidate fixed the 3 (0.79–0.85 → 0.00) but was refused: 2 false alarms vs 0 on 1,496 normal holdout events — noise. Gate changed to a statistical margin |
| retraining, new gate | promoted: the active model had fallen to **77.8%** of attacks at the alert line on the newer hours; the new one caught **99.98%** |
| that model, live | **2.1% of events alerted on by the model alone — all remote-staff VPN hosts.** A uniform 2% label sample had left them out; the holdout could not see it |
| fix | labels sampled per source; a **shadow check** on the newest hour of real traffic added to the gate |
| retraining, per-source labels + shadow | promoted: 14 vs 17 model-only alerts on 20,000 recent events; 0 of the reviewer's 13 relabelled events wrong (4 before) |
| that model, live, 66,624 events | **0.12%** model-only alerts; **none on remote staff** after the first 3 minutes (the restart's replay). The rest: port scans from attacker IPs and internal port scans / SSH — flagged before a rule could fire |

ClickHouse was killed for memory twice that day (17:27, 19:07), each time
with the whole stack, Airflow and the hourly jobs running on the 3.8 GB
Docker VM. No data was lost -- the Kafka intake commits only after an
insert, so what arrived meanwhile was inserted on restart -- but it stayed
down until started by hand: ClickHouse, Kafka and the schema registry had
no restart policy in `docker-compose.yml`. They have `unless-stopped` now
(a container killed for memory is back within seconds -- tested).

---

## 6. Known gaps

- **Nobody is told when a run fails.** Failures show in the UI and the
  tables; no email, Slack or PagerDuty callback is configured.
- **One admin user** (Airflow's simple auth manager; Airflow itself warns
  it is not meant for production). Several users with roles need the FAB
  or Keycloak auth manager.
- **The Kubernetes component has not run on a cluster** — rendered and
  validated only, like the rest of staging (context.md §9).
- **Replays are not orchestrated.** Reprocessing a time range would be a
  bounded run of the Flink job over those Kafka offsets, launched from
  Airflow; not built yet.
- **The model learns the simulator** — its labels are the producer's ground
  truth and the reviewer's corrections. On real traffic, analysts' verdicts
  must become labels before it can be trusted to block.
- **Tasks share the scheduler's pod.** Fine for SQL; a heavier task would
  want the KubernetesExecutor, one pod per task.
