# Watchtower — operations runbook

How to run, test, deploy, scale and troubleshoot the pipeline. Every
workflow is a `make` target; `make help` lists them.

For what the system is and why it is built this way, see
[`context.md`](context.md); for the live, per-event path (Flink) and its
latency, [`streaming.md`](streaming.md). For tuning detection, see
[`NOTE_TO_SOC_ANALYST.md`](../NOTE_TO_SOC_ANALYST.md).

---

## 1. Environments

| | runs on | Kafka | stream processing (Flink) | purpose |
|---|---|---|---|---|
| **dev** | docker compose | 1 combined node | 1 JobManager + 1 TaskManager (1 slot) | seconds-long edit/run loop |
| **staging** | k3d (Kubernetes) | 1 controller + 1–2 brokers (autoscaled) | 1–3 TaskManagers (autoscaled) | production-shaped traffic, the promotion gate |
| **prod** | k3d (Kubernetes) | 3 controllers + 3–6 brokers (autoscaled), RF 3 | 5–24 TaskManagers (autoscaled; 5 = 10,000 events/s) | the real shape |

Flink is the only engine: the Spark pipeline that preceded it was removed
on 2026-09-28.

All three run the **same image** and the **same Kafka version (4.3.1)**. They
differ only in configuration, so a change that works in staging fails in
prod only for reasons of scale, not version skew.

**Memory is the local constraint -- measured, not estimated.** This
machine has 8 GB of RAM and gives Docker a ~3.83 GB VM.

| what runs | fits? |
|---|---|
| dev (compose), Flink path, 1,000 events/sec | **yes** -- with `clickhouse/config/dev-limits.xml`: ~2.8 GB used, 194 ms median / 346 ms p95 end to end ([`streaming.md`](streaming.md) §3) |
| dev (compose) at 100 events/sec | **yes** -- verified end to end |
| staging, Kafka layer only (pipeline paused) | **yes** -- broker scaling verified here |
| staging, full stack | **no** -- node at 87-89% memory, 400-600% CPU, API server timing out; the pipeline alone is ~1.5 GiB |
| prod (3 controllers, 3 brokers, executors) | no -- needs ~7-8 GB |

Pushing past that crashed the Docker VM once ("Internal Virtualization
error") and corrupted images inside the k3d node. **Run one heavy phase at
a time**: build and test with the cluster stopped (`k3d cluster stop
watchtower`), then run the cluster with nothing else. To run full staging
here, raise Docker Desktop's memory (Settings → Resources) and close other
apps -- or run staging on a larger machine.

---

## 2. First run

```bash
make secrets        # generate secrets/ (random passwords, empty groq key)
make dev-up         # build the images, start the dev stack
docker compose --profile sim up -d producer    # 1,000 events/sec
make latency        # end-to-end p50/p95/p99 over the last minute
```

`http://localhost:8082` — Flink UI (job graph, per-operator busy time)
`http://localhost:9250/metrics` — the job's metrics (TaskManager)

An existing ClickHouse volume needs the migrations once, then the Kafka
intake recreated (its columns cannot be altered):

```bash
make ch-migrate && make ch-recreate-ingest
```

Detection needs no key: rules and the model run in the stream. The hourly
LLM review (Airflow, `watchtower_review`) is skipped until you add a Groq
key; Airflow reads it on the next run:

```bash
printf '%s' 'gsk_...' > secrets/groq_api_key
```

---

## 3. Tests and CI

```bash
make test-unit      # engine-free unit tests, seconds
make test-flink     # + the job on a local Flink mini-cluster
make test           # test-flink + test-airflow: every suite
make test-airflow   # DAGs parse and are wired as documented; ops, training, reviewer
make ci             # lint + tests + render both overlays
make evaluate       # detection vs ground truth, per attack type (dev)
```

Tests run **inside the test stage of the Flink image** (unit, the job, lint)
and of the Airflow image (the DAGs and their ops), so they see the same
Python and libraries as production.

| suite | what it proves |
|---|---|
| `unit/test_processor` | decode → validate → normalize → enrich → dedup → features → rules, per event; every reject reason |
| `unit/test_rules` | each attack blocked with its reason; benign look-alikes allowed |
| `unit/test_ml` | the compiled model gives LightGBM's own numbers; the model may alert but not block alone; hot-swap and kill switch |
| `unit/test_dq` | a clean event passes every step boundary; each doubtful case is named where it appears |
| `unit/test_config`, `test_registry` | secrets from files, never printed; the wire format and registry client |
| `flink/` | the real job on a local Flink mini-cluster: operators, keyed state, side output, both execution modes |
| `orchestration/` | the DAGs parse and are wired as documented; checks, rollup, pipeline verdict, training and promotion, the Groq reviewer (against a stand-in API), the evaluator |

CI (`.github/workflows/ci.yml`) runs the same targets, plus a schema
compatibility gate (§5).

---

## 4. Deploying (CD)

```bash
make cluster-up      # once: k3d cluster + Strimzi operator
make promote         # ci -> staging -> smoke -> prod -> smoke
```

`promote` stops at the first failure. Prod is never deployed unless CI
passes **and** staging passes its smoke test on the same images.

Deploy one environment by hand:

```bash
make images-import           # after any image change
make deploy ENV=staging
make smoke ENV=staging
```

**The smoke test checks behaviour, not pod status.** A pod can be Running
while storing nothing. It verifies: Kafka reconciled, schema registered at
BACKWARD, both queries running, `security_events` actually growing over 45s,
zero duplicates, zero rejects, batches inside the trigger interval, and
Prometheus actually scraping.

GitHub-hosted runners cannot reach a laptop cluster, so CD runs locally.
To trigger it from GitHub, register the host as a self-hosted runner.

---

## 5. Changing the schema

The wire format is Avro, registered in a Confluent-compatible registry
(Karapace) at **BACKWARD** compatibility.

**Allowed:** adding a field **with a default**. Removing a field.
**Refused:** adding a field without a default, changing a type, renaming.

```bash
# 1. edit schemas/security_event.avsc
make schema-check              # against the dev registry
# 2. register it (CI does this through the same CLI)
python3 tools/schema_registry.py register --url http://localhost:8081
# 3. restart the pipeline, THEN roll out producers
```

**Order matters.** The pipeline learns every registered version at startup,
and decodes each message with the version that wrote it. A producer on a
version registered after the pipeline started is rejected with
`unknown_schema_version` — loudly, never misread — until the pipeline
restarts.

Producers never register schemas. A producer whose schema is not already
registered refuses to start.

---

## 6. Scaling

Both layers scale **on demand** on Kubernetes; nothing needs a person.

| what | autoscaler | signal | bounds (staging / prod) |
|---|---|---|---|
| Flink TaskManagers | Flink operator's job autoscaler | operator busy time + Kafka backlog (60% busy target, backlog cleared within 2 min) | 1–3 / 5–24 |
| Kafka brokers | HPA `kafka-brokers` on the broker KafkaNodePool | broker CPU (70% of request) | 1–2 / 3–6 |

```bash
make watch-scaling ENV=staging     # TaskManagers, parallelism, brokers, lag, latency
make load ENV=staging RATE=3000    # a surge, without a redeploy
```

Details, and why each scales the way it does: [`streaming.md`](streaming.md) §4.

### Kafka brokers

A new broker joins **empty**. Cruise Control's auto-rebalance
(`spec.cruiseControl.autoRebalance` on the Kafka CR) moves partitions onto
it after it joins, and off a broker **before** Strimzi removes it. The HPA
is deliberately slow both ways (3 min up, 15 min down, one broker at a
time): every change copies data between brokers.

`make deploy` keeps the broker count the HPA chose
(`keep-scaled-replicas.py`): a KafkaNodePool must carry `replicas`, and a
plain re-apply would reset it.

To pin the count instead of autoscaling:

```bash
make scale-kafka ENV=staging BROKERS=2    # sets the HPA's min and max to 2
make unpin-kafka ENV=staging              # back to the overlay's bounds
```

The manual path (without Cruise Control), still available as
`deploy/k8s/scripts/rebalance-topic.sh`, was measured first:

**Up:** grow the broker pool, wait for the new brokers, then rebalance
**every** topic onto all of them.

**Down:** the order is reversed, and it matters. Strimzi removes the
highest-numbered brokers, so every partition is first moved onto the
brokers that will **remain**; only then does the pool shrink. Shrinking
first would take partitions' only copy with it.

**Rebalance all topics, not just yours.** Kafka's internal topics --
`__consumer_offsets` (50 partitions) and the registry's `_schemas` -- were
created while there was one broker, and they stay there. Rebalancing only
`security-logs` after scaling to 3 left broker 0 leading **53 of 57**
partitions; `--all` brought it to **19 / 18 / 20**.

Measured on this machine:

| | result |
|---|---|
| 1 → 3 brokers, including the rebalance | **43 s** |
| load across 3 brokers (150,000 records, one producer) | **90,198 records/s**, split 34 / 33 / 33% |
| 3 → 1 brokers | **12 s**, all 48,400 messages retained |
| monitoring | Prometheus discovered the new brokers with no config change |

Controllers are a separate pool and are **not** touched: changing the KRaft
controller quorum is a different and riskier operation.

Replication factor is fixed at topic creation. Cruise Control (now
deployed for auto-rebalance) can raise it on a live topic.

---

## 6b. ClickHouse migrations

**security_events layout** (`01_schema.sql`): sorted by
`(toStartOfTenMinutes(timestamp), source_ip, timestamp, event_id)` with
bloom-filter (event_id) and min/max (timestamp, ingested_at) skip indexes.
An existing install moves onto it with `make ch-relayout` (writers stopped
first; copies hour by hour, swaps atomically, keeps the old table as
`security_events_before_relayout` until you drop it). `make ch-bench`
measures the analyst/evaluator/latency queries against any table.

Measured on 43M events: one event by id 683 MB → 3 MB read; one IP's whole
history 1 GB → 5 MB; one IP ±15 min 101 MB → 1 MB; the latency check
342 MB → 2 MB; the table 31% smaller. Short time-range queries read ~1.3x
more rows (10-minute buckets) and stay at 10-20 ms.

**Kafka-engine settings** cannot be ALTERed: after changing
`03_streaming_ingest.sql`, run `make ch-recreate-ingest` (offsets live in
the Kafka consumer group, so nothing is skipped).

`clickhouse/init/*.sql` run in order on a fresh volume. **Every statement
is idempotent**, so the same files upgrade an existing one:

```bash
make ch-migrate                    # dev
make ch-migrate-k8s ENV=staging    # a running cluster
```

A materialized view lives only in the migration that last changed its
columns. ClickHouse analyses a view's SELECT even under `IF NOT EXISTS`, so
defining it next to a `CREATE TABLE IF NOT EXISTS` fails on any volume
whose table predates the columns the view reads.

---

## 7. Secrets

| secret | used by | source |
|---|---|---|
| `clickhouse_password` | ClickHouse server, pipeline | generated |
| `grafana_admin_password` | Grafana | generated |
| `groq_api_key` | the hourly LLM review (Airflow) | **you** — empty skips the review; detection is unaffected |
| `airflow_db_password` | Airflow's Postgres, Airflow | generated |
| `airflow_admin_password` | Airflow UI (`admin`) | generated |
| `airflow_jwt_secret` | tokens between Airflow's components | generated, 64 bytes |

Files live in `secrets/` (git-ignored, mode 600). They reach containers as
**mounted files**, never as values in a manifest or compose file: an env var
leaks through `docker inspect`, `kubectl describe` and crash dumps.

`make secrets` never overwrites. To **rotate**, delete the file and re-run,
then redeploy. ClickHouse keeps its password in its data volume, so
rotating that one also needs the ClickHouse user updated in place.

---

## 7b. Orchestration (Airflow)

The pipeline end to end every 10 minutes (`watchtower_pipeline`: services,
stream job, extract → transform → load; restarts a stopped stream job in
Kubernetes), plus hourly data-quality checks, the daily rollup and
detection quality. Full description: [`orchestration.md`](orchestration.md).

```bash
make airflow-up                    # dev: stack + Airflow, producer at 100/s
                                   # UI http://localhost:8080, admin / secrets/airflow_admin_password
make airflow-ui ENV=staging        # Kubernetes: port-forward the UI
docker exec watchtower-airflow airflow dags unpause watchtower_pipeline
make pipeline-health               # dev: the latest end-to-end verdict, stage by stage
docker exec watchtower-airflow airflow backfill create --dag-id watchtower_daily \
  --from-date 2026-09-01 --to-date 2026-09-26          # rebuild past days
```

DAGs start paused in dev and unpaused in Kubernetes. A **failed** run is
data, not noise: the reason is in the task log and in
`watchtower.data_quality_checks` / `watchtower.detection_quality`. A failed
daily `reconcile` means events for that day arrived after the rollup —
clear the run and it rebuilds the day.

On an existing dev ClickHouse volume, `make airflow-up` applies
`clickhouse/init/04_orchestration.sql` itself; in Kubernetes,
`make ch-migrate-k8s ENV=...`.

---

## 8. Alerts

Open Prometheus (`make prometheus` → `/alerts`) or Grafana (`make grafana`).

| alert | means | first move |
|---|---|---|
| `StreamJobDown` | Flink JobManager unreachable | `kubectl get flinkdeployment stream`; operator logs |
| `StreamFallingBehind` | > 10,000 events waiting in Kafka for 5 min | the autoscaler should be adding TaskManagers -- if not, it is at its ceiling or pods are Pending |
| `StreamLatencyHigh` | Kafka → decision p95 > 2 s for 5 min | Flink UI: busy / backpressured time per operator |
| `StreamDataQualityDegraded` | > 1% of events doubtful after normalize/enrich for 10 min (blank users, unknown severities, unplaced IPs, clock skew) | the Grafana panel *Data quality between steps* says which issue; usually one log source changed format |
| `StreamLogicInconsistent` | **critical** — features or a decision contradicting themselves | a detection bug or corrupted state: compare with the last green test run; restore from a savepoint (§9) |
| `StreamRejectingEvents` | the job rejected messages in the last 10 min | `SELECT reject_reason, count() FROM rejected_events GROUP BY 1` |
| `KafkaUnderReplicatedPartitions` | a broker lagging or down | `make status` |
| `KafkaBrokerDown` | broker pod down | Strimzi restarts it; check PVC |

**Consumer lag.** Flink commits its offsets to the `watchtower-stream`
consumer group on every checkpoint, so standard Kafka tooling sees the lag
(`kafka-consumer-groups.sh --describe --group watchtower-stream`).

There is no Alertmanager locally (memory): alerts show in the UI but notify
no one. Adding one Alertmanager Deployment routes them to Slack or email.

---

## 9. Recovery

**Streaming job crash** — Flink restarts it from the newest checkpoint
(offsets + every source's window and dedup memory, taken every 10 s).
On Kubernetes the operator does this with Kubernetes HA; in dev,
`docker/flink/run-job.sh` finds the newest complete checkpoint when the
JobManager container restarts. Nothing to do.

**Streaming state-layout change** — Flink cannot map old state onto new
descriptors; reset the checkpoints (dev: stop the two Flink containers,
empty the `flink-checkpoints` volume, start them). The job resumes from the
consumer group's committed offsets, so no event is skipped; only windows
and dedup memory start empty.

**A bad model** — roll back by promoting an earlier version (the job picks
it up within 5 minutes), or switch the model off entirely:

```sql
INSERT INTO watchtower.ml_model_active (version, reason)
SELECT version, 'rollback' FROM watchtower.ml_models WHERE version = 'lgbm-...';
```

`WATCHTOWER_ML=off` on the Flink job scores with rules alone.

**After a Docker VM crash, recreate the cluster.** A crash corrupted
images inside the k3d node: a 0-byte `/run.sh` in Grafana, rejected with
`exec format error`. Re-importing does not fix it -- containerd sees layers
it already has and skips them. `make cluster-down && make cluster-up`
does.

---

## 10. Known limits of this deployment

- **Checkpoints on a ReadWriteOnce volume.** Flink's checkpoints and HA
  metadata sit on a volume every pod must
  share -- true on this single-node cluster. Multi-node needs object
  storage (`s3://`).
- **The Flink image is ~3 GB** -- PyFlink pulls Apache Beam, PyArrow and
  pandas. On arm64 PyFlink also compiles from source (~4 min build).
- **The LLM reviews offline, hourly**, never per event: a remote call per
  event would stall the stream. The model scores live.
- **One ClickHouse replica.** Sharding is where the Altinity operator
  earns its place.
- **Prometheus storage is an emptyDir** — metrics history is lost if the
  Prometheus pod restarts.
