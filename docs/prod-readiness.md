# Watchtower — production readiness (DataOps)

What is left, in order, to run this pipeline in production. Platform and
data-engineering work only: tuning rules, triaging alerts and judging
detection quality belong to the SOC (`NOTE_TO_SOC_ANALYST.md`).

Each phase depends on the ones before it.

## Phase 1 — Real infrastructure and delivery

- [ ] 1. Cloud staging cluster: 3 nodes × 8 GB, spread over availability zones
- [ ] 2. Container registry (GHCR / ECR); images built and pushed by CI
- [ ] 3. Push the repo; CI runs on every PR; branch protection (nothing merges red)
- [ ] 4. GitOps deploys (Argo CD / Flux): staging automatic, prod on approval
- [ ] 5. Deploy staging and fix what breaks — no Kubernetes manifest has run on a cluster yet
- [ ] 6. Verify autoscaling under `make load`: Flink TaskManagers, Kafka brokers (HPA + Cruise Control)

## Phase 2 — Don't lose data

- [ ] 7. ClickHouse: 2 replicas (ReplicatedMergeTree) + 3 ClickHouse Keeper nodes
- [ ] 8. Nightly ClickHouse backups to object storage — **and a tested restore**
- [ ] 9. Flink checkpoints and savepoints in object storage; a savepoint before every deploy
- [ ] 10. Kafka: rack awareness across zones; confirm RF 3 / `min.insync.replicas=2` everywhere
- [ ] 11. Set recovery objectives (RPO/RTO); run a failure drill: kill a broker, a ClickHouse replica, a TaskManager

## Phase 3 — Observability and alerting

- [ ] 12. Alertmanager → Slack / PagerDuty / Opsgenie, routed by severity
- [ ] 13. Airflow `on_failure_callback` to the same channel
- [ ] 14. `promtool check rules` in CI
- [ ] 15. SLOs (e.g. 99.9% of events decided in < 1 s; 99.99% stored), burn-rate alerts
- [ ] 16. One runbook section per alert, linked from the alert
- [ ] 17. Central logs for the pipeline's own containers (Loki / ELK)

## Phase 4 — Security

- [ ] 18. Kafka: TLS + SASL + ACLs per producer and consumer
- [ ] 19. ClickHouse: TLS; separate writer (ingest) and read-only users
- [ ] 20. Secrets in Vault / External Secrets, with rotation
- [ ] 21. Airflow: FAB or Keycloak auth manager instead of the single admin
- [ ] 22. Kubernetes: NetworkPolicies, Pod Security "restricted", non-root containers, least-privilege RBAC
- [ ] 23. Image scanning (Trivy) and signed images (cosign) in CI
- [ ] 24. Query audit logging in ClickHouse

## Phase 5 — Capacity proof

- [ ] 25. Load test at 10,000 events/s on staging; confirm p95 latency < 200 ms
- [ ] 26. 72-hour soak at target load: memory leaks, state growth, merge backlog
- [ ] 27. Find the real ceiling: step the load up until the latency SLO breaks
- [ ] 28. Update `capacity-report.md`; size prod from measured numbers

## Phase 6 — Data management

- [ ] 29. Retention: 90 days raw, 1 year suspicious, `ttl_only_drop_parts`, cold tier on object storage (sign-off from legal/compliance)
- [ ] 30. Airflow replay DAG: reprocess a time range with a bounded run of the Flink job over those Kafka offsets
- [ ] 31. Data contract per log source: owner, required fields, expected volume
- [ ] 32. Lineage: OpenLineage from Airflow
- [ ] 33. Drop `security_events_before_relayout` (2.85 GB) once confirmed unneeded

## Phase 7 — Real sources and go-live

- [ ] 34. Collectors (Vector / Fluent Bit / syslog) → Kafka for the first real log source
- [ ] 35. Disable the synthetic producer, the detection-quality DAG and simulator label collection in prod (`WATCHTOWER_SYNTHETIC_TRAFFIC=false`)
- [ ] 35b. Set the Groq key in prod; a spending limit on the Groq account
- [ ] 36. Rehearse the prod deploy on staging (a full `make promote`)
- [ ] 37. Define on-call ownership and escalation for the pipeline
- [ ] 38. Go live with the first source; hand over operation of the dashboards and verdict tables to the SOC

---

**Can start today, locally:** 14 (promtool in CI), 29 (retention), and the
Airflow side of 13 (failure callbacks). The rest of 12, 13 and 15 needs a
real alert channel, and most other items need Phase 1 first.
