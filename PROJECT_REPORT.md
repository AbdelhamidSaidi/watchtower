# Watchtower — project report (2026-10-01)

## What it is
Watchtower is a real-time log pipeline built for a Sekera Services internship (French title: "Conception d'un pipeline de traitement des logs … avec ClickHouse"). It began as a **security-log** pipeline. On 2026-10-01 the domain was switched to **compilation (build-farm) logs**: the logs of the data-center runners that compile, test and publish applications. The goal is to decide, within milliseconds, whether a build runner is healthy or in trouble, store everything for analysis, and improve the detector over time with an LLM's second opinion.

## Architecture (unchanged by the pivot)
1. **Ingest:** a simulator produces Avro messages (Confluent wire format, schema looked up in a Karapace schema registry) to Kafka topic `security-logs`, keyed by `runner_ip`.
2. **Stream processing (Apache Flink / PyFlink 2.2.1):** per event, one at a time, no micro-batches: decode → validate → normalize → enrich → `keyBy(runner_ip)` → dedup → rolling 1- and 5-minute windows (O(1) per event, keyed state) → 17 deterministic rules → a LightGBM model compiled to plain Python (~10 µs) → decision. Data-quality counters between every step. Dead letters go to a rejected topic.
3. **Storage (ClickHouse 25.8):** Flink writes finished rows to Kafka; ClickHouse's Kafka engine inserts them in 50 ms blocks into `security_events` (ReplacingMergeTree), with a `suspicious_events` view and `rejected_events`. At-least-once delivery, duplicates collapse on merge.
4. **Batch / MLOps (Airflow 3.3, six DAGs):** end-to-end pipeline check (10 min), hourly data-quality checks, hourly **AI review** (Groq, `openai/gpt-oss-safeguard-20b`, an open-weights model hosted by Groq) of a sample of events the pipeline passed plus the model's own alerts, retraining when confident disagreements become labels, promotion only if the candidate beats the active model on a holdout and a shadow check on real traffic, an automatic rollback guard, a daily rollup, and a 6-hourly detection-quality evaluation against the simulator's ground truth. Flink hot-swaps the promoted model within 5 minutes.
5. All decision logic lives in `etl/core/` (plain Python, tested without a cluster).

The live path is genuine stream processing: ~4 ms median decision after Kafka. The Airflow side is batch by design.

## What the pivot changed
- **Events:** `BUILD_STARTED`, `BUILD_SUCCESS`, `BUILD_FAILURE`, `COMPILE_STEP`, `TEST_RUN`, `DEPENDENCY_FETCH`, `ARTIFACT_PUBLISH`. Fields include project, runner, exit code, duration, peak memory, cache status, error message, plus registry (URL, status, bytes) and process info. New schema: `schemas/build_event.avsc`.
- **Source:** the stream and all windows are per build runner (`runner_ip`).
- **Actions:** `ok` / `alert` / `quarantine` ("stop scheduling builds on this runner"), replacing allow/alert/block. Reviewer verdicts: normal / degraded / incident.
- **Nine simulated incident kinds:** retry storm, broken toolchain, OOM-kill storm, slow compile, dependency-not-found flood, cache corruption, compiler crash, rogue build step (miner, `curl | sh`), artifact bloat. Incidents hit ordinary runners that keep doing normal work, so the detector learns behaviour, not a bad IP.
- **Rules:** signatures (compiler crash, checksum mismatch, disk full, rogue command, untrusted fetch, OOM kill, slow step) and behaviours (failure storm, broken toolchain, OOM-kill storm, repeated slow steps, dependency 404 storm, artifact bloat, repeated failure signatures, pass after failure storm). Ordinary compile errors, failing tests and root containers deliberately fire nothing.
- **Features:** 16 rolling features per runner; the model uses 35 inputs.
- **Kept names (user's choice):** Kafka topics, ClickHouse tables, registry subject (`security-logs`, `security_events`, …), so the plumbing did not move. Producer renamed `build_log_producer.py`; the SOC note became `NOTE_TO_BUILD_ENGINEER.md`.
- **Also rewritten:** ClickHouse DDL, reviewer prompt, Grafana dashboards, alerts, tests, README and docs. New tool `tools/replay_offline.py` (replays the simulator through the per-event path with no infrastructure) and `tests/unit/test_simulation.py`.

## What was verified
- **Tests:** Flink image 92 passed (includes the real job on a Flink mini-cluster and the compiled model vs LightGBM); Airflow image 136 passed; ruff clean; both Kubernetes overlays render.
- **Offline replay, rules only:** two 15-minute replays (900,000 events each, 9 kinds): 111 of 111 incidents caught; 0 of 1.76 million normal events flagged on runners with no incident.
- **Live stack at 200 events/s:** all events stored, 0 rejected; incidents caught.
- **Live stack at 1,000 events/s, ~10 minutes (8 GB Mac, 3.8 GB Docker VM):**
  - Throughput 998 events/s stored, 0 rejected or missing; Kafka backlog rose and drained between ~400 and ~9,800 and never grew.
  - End-to-end latency (created → stored): p50 51–71 ms (≈58), p95 348–613 ms, p99 544–1,009 ms, max 610–1,456 ms. Inside Flink (Kafka → decision): p50 4 ms, p95 6–16 ms. The tail is in the ClickHouse insert and Kafka hops, not detection.
  - Resources: Flink TaskManager ~40–60% of a core, ClickHouse 27–80% (1.35–1.68 GB), Kafka 12–38%. The VM was the constraint: available memory 540–850 MB and its 1 GB swap full.
  - `make evaluate` (8 min, 480,381 events, 7 incident kinds seen): every incident caught, first flag 0–2 s after the incident's first event, coverage 100%.
- **Evaluator bug found and fixed:** the evaluator reported 383–414 "false positives on uninvolved runners" (0.09–0.13%) because it could not see incidents that ended just before its window. Checking against the producer's own incident log showed none were real. It now reads 5 minutes before the window (`--lead-in-minutes`) and counts only events inside; the same kind of live window reports 0.
- **Airflow:** all six DAGs load with no import errors. After unpausing `watchtower_pipeline`, `watchtower_data_quality` and `watchtower_detection_quality`, the first data-quality run succeeded (all 7 checks passed, 1.2 million events in the hour, p95 latency 559 ms). I did not see the pipeline and detection-quality runs finish before Docker went down.

## Current state
- Docker Desktop's engine crashed (the Mac was nearly out of RAM). Docker reports "unable to start"; no containers can be running. Volumes should be intact but are unverified. Waiting on the user to restart Docker Desktop.
- Next planned: run the stack at 10 events/s to check it works on the low-power PC, then do a linear projection to 1,000 events/s. Caveats: at 10 events/s incident traffic is capped at 2 events/s, so rule thresholds fill more slowly; CPU and throughput can be projected linearly, memory cannot (ClickHouse and Kafka have large fixed baselines). The 200 and 1,000 events/s measurements above can validate the projection.

## What is not done / known limits
- **No ML model exists yet for the build features.** Detection is rules-only. Training needs ≥ 2,000 labelled rows and ≥ 200 incident rows from the hourly label collection.
- **The Groq reviewer has never run:** no API key, and its rewritten prompt has never met a real model's answers. It sends runner IPs, project names, URLs, command lines and error text to a third party.
- **Thresholds are tuned to the simulator** (20 failures, 8 projects, 250 MB, 5-minute slow step, 30 dependency 404s per minute). A real farm needs them re-tuned; `WATCHTOWER_SLOW_STEP_MS` is the most likely to be wrong.
- **Detection gap:** a bad commit that fails a few builds on many runners at once is invisible, because features are per runner. It needs a project-keyed pass.
- **Windows are 1 and 5 minutes**, so slow incidents (a slow leak, a creeping compile-time regression) are not caught.
- **Older measurements** in the docs (per-event Flink cost, per-TaskManager throughput, the capacity ceiling) come from the earlier security-log workload and are marked as such.
- **Existing installs need a one-time reset** (columns and schema changed); documented in `docs/operations.md`. The reset was done on the dev machine.
- **Kubernetes** manifests render but have never run on a cluster. Replication, backups, alert notifications and TLS are open production tasks (`docs/prod-readiness.md`).
- **Nothing is committed** (project rule); some `git mv` renames are staged.
- **Cosmetic:** the table `daily_top_sources` and the names `is_suspicious` / `suspicious_events` still use the old vocabulary.

## Where to look
`README.md` (entry point), `NOTE_TO_BUILD_ENGINEER.md` (rules, tuning, investigating an alert), `docs/context.md` (design decisions), `docs/streaming.md`, `docs/orchestration.md`, `docs/operations.md`, `tools/replay_offline.py`, `tools/evaluate_detection.py`.
