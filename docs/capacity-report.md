# Watchtower — capacity test report

**Date:** 2026-09-25 · **Environment:** dev (docker compose) on an 8 GB Mac,
Docker VM with 8 vCPUs and 3.8 GB RAM (1 GB swap) · **Tool:**
`tools/load_test.py` (raw results: `load_test_results*.json` in the session
scratchpad).

## Result

| | events/s |
|---|---|
| **Maximum sustained throughput** | **~1,200** (1,187 in, 1,181 decided, 1,149 stored; backlog flat over 10 min) |
| First rate that falls behind | 1,400 (backlog +69/s, latency climbing without limit) |
| Recommended operating rate on this machine | **1,000** (latency median ~220 ms, 90% of the time under 1 s) |

Every event was decided and stored at both 1,000 and 1,200/s — no loss,
no parse errors, no sink errors. What changes between them is **latency**,
and it is limited by this machine's memory, not by the code (see
"Where the ceiling comes from").

## Method

Full pipeline, as deployed in dev: simulator → Kafka `security-logs` →
Flink (1 JobManager, 1 TaskManager, 1 slot) → Kafka `security-events-scored`
→ ClickHouse Kafka engine (50 ms blocks) → `security_events`.

- Load from **two simulator containers** (so one Python producer is not the
  ceiling), realistic traffic: 1,780+ hosts, normal activity plus all nine
  attack types.
- Step test: 1,000 → 2,000/s, then 1,200 / 1,400 / 1,600 / 1,800 / 2,000,
  4 minutes per step, stopping after two failing steps. Then **10-minute
  confirmation runs** at 1,200 and 1,000/s, each from a clean restart.
- Sampled every 20–30 s: rate Kafka received (end offsets), rate Flink
  decided (committed offsets), rate ClickHouse stored (`ingested_at`),
  Kafka backlog, end-to-end latency (`ingested_at − timestamp`), CPU and
  memory per container, VM swap.
- **Sustained** = the backlog's least-squares trend over the step stays
  under 2% of the input rate, and Flink and ClickHouse keep pace (≥97% /
  ≥95% of input). The backlog is read from checkpoint commits (every
  10 s), so single samples jump by a checkpoint's worth; the trend over
  the whole step is what counts.

## Step test

| target | Kafka in | Flink decided | stored | backlog trend | verdict |
|---|---|---|---|---|---|
| 1,000/s | 985/s | 988/s | 1,003/s | −14/s | sustained |
| 1,200/s | 1,169/s | 1,166/s | 1,195/s | +3/s | sustained |
| 1,400/s | 1,371/s | 1,294/s | 1,299/s | +69/s | **falls behind** |
| 1,600/s | 1,563/s | 1,213/s | 1,169/s | +347/s | falls behind |
| 2,000/s | 1,945/s | 1,362/s | 1,360/s | +518/s | falls behind |

## Performance at the maximum: 1,200 events/s for 10 minutes

| | value |
|---|---|
| throughput | 1,187 in · 1,181 decided · 1,149 stored per second; backlog +1.5/s (flat) |
| latency, average | 9.5 s |
| latency, median of 30-s medians | 3.9 s (range 77 ms – 28.9 s) |
| latency, p95 (median over samples) | 8.2 s (worst sample 40 s) |
| worst single event | 44.6 s |
| events under 100 ms | 17% |
| 30-s windows with median under 1 s | 45% |
| CPU (average) | TaskManager 133%, ClickHouse 73%, Kafka 38%, simulators 72%, JobManager 12% |
| memory (peak) | ClickHouse 1.44 GB, TaskManager 0.94 GB, Kafka 0.38 GB, JobManager 0.29 GB |
| VM swap | full (1 GB) |

What happens at 1,200/s: the pipeline starts at ~80 ms median, then
after ~2.5 minutes the VM runs short of memory, parts of the Flink
TaskManager are paged to swap (240 MB), and every GC or state access that
touches them stalls. The backlog reached 38,000 events and latency 29 s.
When the stall clears, Flink catches up at up to ~1,500/s — it has spare
speed — and latency returns to 0.2–0.6 s. On average it keeps up; its
latency is not dependable.

## For comparison: 1,000 events/s for 10 minutes

| | value |
|---|---|
| throughput | 986 in · 982 decided · 987 stored per second; backlog −0.7/s |
| latency, average | 585 ms |
| latency, median of 30-s medians | **218 ms** (range 73 ms – 2.1 s) |
| latency, p95 (median over samples) | 1.16 s (worst sample 4.9 s) |
| worst single event | 6.5 s |
| events under 100 ms | 38% |
| 30-s windows with median under 1 s | 90% |
| Flink job itself (Kafka → decision) | ~5–15 ms when not stalled |
| checkpoints | 66 completed, 1 failed; ~1.1 s average (max 2.6 s); state 62 MB |
| ClickHouse | 9 inserts/s, 125 merges/min, 9 active parts, 0 sink parse errors |
| CPU (average) | TaskManager 129%, ClickHouse 78%, Kafka 33%, simulators 64%, JobManager 9% |
| memory (peak) | ClickHouse 1.55 GB, TaskManager 1.06 GB, Kafka 0.34 GB, JobManager 0.32 GB |
| detection (10 min) | 576,843 allow · 16,654 block; top rules: brute_force 8,535, password_spray 8,155, repeated_attack_signatures 6,316, web_scan 4,483, login_after_brute_force 3,329, scanner_agent 3,019, port_scan 2,314, lateral_movement 1,535, sqli 661, sensitive_command_as_root 545 |

## Where the ceiling comes from

- **Not the Flink job.** Measured earlier with only Kafka and Flink
  running, one TaskManager drains ~4,300 events/s; with ClickHouse also
  running, 2,500–4,000/s. Detection logic alone is ~6,300/s per core.
- **Memory.** The stack needs ~3.5–3.8 GB (ClickHouse 1.4–1.55 GB,
  TaskManager ~1 GB, Kafka, JobManager, VM overhead) in a 3.8 GB VM. Swap
  fills within minutes at any rate; above ~1,200/s the stalls it causes
  outlast the job's spare capacity and the backlog grows.
- **CPU shared with the simulator.** The two producers use ~0.6–0.7 of a
  core on the same 8 vCPUs; ClickHouse's 50 ms ingest adds ~125 merges a
  minute.

## What would raise it

| change | expected effect |
|---|---|
| Docker VM from 3.8 to ~6 GB | removes swap stalls; the job's own ~2,500–4,000/s becomes the ceiling, with latency near the ~70–90 ms seen when not swapping |
| more TaskManagers (Kubernetes autoscaler, 1 slot each) | adds ~2,500–4,000/s per TaskManager, given memory for each (~1 GB) |
| ClickHouse ingest 100 ms instead of 50 ms | fewer inserts and merges, less memory and CPU; +~25 ms latency |
| simulator on another machine | frees ~0.7 core |

Reproduce: `python3 tools/load_test.py 1000 1200 1400 --step-seconds 240`
with the dev stack up and nothing else running.
