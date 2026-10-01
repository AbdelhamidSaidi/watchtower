# Note to the build engineer

**Read this before you trust anything this system flags.**

The detector is built, wired in and measured on simulated build-farm traffic,
but it is **not tuned for your farm**. Every threshold below was chosen to
make the pipeline work on a simulation, not because it is right for your
runners, your projects or your toolchains. Tuning it is your job, and this
note exists so you can do that without reading the code.

Nobody has validated a single alert from this system on real build logs yet.

*Last updated 2026-10-01 -- the day the pipeline moved from security logs to
build-farm (compilation) logs. The topics, tables and registry subject kept
their old names (`security-logs`, `security_events`, ...); the events,
columns, rules and incidents are all new.*

---

## 0. What changed since the previous version of this note

The previous note was written for security logs. Everything about the events
changed; how the pipeline works did not.

| | before | now |
|---|---|---|
| **what the events are** | logins, ssh sessions, port scans, HTTP requests, commands | **builds starting and finishing, compiler invocations, test runs, dependency fetches, artifact uploads** |
| **who the source is** | a host's IP (`source_ip`) | **a build runner's IP (`runner_ip`)**: the stream and every window are per runner |
| **what is detected** | attacks | **build-farm incidents** (§1): failure storms, broken toolchains, OOM-kill storms, compiler crashes, poisoned caches, slow compiles, ... |
| **actions** | `allow` / `alert` / `block` | **`ok` / `alert` / `quarantine`** -- stop scheduling builds on the runner |
| **reviewer's verdicts** | benign / suspicious / malicious | **normal / degraded / incident** |
| **columns** | `failed_logins_5m`, `unique_users_5m`, `unique_ports_5m`, `http_404_1m`, `bytes_sent_5m`, `country_code`, ... | **`failed_builds_5m`, `unique_projects_5m`, `distinct_exit_codes_5m`, `dependency_404_1m`, `published_bytes_5m`, `region`, ...** (§1) |
| **existing data** | -- | **the old columns are gone.** An install created before this change needs the one-time reset in `docs/operations.md` ("Switching an existing install to build logs") |

---

## 1. What the pipeline decides, and from what

Every event ends with a **`recommended_action`: `ok`, `alert`, or
`quarantine`**, plus `rule_hits` naming *why*. That column is the work queue:

```sql
SELECT timestamp, runner_ip, project, event_type, recommended_action, rule_hits,
       error_message, command, process_uid
FROM watchtower.suspicious_events
WHERE recommended_action = 'quarantine'
ORDER BY timestamp DESC LIMIT 50;
```

A decision is made within milliseconds of the event reaching Kafka and is
queryable about 0.2 s after the event happened. The decision is also
available, before storage, on the Kafka topic `security-events-scored`
for anything that must react faster than a database query -- a scheduler
that drains a runner, say.

**What "quarantine" means is up to you.** The pipeline only *recommends*; it
drains nothing. A sensible first wiring: an `alert` opens a ticket, a
`quarantine` takes the runner out of the scheduler's pool for 30 minutes.

### What an event carries

| group | fields |
|---|---|
| identity | `event_id`, `timestamp`, `runner_ip`, `hostname`, `project`, `build_id`, `triggered_by` (a developer, `svc-ci`, a schedule) |
| kind | `event_type`: `BUILD_STARTED`, `BUILD_SUCCESS`, `BUILD_FAILURE`, `COMPILE_STEP`, `TEST_RUN`, `DEPENDENCY_FETCH`, `ARTIFACT_PUBLISH`; `severity`, `outcome`, `log_source` (the tool: make, ninja, gradle, cargo, npm, go, ...) |
| **the step** | `command` (the compiler or linker invocation), `step` (compile / link / archive / codegen), `file_path`, `exit_code`, `duration_ms`, `peak_memory_mb`, `cache_status` (hit / miss / corrupt), `error_message` (the first line of the tool's complaint), `reason` (why a build failed) |
| **registry** | `dest_ip`, `dest_port`, `protocol`, `http_method`, `url_path` (as received), `http_status`, `user_agent`, `bytes_sent`, `response_time_ms` |
| process | `process_name`, `process_id`, `parent_process`, `process_uid` (0 = root, **-1 = unknown**) |

`process_uid` of **-1** means the runner did not report one; it is never
assumed to be root. Builds in containers run as root a good third of the
time on the CI farm -- root is not an incident.

### Indicators -- why an event looks wrong, one column each

| column | set when |
|---|---|
| `failure_signature` | the error text shows **the infrastructure** at fault, not the code: `ice` (an internal compiler error, a segfault), `oom` (`Killed`, out of memory), `disk_full` (no space left on device), `checksum_mismatch` (a corrupt cache entry or artifact) |
| `is_rogue_command` | a build step runs something it has no business running: a miner (`xmrig`, `stratum+tcp`), a download piped to a shell, credentials read or sent out, a reverse shell |
| `is_untrusted_fetch` | a dependency comes from an unofficial or unsigned mirror, or is a script or executable instead of a library |
| `is_slow_step` | a compile step took 5 minutes or more (`WATCHTOWER_SLOW_STEP_MS`) |
| `is_cache_miss` | the build cache missed or returned a corrupt entry |
| `is_privileged` | a **known** uid of 0 |

**An ordinary compile error, a failing test or a red build matches none of
these on purpose.** They are the farm's daily weather: the code is wrong, not
the machine. The detector's job is the other kind of red.

### The rules -- what gets quarantined, and how sure each is

Two kinds of evidence. A **signature** is wrong in itself -- one is enough. A
**behaviour** is the runner's last 1-5 minutes.

| rule | score | fires on |
|---|---|---|
| `reverse_shell` | 1.00 | `nc -e`, `/dev/tcp/`, `bash -i >&` in a build command |
| `rogue_command_as_root` | 0.97 | a rogue command run as uid 0 |
| `cache_poisoned` | 0.95 | a checksum mismatch -- a corrupt cache entry or artifact |
| `compiler_crash` | 0.95 | an internal compiler error / segfault |
| `disk_full` | 0.90 | no space left on the runner |
| `failure_storm` | 0.90 | 20+ failed builds in 1 min |
| `broken_toolchain` | 0.90 | failures across 8+ projects and 20+ failures in 5 min -- the runner is broken, not the projects |
| `oom_kill_storm` | 0.90 | 5+ OOM kills (exit 137 / "Killed") in 5 min |
| `repeated_slow_steps` | 0.90 | 5+ slow compile steps in 5 min |
| `repeated_failure_signatures` | 0.90 | 5+ infrastructure-failure signatures in 5 min |
| `rogue_command` | 0.85 | a rogue command |
| `dependency_not_found_storm` | 0.85 | 30+ 404s on dependency fetches in 1 min |
| `artifact_bloat` | 0.85 | 250 MB+ published in 5 min |
| `oom_kill` | 0.70 | one OOM kill -- **alert, not quarantine** |
| `untrusted_fetch` | 0.70 | one fetch from an untrusted source -- **alert** |
| `slow_step` | 0.70 | one slow compile step -- **alert** |
| `pass_after_failure_storm` | 0.70 | a build that **succeeds** after 20+ failures in 5 min: flaky, not fixed -- **alert** |

`>= 0.85` is **quarantine**, `>= 0.65` **alert**, else **ok**. The rules need
no API key.

### Reading the score columns on the live path

| column | on the live (Flink) path |
|---|---|
| `rule_score`, `final_anomaly_score` | the highest-scoring rule that fired (0 if none) |
| `rule_hits` | every rule that fired, strongest first |
| `ml_score` | the model's probability that this is an incident (0 if no model is active) |
| `ml_model` | the model version that scored it (`watchtower.ml_models`) |
| `ml_reason` | set only when the model **raised** the decision above what the rules said: `ml: <the features that drove it>`, e.g. `ml: failed_builds_5m, unique_projects_5m` |
| `final_anomaly_score` | the higher of the rule score and the model's |
| `is_suspicious` | 1 when the event is flagged: `alert` or `quarantine` |

**The model alone can alert, never quarantine.** To quarantine, a rule must
agree: pulling a runner on a score you cannot explain in rule terms is a
decision you cannot defend. (Set `WATCHTOWER_ML_CAN_QUARANTINE=true` once the
model has earned it.)

### Measured (simulated build-farm traffic)

Two offline replays of the simulator through the per-event path, rules only
(`python3 tools/replay_offline.py --seconds 900 --seed 7`, and `--seed 11`;
900,000 events each, a new incident every ~15 s):

| incident | caught | events quarantined | first flag after |
|---|---|---|---|
| cache corruption | 14 / 14 | 100% | the first event (signature) |
| compiler crash | 11 / 11 | 99% | 1-3 events (signature) |
| slow compile | 12 / 12 | 98% (100% flagged) | the first event (signature: alert, then quarantine) |
| rogue build step | 16 / 16 | 60-62% (100% flagged) | the first event; the rest of its events are `untrusted_fetch` alerts |
| OOM-kill storm | 13 / 13 | 95-96% (99% flagged) | 1-3 events |
| artifact bloat | 9 / 9 | 96-97% | 3-5 events (volume: three or four uploads of ~80 MB) |
| broken toolchain | 10 / 10 | 99% | 1-4 events (a signature, or 8 projects failing) |
| retry storm | 14 / 14 | 98-99% | 17-20 events (behaviour: 20 failures in a minute) |
| dependency not found | 12 / 12 | 97% | 31-35 events (behaviour: 30 404s in a minute) |
| **normal traffic, on runners with no incident** | -- | **0 of 1.76 million events flagged** | |

All 111 incidents were caught. **These are the simulator's incidents, with
thresholds tuned to them** -- the same caveat as the rest of this note.
`make evaluate` runs the same comparison against the live stack, with the
model; Airflow repeats it every 6 hours (`watchtower_detection_quality`) and
keeps each report in `watchtower.detection_quality`. A run fails if an
incident is missed, the median first flag exceeds 5 s, or normal traffic on
uninvolved runners is quarantined above 0.01%:

```sql
SELECT evaluated_at, incidents_caught, incidents_seen, median_time_to_flag_s,
       normal_quarantined_uninvolved, passed, failures
FROM watchtower.detection_quality ORDER BY evaluated_at DESC LIMIT 20;
```

**Two things to understand about those numbers.**

*Behavioural rules miss an incident's first few events.* A retry storm is
invisible until the failures pile up -- that is the 1-4% gap. Signature rules
have no such gap: the first corrupt cache entry is quarantined.

*Almost all quarantined normal traffic is from the runner that has the
incident.* A runner in a failure storm gets **all** its traffic quarantined
for the window, including the healthy builds it runs meanwhile -- during the
incident and for the 5 minutes after, while its windows still hold the
evidence. That is containment, and usually what you want (stop scheduling on
a sick runner). **It is a policy choice, and yours to confirm**: if you would
rather quarantine only the failing builds, the behavioural rules must be
scoped to event type.

---

## 2. How a score is produced

```
   every event (Flink, in the stream)
        |
   RULES          deterministic                  -> rule_score, rule_hits
        |
   MODEL          LightGBM, ~5 us                -> ml_score, ml_model
        |
   final = max(rule score, model score)   -- the model alone stops at `alert`
        |
   ok / alert / quarantine, stored in security_events

   every hour (Airflow, offline)
   a sample of events that PASSED --> LLM (Groq) --> event_reviews
        confident disagreements --> training labels --> retraining
        --> the new model goes live only if it beats the current one
```

**Why the LLM does not score live.** A remote API call per event would
hold up that runner's stream -- the opposite of deciding each event as it
arrives. So the LLM became the **reviewer**: it re-judges a sample of what
the pipeline let through, and teaches the model what it missed.

### What the reviewer looks at

Not everything -- 3.6 million events an hour at 1,000/s -- but up to 150
an hour (3,000 a day):
- **near-misses:** the highest model scores that still passed
- **unusual:** the hour's top 0.1% on a behaviour feature
- **random:** a uniform sample, which is what tells you the real miss rate
- **the model's own alerts** (no rule behind them): where the AI calls one
  normal, the model learns to be quieter

New labels start a retraining at once; a new model goes live only if it
measures better, and is rolled back automatically if the AI calls most of
its own alerts normal.

Each gets a verdict (normal / degraded / incident), a confidence and a
reason, in `watchtower.event_reviews`. The ones that matter to you:

```sql
-- events that passed that the reviewer disagreed with, newest first
SELECT reviewed_at, runner_ip, event_type, verdict, confidence, reason, why_selected
FROM watchtower.label_changes ORDER BY reviewed_at DESC LIMIT 50;
```

If it is **>= 90% sure a passed event was an incident**, the Airflow run
fails at once (`watchtower_review`) -- treat that as an alert. At >= 80%, a
disagreement becomes a training label, weighted at half of ground truth.

**The reviewer's reason is a hypothesis, not a finding.** It is an LLM:
confident, and sometimes wrong. That is why its labels weigh less, and why
a new model goes live only if it measures better on events the reviewer
never judged.

---

## 3. The settings you will need to change

All are environment variables; none require code changes. On Kubernetes
they belong in the `pipeline-env` ConfigMap (deploy/k8s overlays); in dev,
on the Flink containers in `docker-compose.yml`. **They take effect when the
job restarts.**

### Thresholds

| variable | default | meaning |
|---|---|---|
| `WATCHTOWER_QUARANTINE_THRESHOLD` | `0.85` | score at or above which an event is `quarantine` |
| `WATCHTOWER_THRESHOLD` | `0.65` | score at or above which an event is `alert` / `is_suspicious` |
| `WATCHTOWER_SLOW_STEP_MS` | `300000` | a compile step slower than this is a `slow_step` |

These were not derived from your data. Work backwards from your capacity:
the alert threshold should yield roughly the number of alerts your team can
actually triage. **`WATCHTOWER_SLOW_STEP_MS` is the one most likely to be
wrong for you:** the simulator's largest ordinary step links in about four
minutes; a farm that builds a browser or a kernel has steps that take an
hour. The rule scores themselves and the counts in the table above (20
failures, 8 projects, 250 MB, ...) live in `etl/core/rules.py`.

### The stream

| variable | default | meaning |
|---|---|---|
| `WATCHTOWER_DEDUP_RECENT` | `1024` | how many recent event ids each runner remembers for duplicate detection (§5) |
| `WATCHTOWER_SOURCE_IDLE_MS` | 15 min | a runner silent this long is forgotten: its windows restart from zero |
| `WATCHTOWER_ML` | `on` | `off` scores with rules alone, whatever model is active |
| `WATCHTOWER_ML_CAN_QUARANTINE` | `false` | let the model quarantine on its own, without a rule agreeing |

### The reviewer (Airflow)

| variable | default | meaning |
|---|---|---|
| `GROQ_MODEL` | `openai/gpt-oss-safeguard-20b` | pin it; a model change changes what gets relabelled |
| `GROQ_REASONING_EFFORT` | `medium` | how long it thinks per batch |

The per-run and per-day caps (150 / 3,000) and the confidence bars (80% to
become a label, 90% to alert) are in `orchestration/ops/review.py`.

---

## 4. Operating it

**The live path needs no API key and has nothing to fail open.** Rules run
on every event. What can go wrong is the job itself, and the streaming
alerts cover it:

| alert | means |
|---|---|
| `StreamJobDown` | the Flink job is not running -- **nothing is being decided** |
| `StreamFallingBehind` | more than 10,000 events waiting in Kafka for 5 minutes |
| `StreamLatencyHigh` | decisions take more than 2 s after the event reaches Kafka |
| `StreamRejectingEvents` | malformed or unregistered data (§6) |

**An empty `suspicious_events` table therefore means one of two things:**
a healthy farm, or the job not running. Check before concluding it was
healthy:

```sql
SELECT count() AS stored_last_minute
FROM watchtower.security_events
WHERE ingested_at > now() - INTERVAL 1 MINUTE;
```

Zero means nothing is arriving at all -- look at the job, not the farm.
Airflow checks the whole path every 10 minutes and keeps the verdict,
stage by stage -- the quickest answer to "is it quiet, or is it broken?":

```sql
SELECT stage, check_name, passed, detail FROM watchtower.pipeline_health
WHERE run_id = (SELECT argMax(run_id, checked_at) FROM watchtower.pipeline_health)
ORDER BY stage;
```

**End-to-end latency**, any time (`make latency` in dev):

```sql
SELECT quantile(0.5)(l) AS p50_ms, quantile(0.95)(l) AS p95_ms, max(l) AS max_ms
FROM (SELECT toUnixTimestamp64Milli(ingested_at) - toUnixTimestamp64Milli(timestamp) AS l
      FROM watchtower.security_events
      WHERE ingested_at > now64(3) - INTERVAL 60 SECOND);
```

The Grafana dashboard's first row (*Streaming path*) shows the same live:
decision latency, Kafka backlog, decisions per second by action, and the
number of TaskManagers the autoscaler is running.

**The morning list.** Each night Airflow closes the previous UTC day and
builds small tables from it, so a review does not scan a day of events:

```sql
-- the day's most-quarantined runners, with every rule they fired
SELECT runner_ip, events, quarantined, alerted, rules, first_seen, last_seen
FROM watchtower.daily_top_sources WHERE day = yesterday() ORDER BY quarantined DESC;

-- which rules fired, and on how many runners
SELECT rule, recommended_action, events, runners
FROM watchtower.daily_rule_hits WHERE day = yesterday() ORDER BY events DESC;
```

`daily_summary` (events per type and decision) always adds up to the
day's stored events exactly -- the rollup refuses to finish otherwise. An
hourly check also records the data's health in
`watchtower.data_quality_checks`: volume, rejected share, missing fields,
latency, unmerged copies, and whether the share of quarantines jumped against
the past week (`quarantine_share_vs_7d`: a bad commit, a registry outage, or a
rule gone wrong -- look). Details: `docs/orchestration.md`.

### The model

Which model is live, and how it measured:

```sql
SELECT a.activated_at, a.version, a.reason, m.trained_rows, m.metrics
FROM watchtower.ml_model_active AS a JOIN watchtower.ml_models AS m USING (version)
ORDER BY a.activated_at DESC LIMIT 5;
```

A model that is not better is registered but never promoted. To roll back,
promote an earlier version (the stream picks it up within 5 minutes):

```sql
INSERT INTO watchtower.ml_model_active (version, reason)
VALUES ('lgbm-...', 'rollback: <why>');
```

---

## 5. Known gaps -- read before relying on this

**The model learns the simulator.** Its labels are the synthetic
producer's ground truth plus the reviewer's corrections. On real traffic
there is no ground truth: until **your verdicts** become labels, the model
is only as good as the reviewer. It can alert on its own, never quarantine.

**The reviewer has never made a live call** -- no Groq key is set yet
(`secrets/groq_api_key`). Until then the review is skipped. Its prompt was
rewritten for build farms and has not met a real model's answers yet.

**A bad commit is invisible to a per-runner view.** Every feature is
computed per runner. A broken commit fails on *many* runners, a few builds
each, so no runner crosses 20 failures a minute. The detector sees a sick
*runner* well (a retry storm on one machine, a runner failing across 8
projects) and a sick *project* not at all. Closing it needs a second,
project-keyed pass -- the same shape as the second pass the old security
design needed for credential stuffing.

**Features are 1- and 5-minute windows only.** A runner that runs out of
memory once an hour never raises `oom_kills_5m` above one (that single event
is still an `alert`). **This system catches noisy incidents. It does not
catch slow ones**, and a slow memory leak or a creeping compile-time
regression that adds 10% a week will not look like anything to it.

**Duplicate memory is 1,024 events per runner on the live path.** A
re-delivered event is recognised if it repeats one of its runner's last
1,024 events: ~10 minutes for an ordinary runner, ~90 seconds for a CI farm
runner sending 12 events/s. What produces duplicates in practice -- Kafka
producer retries -- arrives within seconds. A duplicate outside that memory
is scored again and counts twice in its runner's features; storage still
collapses it (`FINAL`).

**A runner quiet for 15 minutes is forgotten.** Its windows restart from
zero when it returns. The windows only span 5 minutes, so nothing that
matters to the rules is lost.

**Behavioural rules quarantine the whole runner** while it misbehaves (§1) --
containment, and a policy choice for you to confirm.

**Thresholds assume the simulator's farm.** 20 failures a minute, 8 projects,
250 MB published, a 5-minute slow step, 30 dependency 404s a minute: all
chosen against ~180 simulated runners where healthy ones fail a handful of
builds in five minutes. A farm with flakier tests, bigger artifacts or longer
builds needs these moved (§3), or the CI farm will be flagged every morning.

**The feedback loop is the reviewer's, not yet yours.** The model retrains
on the LLM's corrections; marking an alert as a false positive yourself
still changes nothing. Engineers' verdicts as labels is the next step.

**The reviewer sends event details to a third party (Groq):** runner IPs,
project names, dependency URLs, compiler command lines and error text of the
events it reviews -- up to 3,000 a day. Command lines and error messages can
contain internal paths and, if a build is careless, secrets. Confirm that is
acceptable under your data policy before setting the key on real logs.

**Rogue commands are matched by pattern.** `is_rogue_command` knows miners,
a download piped to a shell, credentials read out and reverse shells. It does
not know a malicious dependency that does its harm inside a normal compiler
invocation. A pinned, signed supply chain is the control for that; this is a
tripwire.

---

## 6. Investigating an alert

Lookups by event id and by runner IP are cheap: the table is laid out for
them (on 43 million events of the earlier workload, a lookup by id read 3 MB
instead of 683 MB, and one runner's whole history 5 MB instead of 1 GB).
**Always include a time range when you have one** -- it narrows the search
further.

The event:

```sql
SELECT *
FROM watchtower.security_events
WHERE event_id = '<the event_id from the alert>'
FORMAT Vertical;
```

The behaviour the decision was based on:

```sql
SELECT timestamp, event_type, project, recommended_action, rule_hits,
       failed_builds_1m, failed_builds_5m, unique_projects_5m, oom_kills_5m,
       slow_steps_5m, dependency_404_1m, published_bytes_5m
FROM watchtower.security_events
WHERE runner_ip = '<ip>'
  AND timestamp > toDateTime64('<alert time>', 3) - INTERVAL 15 MINUTE
  AND timestamp < toDateTime64('<alert time>', 3) + INTERVAL 15 MINUTE
ORDER BY timestamp;
```

Is it the runner or the project? The two look alike on a dashboard and are
fixed by different people:

```sql
-- many projects failing on this runner -> the runner; one project failing on many runners -> the project
SELECT project, runner_ip, count() AS failures
FROM watchtower.security_events
WHERE event_type = 'BUILD_FAILURE' AND timestamp > now() - INTERVAL 15 MINUTE
GROUP BY project, runner_ip ORDER BY failures DESC LIMIT 30;
```

**Exact counts need `FINAL`.** Delivery is at-least-once: after a restart a
few rows can be stored twice, and they collapse only when ClickHouse merges
in the background. `SELECT count() FROM watchtower.security_events FINAL
WHERE ...` is exact; without `FINAL` it may count a replayed event twice.

`security_events` rows do **not** carry Kafka coordinates. The event is
identified by `event_id`; rejected messages (below) keep their topic,
partition and offset.

### Messages that never became events

They are in `watchtower.rejected_events`, with the original bytes kept
(base64):

```sql
SELECT rejected_at, reject_reason, schema_id, kafka_partition, kafka_offset,
       base64Decode(raw_value) AS original
FROM watchtower.rejected_events
ORDER BY rejected_at DESC LIMIT 20;
```

| `reject_reason` | means |
|---|---|
| `not_avro_framed` | not in the Avro wire format at all (e.g. plain JSON) |
| `unknown_schema_version` | a schema version registered after the job started -- restart the job (`docs/operations.md` §5) |
| `undecodable_payload` | framed, but the bytes do not decode |
| `missing_event_id`, `missing_event_type`, `missing_runner_ip` | a required field is empty |
| `invalid_event_id` | the event id is not a UUID |
| `invalid_timestamp` | the timestamp is not ISO-8601 |
| `unknown_event_type` | an event type the pipeline does not know |
| `exit_code_out_of_range`, `port_out_of_range`, `invalid_http_status`, `duration_out_of_range` | impossible values (an exit status is 0-255; a duration over 24 h is a stuck build, not a number) |
| `sink_parse_error` | the job produced a row ClickHouse could not parse -- a pipeline bug, not a bad log source; `raw_value` holds the row |

`StreamRejectingEvents` fires on any of these except `sink_parse_error`
(which ClickHouse creates, after the job) -- check for that one by querying.
**A sudden rise is itself worth investigating**: it usually means a build
tool upgraded and changed its log format, or an agent is sending a field in
a new unit.
