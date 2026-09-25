# Note to the SOC analyst

**Read this before you trust anything this system flags.**

The detector is built, wired in and measured on simulated traffic, but it is
**not tuned for your environment**. Every threshold below was chosen to make
the pipeline work on a simulation, not because it is right for your
network. Tuning it is your job, and this note exists so you can do that
without reading the code.

Nobody has validated a single alert from this system on real traffic yet.

*Last updated 2026-09-25.*

---

## 0. What changed since the previous version of this note

If you read an earlier copy, these are the differences that affect you:

| | before | now |
|---|---|---|
| **engine** | Spark, micro-batches | **Flink, one event at a time** (Spark kept for replays) |
| **time to a decision** | ~5–25 s (a batch every 20 s) | **~5 ms** after the event reaches Kafka |
| **time until the row is queryable** | ~15 s typical | **~0.2 s** (median 194 ms, p95 346 ms at 1,000 events/s) |
| **who decides** | rules, then the LLM for the grey zone | **rules alone** on the live path (the LLM runs only on the Spark replay path, §2) |
| **duplicate memory** | 10 minutes | a source's **last 1,024 events** (§5) |
| **late events** | dropped if > 10 min late | **always scored** |
| **new reject reasons** | — | `invalid_event_id`, `sink_parse_error` (§6) |
| **drill-down queries** | a lookup by IP or event_id scanned the whole table | **20–600x less data read** (§6) |
| **alerts** | `DetectionOutage`, `DetectionDisabled`, `RejectedEventsPresent` | live path: `StreamJobDown`, `StreamFallingBehind`, `StreamLatencyHigh`, `StreamRejectingEvents` (§4) |

The rules, their scores and the thresholds are **unchanged**, and the live
path computes exactly what the Spark path computes — a test feeds the same
traffic through both and requires identical rows.

---

## 1. What the pipeline decides, and from what

Every event ends with a **`recommended_action`: `allow`, `alert`, or
`block`**, plus `rule_hits` naming *why*. That column is the work queue:

```sql
SELECT timestamp, source_ip, event_type, recommended_action, rule_hits,
       url_path, user_agent, command, process_uid
FROM watchtower.suspicious_events
WHERE recommended_action = 'block'
ORDER BY timestamp DESC LIMIT 50;
```

A decision is made within milliseconds of the event reaching Kafka and is
queryable about 0.2 s after the event happened. The decision is also
available, before storage, on the Kafka topic `security-events-scored`
for anything that must react faster than a database query.

### What an event carries (schema v2)

| group | fields |
|---|---|
| origin | `log_source` (sshd, sudo, auditd, nginx, firewall), `outcome`, `session_id` |
| network | `dest_ip`, `dest_port`, `protocol` |
| auth | `auth_method` (password, publickey, mfa, token) |
| **request** | `http_method`, `url_path` (path + query, **undecoded**), `http_status`, `user_agent`, `bytes_sent`, `response_time_ms` |
| **process** | `command`, `process_name`, `parent_process`, `process_uid` (0 = root, **-1 = unknown**) |
| file | `file_path`, `file_operation` |

`url_path` is stored exactly as received. `%2e%2e` is evidence -- decoding
it would erase the traversal signature. `process_uid` of **-1** means the
source did not report one; it is never assumed to be root.

### Indicators -- why an event looks bad, one column each

| column | set when |
|---|---|
| `request_signature` | `sqli`, `path_traversal` or `xss` payload in the URL |
| `is_scanner_agent` | sqlmap, nikto, gobuster, zgrab, nuclei, ... in the User-Agent |
| `is_sensitive_path` | `/.env`, `/.git`, `/wp-admin`, `/phpmyadmin`, `/actuator`, ... |
| `is_sensitive_command` | `/etc/shadow`, `useradd`, `history -c`, `nc -e`, download piped to a shell, ... |
| `is_privileged` | a **known** uid of 0 |

### The rules -- what gets blocked, and how sure each is

Two kinds of evidence. A **signature** is bad in itself -- one is enough. A
**behaviour** is the source's last 1-5 minutes.

| rule | score | fires on |
|---|---|---|
| `reverse_shell` | 1.00 | `nc -e`, `/dev/tcp/`, `bash -i >&` |
| `login_after_brute_force` | 1.00 | a login that **succeeds** after 20+ failures in 5 min |
| `sensitive_command_as_root` | 0.97 | a sensitive command run as uid 0 |
| `sqli`, `path_traversal` | 0.95 | payload in the URL |
| `xss` | 0.90 | payload in the URL |
| `brute_force` | 0.90 | 20+ failed logins in 1 min |
| `password_spray` | 0.90 | 8+ accounts and 20+ failures in 5 min |
| `port_scan` | 0.90 | 10+ distinct ports in 5 min |
| `lateral_movement` | 0.90 | an **internal** host port-scanning (5+ in 5 min) |
| `repeated_attack_signatures` | 0.90 | 5+ injection payloads in 5 min |
| `sensitive_command` | 0.85 | a sensitive command |
| `scanner_agent` | 0.85 | offensive tooling's User-Agent |
| `web_scan` | 0.85 | 30+ 404s in 1 min |
| `data_exfiltration` | 0.85 | 250 MB+ sent in 5 min |
| `sensitive_path_probe` | 0.70 | one probe of `/.env` & co. -- **alert, not block** |

`>= 0.85` is **block**, `>= 0.65` **alert**, else **allow**. The rules need
no API key.

### Reading the score columns on the live path

| column | on the live (Flink) path |
|---|---|
| `rule_score`, `final_anomaly_score` | the highest-scoring rule that fired (0 if none) |
| `rule_hits` | every rule that fired, strongest first |
| `llm_score`, `llm_model` | always `0` / empty |
| `llm_reason` | `skipped:rule_decided` (blocked by rules) or `detection_disabled:streaming_rules_only` (not blocked; no LLM second opinion) |

So on the live path an event the rules do not settle is **allowed**. There
is no grey-zone judgement yet (§5).

### Measured (synthetic company traffic)

On ~33,000 labelled events (Spark path, same rules):

| scenario | blocked | how |
|---|---|---|
| path traversal | **100%** | signature, from the first request |
| web scan | **100%** | scanner User-Agent, from the first request |
| ssh brute force | **100%** | behaviour |
| data exfiltration | **97.9%** | volume -- a normal browser, 200s, only size gives it away |
| password spray | **94.6%** | behaviour |
| lateral movement | **94.3%** | behaviour |
| **normal traffic** | **0.32% blocked, 0% alerted** | see below |

On the live path, a 10-minute run at 1,000 events/s: 576,843 allowed,
16,654 blocked, every attack family firing its rule (brute force 8,535
hits, password spray 8,155, repeated signatures 6,316, web scan 4,483,
login after brute force 3,329, scanner agent 3,019, port scan 2,314, …).
**The per-scenario percentages above have not yet been re-measured against
the live path's output** (`make evaluate`); the logic is the same, and a
test holds it equal.

**Two things to understand about those numbers.**

*Behavioural rules miss an attack's first few events.* A brute force is
invisible until the failures pile up -- that is the 2-6% gap. Signature
rules have no such gap: the first SQL injection is blocked.

*The 0.32% are not innocent hosts.* All 90 came from exactly two
workstations -- the ones running the exfiltration and lateral-movement
attacks -- and were those hosts' own background traffic during the attack.
Behavioural rules key on the SOURCE, so a host that is exfiltrating gets
**all** its traffic blocked for the window. That is containment, and
usually what you want. **It is a policy choice, and yours to confirm**:
if you would rather block only the offending requests, the behavioural
rules must be scoped to event type.

---

## 2. How a score is produced

```
   every event
        |
   RULES              deterministic, no API call  -> rule_score, rule_hits
        |
   +----+----------------------------------------+
   |                                             |
 live path (Flink)                         replay path (Spark)
   |                                             |
 final = rule score                  rule score >= 0.85 -> decided
                                     otherwise -> TRIAGE GATE -> LLM (Groq)
                                     final = max(rule score, LLM score)
```

**Why the live path has no LLM.** A remote API call per undecided event
would hold up that source's stream while the call is in flight -- the
opposite of deciding each event as it arrives. Bringing the LLM back needs
an asynchronous step: rule decisions go out immediately, and an LLM verdict
updates the row when it arrives. That is on the roadmap, not built.

### The LLM on the replay path

Verdicts come from Groq, not a fitted model; nothing is trained. Because
one call per event is impossible at volume, events pass a **triage gate**
first, and verdicts are cached by behaviour signature for 60 seconds.
Measured on 59,300 labelled events (v1 traffic):

| | events | reach the LLM |
|---|---|---|
| benign traffic | 55,724 | **0.1%** |
| ssh brute force | 1,700 | 98.7% |
| password spray | 805 | 98.5% |
| lateral movement | 849 | 96.3% |
| **all attacks** | 3,576 | **92.7%** (recall ceiling) |

The LLM sees one sentence per candidate, not log lines:

```
external IP 45.134.26.7, night: 40 events/min, 38 failed logins/min,
180 failed logins/5min, 1 distinct accounts, 0 port scans, ...
```

`llm_reason` is the model's own justification. Treat it as a hypothesis to
check, not a finding.

---

## 3. The settings you will need to change

All are environment variables; none require code changes. On Kubernetes
they belong in the `pipeline-env` ConfigMap (deploy/k8s overlays); in dev,
on the Flink containers in `docker-compose.yml`. **They take effect when the
job restarts.**

### Both paths

| variable | default | meaning |
|---|---|---|
| `WATCHTOWER_BLOCK_THRESHOLD` | `0.85` | score at or above which an event is `block` |
| `WATCHTOWER_THRESHOLD` | `0.65` | score at or above which an event is `alert` / `is_suspicious` |

These were not derived from your data. Work backwards from your capacity:
the alert threshold should yield roughly the number of alerts your team can
actually triage. The rule scores themselves (§1) live in
`etl/core/rules.py` (live path) and `etl/detect/rules.py` (replay path),
and a test requires the two to agree.

### Live path only

| variable | default | meaning |
|---|---|---|
| `WATCHTOWER_DEDUP_RECENT` | `1024` | how many recent event ids each source remembers for duplicate detection (§5) |
| `WATCHTOWER_SOURCE_IDLE_MS` | 15 min | a source silent this long is forgotten: its windows restart from zero |

### Replay path only (the LLM)

| variable | default | meaning |
|---|---|---|
| `TRIAGE_FAILED_1M` / `_5M` | 12 / 30 | failed logins that make an event an LLM candidate |
| `TRIAGE_PORTS_5M` / `TRIAGE_SCANS_5M` | 6 / 4 | distinct ports / port-scan events |
| `TRIAGE_USERS_5M` | 8 | distinct accounts |
| `TRIAGE_REQUESTS_1M` | 900 | events per minute |
| `GROQ_MODEL` | `llama-3.1-8b-instant` | pin it; a model change is a detector change |
| `GROQ_VERDICT_TTL` | 60 s | how long a verdict is reused for matching behaviour |
| `GROQ_BATCH_SIZE` / `GROQ_MIN_INTERVAL` | 25 / 0.5 s | candidates per call, gap between calls |

Each triage default sits just above what that feature reaches on benign
simulated traffic; guessed values once sent 46.9% of normal traffic to the
API. **Re-measure them against your own traffic** -- they encode what this
simulation's backup jobs and CI runners do, not what yours do. The v2
triage signals have not been re-measured at all.

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
a quiet period, or the job not running. Check before concluding it was
quiet:

```sql
SELECT count() AS stored_last_minute
FROM watchtower.security_events
WHERE ingested_at > now() - INTERVAL 1 MINUTE;
```

Zero means nothing is arriving at all -- look at the job, not the threats.

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

### If you run the replay path with the LLM

Set the key as a file (`secrets/groq_api_key`), never an exported variable
in a shared shell. Without it the replay path still runs; rows carry
`detection_disabled:no_api_key`.

On that path detection **fails open**: an API error scores the event 0 and
lets it through, so an outage looks like a quiet night. `DetectionOutage`
fires when any event in the last 10 minutes passed unjudged;
`DetectionDisabled` when there is no key. By hand:

```sql
SELECT count() AS failures
FROM watchtower.security_events
WHERE timestamp > now() - INTERVAL 10 MINUTE
  AND llm_reason LIKE 'llm_error%';
```

---

## 5. Known gaps — read before relying on this

**No grey-zone judgement on the live path.** Whatever the rules do not
settle is `allow`. The LLM exists only on the replay path, and has never
made a live API call (no key has been set).

**Duplicate memory is 1,024 events per source on the live path.** A
re-delivered event is recognised if it repeats one of its source's last
1,024 events: ~10 minutes for an ordinary host, ~25 seconds for a source
sending 40 events/s. What produces duplicates in practice -- Kafka producer
retries -- arrives within seconds. A duplicate outside that memory is
scored again and counts twice in its source's features; storage still
collapses it (`FINAL`).

**A source quiet for 15 minutes is forgotten.** Its windows restart from
zero when it returns. The windows only span 5 minutes, so nothing that
matters to the rules is lost.

**`unique_source_ips_5m` is always 0.** Every feature is computed per
source IP, so "how many IPs has this *user* come from" cannot be derived.
**Credential stuffing -- one account accessed from many IPs -- is currently
invisible.** Closing it needs a second, user-keyed pass.

**Features are 1- and 5-minute windows only.** A patient attacker doing
three failed logins every ten minutes never raises `failed_logins_5m` above
three. **This system catches noisy attacks. It does not catch slow ones.**

**Behavioural rules block the whole source** while it misbehaves (§1) --
containment, and a policy choice for you to confirm.

**No feedback loop.** Marking an alert as a false positive changes nothing.
Improving detection means editing the rules or thresholds by hand.

**On the replay path only:** the LLM depends on an external API, is not
deterministic across model versions (pin `GROQ_MODEL`), and sends behaviour
summaries -- including internal IP addresses, never log content, usernames
or commands -- to a third party. Confirm that is acceptable under your data
policy before running it on real traffic.

**Privilege escalation -- closed.** 144 hostile commands in 5 minutes used
to look the same as the CI runners' 1,762 routine ones. Commands are now
read: `is_sensitive_command` flags them individually and
`sensitive_command_as_root` blocks one at 0.97. The backup job running
`rsync` as root stays `allow`.

---

## 6. Investigating an alert

Lookups by event id and by source IP are now cheap: the table is laid out
for them (on 43 million events, a lookup by id reads 3 MB instead of
683 MB, and one IP's whole history 5 MB instead of 1 GB). **Always include a
time range when you have one** -- it narrows the search further.

The event:

```sql
SELECT *
FROM watchtower.security_events
WHERE event_id = '<the event_id from the alert>'
FORMAT Vertical;
```

The behaviour the decision was based on:

```sql
SELECT timestamp, event_type, user, recommended_action, rule_hits,
       failed_logins_1m, failed_logins_5m, unique_ports_5m, http_404_1m, bytes_sent_5m
FROM watchtower.security_events
WHERE source_ip = '<ip>'
  AND timestamp > toDateTime64('<alert time>', 3) - INTERVAL 15 MINUTE
  AND timestamp < toDateTime64('<alert time>', 3) + INTERVAL 15 MINUTE
ORDER BY timestamp;
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
| `missing_event_id`, `missing_event_type`, `missing_source_ip` | a required field is empty |
| `invalid_event_id` | the event id is not a UUID |
| `invalid_timestamp` | the timestamp is not ISO-8601 |
| `unknown_event_type` | an event type the pipeline does not know |
| `port_out_of_range`, `invalid_http_status` | impossible values |
| `sink_parse_error` | the job produced a row ClickHouse could not parse -- a pipeline bug, not a bad log source; `raw_value` holds the row |

`StreamRejectingEvents` fires on any of these except `sink_parse_error`
(which ClickHouse creates, after the job) -- check for that one by querying.
On the replay path the equivalent alert is `RejectedEventsPresent`. **A
sudden rise is itself worth investigating**: it can mean a broken log source, or something
deliberately malforming logs to avoid being parsed.
