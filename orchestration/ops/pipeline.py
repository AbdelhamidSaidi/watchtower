"""The pipeline end to end, checked in the order data travels through it.

watchtower_pipeline (orchestration/dags/watchtower_pipeline.py) runs these
every 10 minutes:

  infrastructure  kafka, schema_registry, clickhouse -- up, and set up?
  stream_job      the Flink job RUNNING? If it has stopped for good,
                  restart it through the Flink operator (Kubernetes)
  sample_flow     every topic's end offsets and both consumer groups'
                  committed offsets, twice, SAMPLE_S apart
  extract         events arriving in security-logs
  transform       Flink keeping up with them and writing its results
  load            ClickHouse taking the results in; rows landing; latency

Every check is a result in one shape -- stage, name, value, threshold,
severity, passed -- recorded in watchtower.pipeline_health. A failed `fail`
check fails its stage's task, so the DAG's graph turns red at the stage
where the pipeline is broken; `warn` results are only recorded.

Prometheus alerts on the same signals minute by minute; this is the
end-to-end verdict, kept as history, that other DAGs can wait for
(healthy_recently).
"""

import json
import os
import ssl
import time
import urllib.request

from etl import config
from orchestration.ops.quality import OPS

TOPICS = (config.KAFKA_TOPIC, config.SCORED_TOPIC, config.REJECTED_TOPIC)
TABLES = ("security_events", "rejected_events", "suspicious_events",
          "security_events_queue", "rejected_events_queue")
# The Kafka engine's consumer group for scored events
# (clickhouse/init/03_streaming_ingest.sql).
CLICKHOUSE_GROUP = "clickhouse-security-events"

FLINK_REST_URL = os.getenv("FLINK_REST_URL", "http://flink-jobmanager:8081")
FLINK_JOB = "watchtower-stream"
# "operator": restart a stopped job by bumping the FlinkDeployment's
# restartNonce (Kubernetes; the operator resumes it from its last
# checkpoint). "none": report it -- in docker compose, restart policies
# and run-job.sh already bring a crashed job back.
FLINK_RESTART = os.getenv("WATCHTOWER_FLINK_RESTART", "none")
FLINK_DEPLOYMENT = os.getenv("WATCHTOWER_FLINK_DEPLOYMENT", "stream")

RUNNING = "RUNNING"
# Flink calls a job RUNNING as soon as it starts scheduling, even while its
# tasks wait for a TaskManager slot that may never come. Until every task
# runs, it is DEPLOYING here.
DEPLOYING = "DEPLOYING"
# States a job passes through on its own; waited out, not acted on.
TRANSIENT = {"INITIALIZING", "CREATED", "RESTARTING", "RECONCILING", "FAILING", "CANCELLING", DEPLOYING}

SAMPLE_S = 20

# Thresholds. Lags are in seconds of traffic: events waiting / arrival rate.
MAX_STREAM_LAG_S = 120      # Flink commits offsets at checkpoints (10 s), so ~10 s is normal
MIN_OUTPUT_RATIO = 0.5      # (scored + rejected) written per event arriving
MAX_INTAKE_LAG_S = 60       # scored results not yet in ClickHouse
MAX_LATENCY_P95_MS = 2000   # same line as the StreamLatencyHigh alert
MAX_REJECTED_SHARE = 0.01
# Events that passed validation but are doubtful after normalize or enrich
# (etl/core/dq.py); same line as the StreamDataQualityDegraded alert.
MAX_DOUBTFUL_SHARE = 0.01


def result(stage, name, severity, value, op, threshold, description):
    """One check's verdict. No value means nothing to judge: passed."""
    base = {"stage": stage, "check_name": name, "severity": severity, "threshold": float(threshold)}
    if value is None:
        return {**base, "value": None, "passed": True, "detail": f"{stage}/{name}: nothing to judge ({description})"}
    passed = OPS[op](value, threshold)
    return {**base, "value": float(value), "passed": passed,
            "detail": f"{stage}/{name} = {value:g}, must be {op} {threshold:g} ({description})"}


def up(stage, name, ok, detail):
    """An is-it-there check: 1 or 0."""
    return {"stage": stage, "check_name": name, "severity": "fail", "threshold": 1.0,
            "value": 1.0 if ok else 0.0, "passed": ok, "detail": f"{stage}/{name}: {detail}"}


def failures(results):
    return [r for r in results if r["severity"] == "fail" and not r["passed"]]


# --- infrastructure ------------------------------------------------------------

def _consumer(**kw):
    from kafka import KafkaConsumer

    return KafkaConsumer(bootstrap_servers=config.KAFKA_BOOTSTRAP_SERVERS, enable_auto_commit=False,
                         request_timeout_ms=15_000, **kw)


def check_kafka():
    try:
        consumer = _consumer()
        try:
            present = consumer.topics()
            partitions = {t: len(consumer.partitions_for_topic(t) or ()) for t in TOPICS if t in present}
        finally:
            consumer.close()
    except Exception as exc:
        return [up("infrastructure", "kafka", False, f"unreachable at {config.KAFKA_BOOTSTRAP_SERVERS} ({exc})")]
    missing = [t for t in TOPICS if t not in present]
    if missing:
        return [up("infrastructure", "kafka", False, f"topics missing: {', '.join(missing)}")]
    return [up("infrastructure", "kafka", True,
               ", ".join(f"{t} ({n} partitions)" for t, n in partitions.items()))]


def _get_json(url, timeout=10):
    with urllib.request.urlopen(url, timeout=timeout) as response:
        return json.load(response)


def check_registry():
    url = f"{config.SCHEMA_REGISTRY_URL}/subjects/{config.SCHEMA_SUBJECT}/versions/latest"
    try:
        latest = _get_json(url)
    except Exception as exc:
        return [up("infrastructure", "schema_registry", False, f"{url}: {exc}")]
    return [up("infrastructure", "schema_registry", True,
               f"{config.SCHEMA_SUBJECT} v{latest['version']} (id {latest['id']})")]


def check_clickhouse(ch):
    try:
        present = {r["name"] for r in ch.rows("SELECT name FROM system.tables WHERE database = 'watchtower'")}
    except Exception as exc:
        return [up("infrastructure", "clickhouse", False, f"unreachable ({str(exc)[:200]})")]
    missing = [t for t in TABLES if t not in present]
    if missing:
        return [up("infrastructure", "clickhouse", False, f"tables missing: {', '.join(missing)}")]
    return [up("infrastructure", "clickhouse", True, f"{len(TABLES)} pipeline tables present")]


# --- the stream job ----------------------------------------------------------------

def stream_job_state(get_json=_get_json):
    """(state, job id) of the stream job; (None, None) if Flink is unreachable
    or has no such job. A RUNNING instance wins over older, finished ones."""
    try:
        jobs = [j for j in get_json(f"{FLINK_REST_URL}/jobs/overview")["jobs"] if j["name"] == FLINK_JOB]
    except Exception:
        return None, None
    if not jobs:
        return None, None
    job = max(jobs, key=lambda j: (j["state"] == RUNNING, j.get("start-time", 0)))
    tasks = job.get("tasks", {})
    if job["state"] == RUNNING and tasks.get("running", 0) < tasks.get("total", 0):
        return DEPLOYING, job["jid"]
    return job["state"], job["jid"]


def restart_via_operator():
    """Bump the FlinkDeployment's restartNonce; the operator redeploys the job
    from its last checkpoint (upgradeMode: last-state). Needs the patch
    permission granted in deploy/k8s/components/airflow/airflow.yaml."""
    sa = "/var/run/secrets/kubernetes.io/serviceaccount"
    namespace = open(f"{sa}/namespace").read().strip()
    token = open(f"{sa}/token").read().strip()
    request = urllib.request.Request(
        f"https://kubernetes.default.svc/apis/flink.apache.org/v1beta1/namespaces/{namespace}"
        f"/flinkdeployments/{FLINK_DEPLOYMENT}",
        data=json.dumps({"spec": {"restartNonce": int(time.time())}}).encode(),
        method="PATCH",
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/merge-patch+json"},
    )
    urllib.request.urlopen(request, context=ssl.create_default_context(cafile=f"{sa}/ca.crt"), timeout=30)


def ensure_stream_job(wait_s=300, poll_s=10, get_json=_get_json, restart=restart_via_operator,
                      sleep=time.sleep, clock=time.monotonic):
    """The job RUNNING, or a failed result saying why not.

    Transient states and an unreachable JobManager are waited out (a
    restarting job passes through both). A job stopped for good is
    restarted when FLINK_RESTART allows it, then waited for.
    """
    deadline = clock() + wait_s
    state, jid = stream_job_state(get_json)
    restarted = False
    while state != RUNNING and clock() < deadline:
        if state is not None and state not in TRANSIENT and not restarted:
            if FLINK_RESTART != "operator":
                return [up("stream_job", "flink_job", False,
                           f"{FLINK_JOB} is {state} and restarts are off here "
                           f"(WATCHTOWER_FLINK_RESTART={FLINK_RESTART}); in docker compose: "
                           "docker compose restart flink-jobmanager")]
            restart()
            restarted = True
        sleep(poll_s)
        state, jid = stream_job_state(get_json)

    if state != RUNNING:
        return [up("stream_job", "flink_job", False,
                   f"{FLINK_JOB} not RUNNING after {wait_s} s (last seen: {state or 'unreachable'})")]
    results = [up("stream_job", "flink_job", True, f"{FLINK_JOB} RUNNING, every task running ({jid})")]
    if restarted:
        results.append({"stage": "stream_job", "check_name": "restarted", "severity": "warn",
                        "value": 1.0, "threshold": 0.0, "passed": False,
                        "detail": f"stream_job/restarted: {FLINK_JOB} had stopped and was restarted "
                                  "through the Flink operator -- find out why"})
    return results


def dq_counters(get_json=_get_json):
    """The stream job's data-quality counters, summed over its subtasks:
    {"normalize_missing_project": n, ..., "scored": n}. None if unreadable.

    Counters start again from 0 when the job restarts; sample_flow keeps
    only increases.
    """
    try:
        state, jid = stream_job_state(get_json)
        if jid is None:
            return None
        totals = {}
        for vertex in get_json(f"{FLINK_REST_URL}/jobs/{jid}")["vertices"]:
            base = f"{FLINK_REST_URL}/jobs/{jid}/vertices/{vertex['id']}/metrics"
            ids = [m["id"] for m in get_json(base)
                   if ".watchtower.dq_" in m["id"] or m["id"].endswith(".watchtower.scored_events")]
            if not ids:
                continue
            for metric in get_json(f"{base}?get={','.join(ids)}"):
                name = metric["id"].split(".watchtower.", 1)[1]
                key = name[len("dq_"):] if name.startswith("dq_") else "scored"
                totals[key] = totals.get(key, 0.0) + float(metric["value"])
        return totals
    except Exception:
        return None


# --- the flow ----------------------------------------------------------------------

def _committed(group, partitions):
    """A group's committed offsets, read without joining the group: no
    subscription, no auto-commit, so the running consumer is not disturbed."""
    consumer = _consumer(group_id=group)
    try:
        return {tp: consumer.committed(tp) for tp in partitions}
    finally:
        consumer.close()


def sample_flow(seconds=SAMPLE_S, sleep=time.sleep, counters=dq_counters):
    """Arrival rate per topic over `seconds`, each group's lag at the end,
    and what the job's data-quality counters counted in between."""
    from kafka import TopicPartition

    consumer = _consumer()
    try:
        tps = {t: [TopicPartition(t, p) for p in sorted(consumer.partitions_for_topic(t))] for t in TOPICS}
        every = [tp for group in tps.values() for tp in group]
        t0, end0, dq0 = time.monotonic(), consumer.end_offsets(every), counters()
        sleep(seconds)
        t1, end1, dq1 = time.monotonic(), consumer.end_offsets(every), counters()
    finally:
        consumer.close()

    elapsed = max(t1 - t0, 1e-3)
    lag = {}
    for group, topic in ((config.CONSUMER_GROUP, config.KAFKA_TOPIC), (CLICKHOUSE_GROUP, config.SCORED_TOPIC)):
        committed = _committed(group, tps[topic])
        # A partition the group never committed on counts from its start.
        lag[group] = sum(max(0, end1[tp] - (committed[tp] or 0)) for tp in tps[topic])
    return {
        "seconds": elapsed,
        "rate": {t: sum(end1[tp] - end0[tp] for tp in tps[t]) / elapsed for t in TOPICS},
        "lag": lag,
        "dq": None if dq0 is None or dq1 is None
        else {k: max(0.0, v - dq0.get(k, 0.0)) for k, v in dq1.items()},
    }


def judge_extract(sample, min_rate):
    arriving = sample["rate"][config.KAFKA_TOPIC]
    refused = sample["rate"][config.REJECTED_TOPIC]
    return [
        result("extract", "input_rate", "fail", arriving, ">=", min_rate,
               f"events/s arriving in {config.KAFKA_TOPIC}"),
        result("extract", "rejected_share", "warn", refused / arriving if arriving else None, "<=",
               MAX_REJECTED_SHARE, "share of arriving messages refused"),
    ]


def _issues(dq, steps):
    found = {k: v for k, v in (dq or {}).items() if k.split("_", 1)[0] in steps and v}
    total = sum(found.values())
    listed = ", ".join(f"{k} {int(v)}" for k, v in sorted(found.items(), key=lambda kv: -kv[1]))
    return total, listed


def judge_transform(sample):
    arriving = sample["rate"][config.KAFKA_TOPIC]
    written = sample["rate"][config.SCORED_TOPIC] + sample["rate"][config.REJECTED_TOPIC]
    dq = sample.get("dq")
    doubtful, doubtful_listed = _issues(dq, ("normalize", "enrich"))
    broken, broken_listed = _issues(dq, ("features", "rules"))
    scored = (dq or {}).get("scored", 0.0)
    return [
        result("transform", "lag_seconds", "fail",
               sample["lag"][config.CONSUMER_GROUP] / max(arriving, 1.0), "<=", MAX_STREAM_LAG_S,
               "input waiting for Flink, in seconds of traffic"),
        result("transform", "output_ratio", "fail", written / arriving if arriving else None, ">=",
               MIN_OUTPUT_RATIO, "results written per event arriving"),
        # Between the steps, from the job's own counters (etl/core/dq.py).
        result("transform", "doubtful_share", "warn", doubtful / scored if dq and scored else None, "<=",
               MAX_DOUBTFUL_SHARE,
               "events doubtful after normalize/enrich" + (f": {doubtful_listed}" if doubtful_listed else "")),
        result("transform", "logic_inconsistent", "fail", broken if dq else None, "==", 0,
               "events whose features or decision contradict themselves -- a bug, never traffic"
               + (f": {broken_listed}" if broken_listed else "")),
    ]


def judge_load(sample, ch, min_rate):
    arriving = sample["rate"][config.KAFKA_TOPIC]
    scored = sample["rate"][config.SCORED_TOPIC]
    rows = ch.value("SELECT count() FROM watchtower.security_events "
                    "WHERE ingested_at > now64(3) - INTERVAL 1 MINUTE")
    p95 = ch.value("SELECT quantile(0.95)(toUnixTimestamp64Milli(ingested_at) - toUnixTimestamp64Milli(timestamp)) "
                   "FROM watchtower.security_events WHERE ingested_at > now64(3) - INTERVAL 5 MINUTE")
    errors = ch.value("SELECT countIf(arrayExists(t -> t > now() - INTERVAL 10 MINUTE, exceptions.time)) "
                      "FROM system.kafka_consumers WHERE database = 'watchtower'")
    return [
        result("load", "lag_seconds", "fail", sample["lag"][CLICKHOUSE_GROUP] / max(scored, 1.0), "<=",
               MAX_INTAKE_LAG_S, "scored results not yet taken in by ClickHouse, in seconds of traffic"),
        # Without input there is nothing to land; extract has already said so.
        result("load", "rows_last_minute", "fail", rows if arriving >= min_rate else None, ">=", 1,
               "rows stored in security_events in the last minute"),
        result("load", "latency_p95_ms", "warn", p95, "<=", MAX_LATENCY_P95_MS,
               "event created -> row stored, last 5 minutes"),
        result("load", "intake_errors", "warn", errors, "==", 0,
               "ClickHouse Kafka consumers with an exception in the last 10 minutes"),
    ]


# --- for other DAGs ------------------------------------------------------------------

def healthy_recently(ch, max_age_minutes=20):
    """Did the latest pipeline check, within `max_age_minutes`, get all the
    way to `load` with no failed `fail` check?"""
    rows = ch.rows(
        "SELECT run_id, max(checked_at) AS at, countIf(severity = 'fail' AND passed = 0) AS failed, "
        "countIf(stage = 'load') AS load_checks FROM watchtower.pipeline_health "
        "WHERE checked_at > now64(3) - toIntervalMinute({age:UInt32}) "
        "GROUP BY run_id ORDER BY at DESC LIMIT 1",
        age=max_age_minutes,
    )
    return bool(rows) and rows[0]["failed"] == 0 and rows[0]["load_checks"] > 0
