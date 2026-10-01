#!/usr/bin/env bash
# End-to-end smoke test for the dev (docker compose) stack, run by CI and by
# `make smoke-dev`. The stack must be up WITH the producer:
#
#   LOGS_PER_SECOND=50 INCIDENT_START_CHANCE=0.05 docker compose --profile sim up -d
#   tools/smoke_dev.sh
#
# It checks behaviour, not container status: a container can be "Up" while the
# pipeline stores nothing. Every check must pass or this exits non-zero.
# (deploy/k8s/scripts/smoke-test.sh is the same idea for a Kubernetes namespace.)
#
# Needs `pip install kafka-python fastavro` on the host for the last check
# (tools/evaluate_detection.py reads the simulator's ground truth from Kafka).
set -uo pipefail
cd "$(dirname "$0")/.."

FAILED=0
pass() { printf '  \033[32mPASS\033[0m  %s\n' "$1"; }
fail() { printf '  \033[31mFAIL\033[0m  %s\n' "$1"; FAILED=1; }

# One SQL statement in, one value out. Sent on stdin so no quoting survives.
ch() {
  docker exec -i watchtower-clickhouse sh -c \
    'clickhouse-client --user watchtower --password "$(cat /run/secrets/clickhouse_password)" --database watchtower' \
    <<<"$1" 2>/dev/null
}

# A number, or 0 when the query returned nothing (ClickHouse down, no table yet).
num() { printf '%s' "${1:-0}" | grep -E '^[0-9]+$' || echo 0; }

# wait_until <seconds> <command...>: poll every 3 s until the command succeeds.
wait_until() {
  local limit="$1" waited=0
  shift
  until "$@" >/dev/null 2>&1; do
    [ "$waited" -ge "$limit" ] && return 1
    sleep 3
    waited=$((waited + 3))
  done
}

job_running() {
  docker exec watchtower-flink-jobmanager curl -s localhost:8081/jobs/overview | grep -q '"state":"RUNNING"'
}
has_events() { [ "$(num "$(ch 'SELECT count() FROM security_events')")" -gt 0 ]; }
has_flags() { [ "$(num "$(ch "SELECT countIf(recommended_action != 'ok') FROM security_events")")" -gt 0 ]; }

echo "smoke test: dev stack"
docker ps >/dev/null 2>&1 || { echo "docker is not reachable"; exit 1; }

# 1. the streaming job is running
if wait_until 180 job_running; then pass "Flink job RUNNING"; else fail "Flink job not running after 180 s"; fi

# 2. the schema is registered, with the compatibility level enforced
compat="$(curl -s localhost:8081/config/security-logs-value)"
case "$compat" in
  *BACKWARD*) pass "schema registered, compatibility BACKWARD" ;;
  *) fail "schema subject missing or compatibility not BACKWARD ($compat)" ;;
esac

# 3. data is actually arriving -- the check that matters
if wait_until 180 has_events; then
  before="$(num "$(ch 'SELECT count() FROM security_events')")"
  sleep 20
  after="$(num "$(ch 'SELECT count() FROM security_events')")"
  if [ "$after" -gt "$before" ]; then
    pass "security_events growing: ${before} -> ${after} (+$((after - before)) in 20 s)"
  else
    fail "security_events not growing (${before} -> ${after})"
  fi
else
  fail "no event stored after 180 s"
fi

# 4. dedup holding, and nothing refused from a well-behaved producer
dupes="$(ch 'SELECT count() - uniqExact(event_id) FROM security_events')"
[ "$dupes" = "0" ] && pass "zero duplicate event_ids" || fail "${dupes:-?} duplicate event_ids"
rejected="$(ch 'SELECT count() FROM rejected_events')"
[ "$rejected" = "0" ] && pass "zero rejected events" || fail "${rejected:-?} rejected events -- check reject_reason"

# 5. the features are computed: a runner's window holds more than the event itself
window="$(num "$(ch 'SELECT max(events_1m) FROM security_events')")"
[ "$window" -gt 1 ] && pass "rolling windows populated (max events_1m ${window})" || fail "windows empty (max events_1m ${window:-?})"

# 6. the rules fire: the simulator's incidents are flagged
if wait_until 120 has_flags; then
  pass "incidents flagged: $(ch "SELECT countIf(recommended_action = 'quarantine') FROM security_events") quarantine, $(ch "SELECT countIf(recommended_action = 'alert') FROM security_events") alert"
else
  fail "nothing flagged after 120 s -- no incident ran, or the rules never fired"
fi

# 7. fast: end to end, event created -> row stored
p95="$(ch 'SELECT round(quantile(0.95)(toUnixTimestamp64Milli(ingested_at) - toUnixTimestamp64Milli(timestamp))) FROM security_events WHERE ingested_at > now64(3) - INTERVAL 60 SECOND')"
if [ -n "$p95" ] && [ "$(num "${p95%.*}")" -gt 0 ] && [ "${p95%.*}" -lt 5000 ]; then
  pass "end-to-end p95 latency ${p95} ms (budget 5000)"
else
  fail "end-to-end p95 latency ${p95:-?} ms over the 5000 ms budget"
fi

# 8. detection against the simulator's ground truth. A rule that only needs the
# last second of an incident may not have fired yet, so one miss is allowed.
if python3 -c "import kafka, fastavro" 2>/dev/null; then
  report="$(python3 tools/evaluate_detection.py --minutes 3 --json 2>/dev/null)"
  [ -n "$report" ] || report='{"summary": {"incidents_seen": 0, "incidents_caught": 0, "coverage": 0, "normal_quarantined_uninvolved": 0}}'
  verdict="$(REPORT="$report" python3 - <<'PY' 2>&1
import json, os

r = json.loads(os.environ["REPORT"])
s = r["summary"]
seen, caught, coverage = s["incidents_seen"], s["incidents_caught"], s["coverage"] or 0
problems = []
if seen < 1:
    problems.append("no incident in the window")
if caught < seen - 1:
    problems.append(f"{seen - caught} of {seen} incidents never flagged")
if coverage < 0.999:
    problems.append(f"coverage {coverage:.3f}")
if s["normal_quarantined_uninvolved"]:
    problems.append(f"{s['normal_quarantined_uninvolved']} quarantines on uninvolved runners")
print("; ".join(problems) if problems else
      f"OK {caught}/{seen} incidents caught, coverage {coverage:.3f}, no uninvolved runner quarantined")
PY
)"
  case "$verdict" in
    OK*) pass "detection vs ground truth: ${verdict#OK }" ;;
    *) fail "detection vs ground truth: ${verdict:-evaluator printed nothing}" ;;
  esac
else
  echo "  SKIP  detection vs ground truth (pip install kafka-python fastavro)"
fi

echo
if [ "$FAILED" = "0" ]; then echo "smoke test PASSED"; else echo "smoke test FAILED"; fi
exit "$FAILED"
