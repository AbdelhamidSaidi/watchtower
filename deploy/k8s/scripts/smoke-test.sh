#!/usr/bin/env bash
# End-to-end smoke test for a deployed environment. The gate for promotion.
#
# Checks behaviour, not just pod status: a pod can be Running while the
# pipeline stores nothing. Every check must pass, or this exits non-zero and
# `make promote` stops before prod.
#
#   smoke-test.sh <namespace>
set -uo pipefail

NS="${1:?usage: smoke-test.sh <namespace>}"
FAILED=0
pass() { printf '  \033[32mPASS\033[0m  %s\n' "$1"; }
fail() { printf '  \033[31mFAIL\033[0m  %s\n' "$1"; FAILED=1; }

ch() {
  kubectl -n "$NS" exec clickhouse-0 -- sh -c \
    "clickhouse-client --user watchtower --password \"\$CLICKHOUSE_PASSWORD\" -d watchtower -q \"$1\"" 2>/dev/null
}
metric() {  # one value from the Flink TaskManagers' /metrics, max over pods
  for pod in $(kubectl -n "$NS" get pods -l component=taskmanager -o name 2>/dev/null); do
    kubectl -n "$NS" exec "$pod" -- sh -c "curl -s localhost:9249/metrics" 2>/dev/null
  done | grep -E "^$1" | awk '{print $NF}' | sort -g | tail -1
}

echo "smoke test: $NS"

# 1. Kafka cluster reconciled by Strimzi
if kubectl -n "$NS" wait kafka/watchtower --for=condition=Ready --timeout=30s >/dev/null 2>&1; then
  pass "Kafka cluster Ready ($(kubectl -n "$NS" get kafkanodepool brokers -o jsonpath='{.spec.replicas}') broker(s))"
else
  fail "Kafka cluster not Ready"
fi

# 2. every Deployment available
unavailable="$(kubectl -n "$NS" get deploy -o jsonpath='{range .items[?(@.status.availableReplicas!=@.spec.replicas)]}{.metadata.name} {end}')"
[ -z "$unavailable" ] && pass "all Deployments available" || fail "unavailable: $unavailable"

# 3. schema registered, with the compatibility level enforced
compat="$(kubectl -n "$NS" exec deploy/schema-registry -- python3 -c \
  "import urllib.request;print(urllib.request.urlopen('http://localhost:8081/config/security-logs-value',timeout=5).read().decode())" 2>/dev/null)"
case "$compat" in
  *BACKWARD*) pass "schema registered, compatibility BACKWARD" ;;
  *) fail "schema subject missing or compatibility not BACKWARD ($compat)" ;;
esac

# 4. the streaming job running
state="$(kubectl -n "$NS" get flinkdeployment stream -o jsonpath='{.status.jobStatus.state}' 2>/dev/null)"
[ "$state" = "RUNNING" ] && pass "Flink job RUNNING" || fail "Flink job not running (${state:-no FlinkDeployment})"

# 5. data is actually arriving -- the check that matters
before="$(ch 'SELECT count() FROM security_events')"
sleep 45
after="$(ch 'SELECT count() FROM security_events')"
if [ -n "$before" ] && [ -n "$after" ] && [ "$after" -gt "$before" ]; then
  pass "security_events growing: ${before} -> ${after} (+$((after - before)) in 45s)"
else
  fail "security_events not growing (${before:-?} -> ${after:-?})"
fi

# 6. dedup holding
dupes="$(ch 'SELECT count() - uniqExact(event_id) FROM security_events')"
[ "$dupes" = "0" ] && pass "zero duplicate event_ids" || fail "$dupes duplicate event_ids"

# 7. nothing rejected from a well-behaved producer
rejected="$(ch 'SELECT count() FROM rejected_events')"
[ "$rejected" = "0" ] && pass "zero rejected events" || fail "$rejected rejected events -- check reject_reason"

# 8. not falling behind, and fast: end to end, event created -> row stored
lag="$(metric 'flink_taskmanager_job_task_operator_KafkaSourceReader_KafkaConsumer_records_lag_max')"
if [ -n "$lag" ] && [ "${lag%.*}" -lt 5000 ]; then pass "Kafka lag ${lag%.*}"; else fail "Kafka lag ${lag:-?} -- falling behind"; fi
p95="$(ch 'SELECT round(quantile(0.95)(toUnixTimestamp64Milli(ingested_at) - toUnixTimestamp64Milli(timestamp))) FROM security_events WHERE ingested_at > now64(3) - INTERVAL 60 SECOND')"
if [ -n "$p95" ] && [ "${p95%.*}" -lt 5000 ]; then
  pass "end-to-end p95 latency ${p95} ms (budget 5000)"
else
  fail "end-to-end p95 latency ${p95:-?} ms over the 5000 ms budget"
fi

# 9. Prometheus is actually scraping the pipeline
scraped="$(kubectl -n "$NS" exec deploy/prometheus -- wget -qO- \
  'http://localhost:9090/api/v1/query?query=up%7Bjob%3D%22watchtower-stream%22%7D' 2>/dev/null)"
case "$scraped" in
  *'"1"'*) pass "Prometheus scraping the Flink job" ;;
  *) fail "Prometheus not scraping the Flink job" ;;
esac

echo
if [ "$FAILED" = "0" ]; then echo "smoke test PASSED: $NS"; else echo "smoke test FAILED: $NS"; fi
exit "$FAILED"
