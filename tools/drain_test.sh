#!/usr/bin/env bash
# Processing capacity of the Flink job with N TaskManagers (1 slot each):
# build a Kafka backlog with the job stopped, start it, and measure how fast
# it decides events (the scored topic's end offsets). Kafka + registry +
# Flink only -- ClickHouse and live producers stay off, so the number is the
# job's, not the machine's leftovers.
#
#   tools/drain_test.sh 1 2        # 1 TaskManager, then 2
set -euo pipefail
cd "$(dirname "$0")/.."
BACKLOG_RATE=${BACKLOG_RATE:-6000}   # events/s written while the job is stopped
BACKLOG_SECONDS=${BACKLOG_SECONDS:-60}

offsets() { docker exec watchtower-kafka /opt/kafka/bin/kafka-get-offsets.sh --bootstrap-server localhost:9092 --topic "$1" \
  | awk -F: '{s+=$3} END {print s}'; }
# Events not yet read by the job: its consumer group's lag (committed on
# each checkpoint, so it moves in 10 s steps). NOT input minus output
# offsets -- the input topic holds history from before the job existed.
lag() { docker exec watchtower-kafka /opt/kafka/bin/kafka-consumer-groups.sh --bootstrap-server localhost:9092 \
  --describe --group watchtower-stream 2>/dev/null | awk '$2=="security-logs" && $6 ~ /^[0-9]+$/ {s+=$6} END {print s+0}'; }
flink_up() {
  FLINK_PARALLELISM=$1 docker compose up -d --no-deps --scale flink-taskmanager=$1 flink-jobmanager flink-taskmanager >/dev/null 2>&1
  until curl -s localhost:8082/jobs/overview 2>/dev/null | grep -q '"state":"RUNNING"'; do sleep 2; done
}
flink_down() { docker compose stop flink-jobmanager flink-taskmanager >/dev/null 2>&1; }

docker compose up -d kafka kafka-init schema-registry schema-init >/dev/null 2>&1
until docker compose ps schema-init --format '{{.State}}' -a | grep -q exited; do sleep 2; done

for n in "$@"; do
  echo "=== $n TaskManager(s) ==="
  flink_down
  docker run --rm -v watchtower_flink-checkpoints:/c alpine sh -c 'rm -rf /c/*'   # fresh state each time
  flink_up "$n"                               # catch up whatever is already in Kafka
  until [ "$(lag)" -lt 5000 ]; do sleep 5; done
  flink_down
  producers=$(( (BACKLOG_RATE + 1999) / 2000 ))
  for i in $(seq 1 $producers); do
    docker compose --profile sim run -d --rm --name backlog-$i -e LOGS_PER_SECOND=$((BACKLOG_RATE / producers)) producer >/dev/null
  done
  sleep "$BACKLOG_SECONDS"
  for i in $(seq 1 $producers); do docker stop backlog-$i >/dev/null; done
  echo "backlog: $(lag) events"
  flink_up "$n"
  sleep 20                                    # warm-up (JIT, state creation)
  o0=$(offsets security-events-scored); t0=$(date +%s)
  for i in 1 2 3; do
    sleep 20
    o=$(offsets security-events-scored); t=$(date +%s)
    left=$(lag)
    echo "  +$(( t - t0 ))s: $(( (o - o0) / (t - t0) )) events/s decided (backlog left $left)"
    [ "$left" -lt 20000 ] && break
  done
  flink_down
done
docker compose --profile sim down >/dev/null 2>&1
echo "stack stopped"
