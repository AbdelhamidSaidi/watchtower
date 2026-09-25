#!/usr/bin/env bash
# Spread a topic's partitions across ALL current brokers.
#
# Adding brokers does not move existing partitions: new brokers join empty
# and take no load until partitions are reassigned onto them. This computes
# a balanced assignment over every live broker and applies it.
#
# (Strimzi can automate this with Cruise Control's auto-rebalance, at the
# cost of another ~500 MB JVM -- too much for this machine. This is the
# manual equivalent.)
#
#   rebalance-topic.sh [namespace] [topic]     one topic
#   rebalance-topic.sh [namespace] --all       every topic, INCLUDING Kafka's
#                                              internal ones
#
# --all matters: __consumer_offsets (50 partitions) and the registry's
# _schemas were created while the cluster had one broker, and they stay
# there. At replication factor 1 that broker is then a single point of
# failure for them, however many brokers are added.
set -euo pipefail

NS="${1:-watchtower-staging}"
TOPIC="${2:-security-logs}"
BOOTSTRAP=watchtower-kafka-bootstrap:9092

POD="$(kubectl -n "$NS" get pod -l strimzi.io/pool-name=brokers -o jsonpath='{.items[0].metadata.name}')"
kexec() { kubectl -n "$NS" exec "$POD" -c kafka -- bash -c "$1"; }

BROKERS="$(kexec "/opt/kafka/bin/kafka-broker-api-versions.sh --bootstrap-server $BOOTSTRAP 2>/dev/null \
  | grep -oE '\(id: [0-9]+' | grep -oE '[0-9]+' | sort -n | paste -sd, -")"
# BROKER_LIST overrides the live set. Scale-down uses it: partitions must
# first move onto the brokers that will REMAIN, or removing a broker would
# take the only copy of its partitions with it.
BROKERS="${BROKER_LIST:-$BROKERS}"
echo "target brokers: $BROKERS"

leaders() {
  local what="--topic $TOPIC"; [ "$TOPIC" = "--all" ] && what=""
  kexec "/opt/kafka/bin/kafka-topics.sh --bootstrap-server $BOOTSTRAP --describe $what" \
    | grep -oE 'Leader: [0-9]+' | sort | uniq -c | awk '{print "  broker "$3": leads "$1" partition(s)"}'
}
echo "--- before ---"; leaders

if [ "$TOPIC" = "--all" ]; then
  TOPICS_JSON="$(kexec "/opt/kafka/bin/kafka-topics.sh --bootstrap-server $BOOTSTRAP --list" \
    | python3 -c 'import sys,json;print(json.dumps({"topics":[{"topic":t.strip()} for t in sys.stdin if t.strip()],"version":1}))')"
  TOPIC_LABEL="all topics"
else
  TOPICS_JSON="{\"topics\":[{\"topic\":\"$TOPIC\"}],\"version\":1}"
  TOPIC_LABEL="$TOPIC"
fi
echo "rebalancing: $TOPIC_LABEL"

kexec "echo '$TOPICS_JSON' > /tmp/topics.json && \
  /opt/kafka/bin/kafka-reassign-partitions.sh --bootstrap-server $BOOTSTRAP \
    --topics-to-move-json-file /tmp/topics.json --broker-list $BROKERS --generate \
  | sed -n '/Proposed partition reassignment configuration/{n;p;}' > /tmp/plan.json && \
  /opt/kafka/bin/kafka-reassign-partitions.sh --bootstrap-server $BOOTSTRAP \
    --reassignment-json-file /tmp/plan.json --execute >/dev/null"

for attempt in $(seq 1 60); do
  if kexec "/opt/kafka/bin/kafka-reassign-partitions.sh --bootstrap-server $BOOTSTRAP \
      --reassignment-json-file /tmp/plan.json --verify" | grep -q "is still in progress"; then
    sleep 5
  else
    break
  fi
done

echo "--- after ---"; leaders
