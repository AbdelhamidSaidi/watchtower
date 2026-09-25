#!/usr/bin/env bash
# Watch the pipeline scale, one line every 15 s:
#
#   taskmgrs   Flink TaskManager pods Running/Pending (the autoscaler's doing)
#   parallel   parallelism of each job vertex: source | detection
#   brokers    broker pods Running, HPA CPU vs target, Cruise Control state
#   lag, p95   Kafka backlog, and Kafka -> decision p95 latency (ms)
set -uo pipefail
NS="${1:?usage: watch-scaling.sh NAMESPACE}"

tm_metric() {  # max over TaskManagers
  for pod in $(kubectl -n "$NS" get pods -l component=taskmanager --field-selector=status.phase=Running -o name 2>/dev/null); do
    kubectl -n "$NS" exec "$pod" -- sh -c "curl -s localhost:9249/metrics" 2>/dev/null
  done | grep -E "^$1" | awk '{print $NF}' | sort -g | tail -1
}

printf "%-8s  %-16s  %-10s  %-32s  %s\n" time taskmgrs parallel "brokers (cpu/target, rebalance)" "lag / p95 ms"
while true; do
  run=$(kubectl -n "$NS" get pods -l component=taskmanager --field-selector=status.phase=Running --no-headers 2>/dev/null | wc -l | tr -d ' ')
  pend=$(kubectl -n "$NS" get pods -l component=taskmanager --field-selector=status.phase=Pending --no-headers 2>/dev/null | wc -l | tr -d ' ')
  par=$(kubectl -n "$NS" get flinkdeployment stream -o jsonpath='{.status.jobStatus.jobId}' 2>/dev/null | xargs -I{} \
        kubectl get --raw "/api/v1/namespaces/$NS/services/stream-rest:8081/proxy/jobs/{}" 2>/dev/null \
        | python3 -c 'import sys,json;print("|".join(str(v["parallelism"]) for v in json.load(sys.stdin)["vertices"]))' 2>/dev/null)
  brokers=$(kubectl -n "$NS" get pods -l strimzi.io/pool-name=brokers --field-selector=status.phase=Running --no-headers 2>/dev/null | wc -l | tr -d ' ')
  hpa=$(kubectl -n "$NS" get hpa kafka-brokers -o jsonpath='{.status.currentMetrics[0].resource.current.averageUtilization}%/{.spec.metrics[0].resource.target.averageUtilization}%' 2>/dev/null)
  reb=$(kubectl -n "$NS" get kafka watchtower -o jsonpath='{.status.autoRebalance.state}' 2>/dev/null)
  lag=$(tm_metric flink_taskmanager_job_task_operator_KafkaSourceReader_KafkaConsumer_records_lag_max)
  p95=$(tm_metric flink_taskmanager_job_task_operator_watchtower_kafka_to_scored_p95_ms)
  printf "%-8s  %-16s  %-10s  %-32s  %s / %s\n" "$(date +%H:%M:%S)" "${run} run ${pend} pend" "${par:-?}" \
    "${brokers} (${hpa:-?} ${reb:-idle})" "${lag%.*}" "${p95%.*}"
  sleep 15
done
