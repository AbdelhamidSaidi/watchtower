#!/usr/bin/env bash
# Start the streaming job (Flink application mode), resuming from the
# newest completed checkpoint if there is one.
#
# Without Flink HA, a restarted JobManager knows nothing about the previous
# run and would start from the committed Kafka offsets with EMPTY state --
# every source's 5-minute window and dedup memory gone. Checkpoints are
# retained on cancellation (see FLINK_PROPERTIES), so this finds the newest
# complete one (it has a _metadata file) and resumes from it.
set -euo pipefail

dir="${CHECKPOINT_DIR:-/var/lib/watchtower/flink-checkpoints}"
resume=()
latest=$(ls -1dt "$dir"/*/chk-*/_metadata 2>/dev/null | head -1 || true)
if [ -n "$latest" ]; then
  echo "resuming from $(dirname "$latest")"
  resume=(--fromSavepoint "$(dirname "$latest")")
else
  echo "no checkpoint in $dir: fresh start"
fi

exec /docker-entrypoint.sh standalone-job "${resume[@]}" \
  --job-classname org.apache.flink.client.python.PythonDriver \
  -py /opt/watchtower/etl/stream/job.py
