#!/usr/bin/env bash
# Start Airflow.
#
#   start.sh              (docker compose) migrate the metadata database,
#                         then run the API server, scheduler and DAG
#                         processor in this one container -- the lightest
#                         way to have all three on a laptop
#   start.sh <command>    (Kubernetes) `airflow <command>`, one component
#                         per pod, e.g. `start.sh scheduler`
#
# dumb-init (the entrypoint) forwards SIGTERM to every process here, so
# `docker compose stop` shuts all three down cleanly.
set -euo pipefail

# One user, `admin`. The simple auth manager reads passwords from a JSON
# file; it is written from the mounted secret so the password never sits in
# an image, a manifest or an environment variable.
export AIRFLOW__CORE__SIMPLE_AUTH_MANAGER_USERS="${AIRFLOW__CORE__SIMPLE_AUTH_MANAGER_USERS:-admin:admin}"
if [ -r /run/secrets/airflow_admin_password ]; then
  python - <<'EOF'
import json, os
password = open("/run/secrets/airflow_admin_password").read().strip()
path = os.environ["AIRFLOW__CORE__SIMPLE_AUTH_MANAGER_PASSWORDS_FILE"]
with open(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w") as handle:
    json.dump({"admin": password}, handle)
EOF
fi

if [ $# -gt 0 ]; then
  exec airflow "$@"
fi

airflow db migrate
airflow api-server &
airflow scheduler &
airflow dag-processor &
# The first component to exit takes the container down with it; the
# restart policy brings the whole set back.
wait -n
exit 1
