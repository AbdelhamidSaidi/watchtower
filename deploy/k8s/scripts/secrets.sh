#!/usr/bin/env bash
# Secrets: generated locally, never committed, never typed into a manifest.
#
#   secrets.sh               create any missing files under ./secrets
#   secrets.sh <namespace>   ...and load them into that namespace as the
#                            `watchtower-secrets` Secret
#
# Existing files are NEVER overwritten -- rotating a password is a
# deliberate act, not a side effect of re-running a deploy.
#
# groq_api_key starts EMPTY, which disables detection (the pipeline still
# runs and says so). Put your key in it yourself:
#     printf '%s' 'gsk_...' > secrets/groq_api_key
set -euo pipefail

DIR="$(cd "$(dirname "$0")/../../.." && pwd)/secrets"
mkdir -p "$DIR"
chmod 700 "$DIR"

generate() {
  local file="$DIR/$1" bytes="${2:-24}"
  if [ ! -s "$file" ] && [ "$1" != groq_api_key ]; then
    python3 -c "import secrets; print(secrets.token_urlsafe($bytes), end='')" > "$file"
    echo "generated secrets/$1"
  elif [ ! -e "$file" ]; then
    : > "$file"
    echo "created empty secrets/$1 (detection disabled until you fill it)"
  fi
  chmod 600 "$file"
}

generate clickhouse_password
generate grafana_admin_password
generate groq_api_key
generate airflow_db_password
generate airflow_admin_password
# Signs the tokens Airflow's components hand each other (HS512): 64 bytes,
# the hash's own size.
generate airflow_jwt_secret 64

if [ "${1:-}" != "" ]; then
  kubectl create namespace "$1" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
  kubectl -n "$1" create secret generic watchtower-secrets \
    --from-file=clickhouse_password="$DIR/clickhouse_password" \
    --from-file=grafana_admin_password="$DIR/grafana_admin_password" \
    --from-file=groq_api_key="$DIR/groq_api_key" \
    --from-file=airflow_db_password="$DIR/airflow_db_password" \
    --from-file=airflow_admin_password="$DIR/airflow_admin_password" \
    --from-file=airflow_jwt_secret="$DIR/airflow_jwt_secret" \
    --dry-run=client -o yaml | kubectl apply -f - >/dev/null
  echo "secret watchtower-secrets applied to $1"
fi
