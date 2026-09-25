#!/usr/bin/env bash
# Install the Strimzi operator once per cluster, watching every namespace.
#
# One operator serves both watchtower-staging and watchtower-prod. The
# release manifest is namespace-scoped by default (it watches only the
# namespace it is installed in); watching all namespaces needs its
# STRIMZI_NAMESPACE set to "*" plus three ClusterRoleBindings, per the
# Strimzi docs. The version is pinned -- Strimzi dictates which Kafka
# versions run (1.2.0 -> Kafka 4.2-4.3).
set -euo pipefail

VERSION="${STRIMZI_VERSION:-1.2.0}"
NS=strimzi
URL="https://github.com/strimzi/strimzi-kafka-operator/releases/download/${VERSION}/strimzi-cluster-operator-${VERSION}.yaml"

kubectl create namespace "$NS" --dry-run=client -o yaml | kubectl apply -f -

echo "downloading Strimzi ${VERSION}..."
# The release manifest leaves the operator's Deployment, ServiceAccount,
# ConfigMap and RoleBindings WITHOUT a namespace -- it expects `kubectl -n`.
# Only the binding subjects say `myproject`. So both are set explicitly
# here: without it everything namespaced lands in `default`, and the
# bindings point at a ServiceAccount that does not exist.
curl -sSLf "$URL" \
  | sed "s/namespace: myproject/namespace: ${NS}/" \
  | NS="$NS" python3 -c '
import os, sys, yaml
CLUSTER_SCOPED = {"CustomResourceDefinition", "ClusterRole", "ClusterRoleBinding"}
docs = [d for d in yaml.safe_load_all(sys.stdin) if d]
if not any(d["kind"] == "Deployment" for d in docs):
    sys.exit("manifest has no operator Deployment -- truncated download?")
for doc in docs:
    if doc["kind"] not in CLUSTER_SCOPED:
        doc["metadata"]["namespace"] = os.environ["NS"]
    if doc["kind"] == "Deployment":
        for c in doc["spec"]["template"]["spec"]["containers"]:
            for env in c.get("env", []):
                if env["name"] == "STRIMZI_NAMESPACE":
                    env.pop("valueFrom", None)
                    env["value"] = "*"
yaml.safe_dump_all(docs, sys.stdout)
' | kubectl apply --server-side -f - >/dev/null

for binding in namespaced watched; do
  kubectl create clusterrolebinding "strimzi-cluster-operator-${binding}" \
    --clusterrole="strimzi-cluster-operator-${binding}" \
    --serviceaccount="${NS}:strimzi-cluster-operator" \
    --dry-run=client -o yaml | kubectl apply -f -
done
kubectl create clusterrolebinding strimzi-cluster-operator-entity-operator-delegation \
  --clusterrole=strimzi-entity-operator \
  --serviceaccount="${NS}:strimzi-cluster-operator" \
  --dry-run=client -o yaml | kubectl apply -f -

kubectl -n "$NS" rollout status deployment/strimzi-cluster-operator --timeout=300s
echo "Strimzi ${VERSION} ready, watching all namespaces"
