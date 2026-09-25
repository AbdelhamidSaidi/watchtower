#!/usr/bin/env bash
# Install the Flink Kubernetes Operator once per cluster, watching every
# namespace. It runs the streaming job (base/stream.yaml) and its
# autoscaler.
#
# No Helm on the host: the release chart is downloaded, checked against
# its published SHA-512, and rendered with a throwaway Helm container.
# The admission webhook is off -- it needs cert-manager, a whole extra
# controller, only to validate FlinkDeployment specs the operator
# validates again when it reconciles them.
set -euo pipefail

VERSION="${FLINK_OPERATOR_VERSION:-1.16.1}"
NS=flink-operator
BASE="https://downloads.apache.org/flink/flink-kubernetes-operator-${VERSION}"
CHART="flink-kubernetes-operator-${VERSION}-helm.tgz"
HELM_IMAGE="alpine/helm:3.19.0"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

echo "downloading Flink Kubernetes Operator ${VERSION}..."
curl -sSLf -o "$WORK/$CHART" "$BASE/$CHART"
expected="$(curl -sSLf "$BASE/$CHART.sha512" | awk '{print $1}')"
actual="$(shasum -a 512 "$WORK/$CHART" | awk '{print $1}')"
[ "$expected" = "$actual" ] || { echo "checksum mismatch for $CHART" >&2; exit 1; }

kubectl create namespace "$NS" --dry-run=client -o yaml | kubectl apply -f -

# CRDs first (helm template leaves crds/ out), then the operator.
tar -xzf "$WORK/$CHART" -C "$WORK"
kubectl apply --server-side --force-conflicts -f "$WORK/flink-kubernetes-operator/crds/"

docker run --rm -v "$WORK:/work" "$HELM_IMAGE" template flink-kubernetes-operator \
    "/work/$CHART" --namespace "$NS" \
    --set webhook.create=false \
    --set operatorPod.resources.requests.memory=256Mi \
    --set operatorPod.resources.limits.memory=512Mi \
  | kubectl apply -n "$NS" -f -

kubectl -n "$NS" rollout status deploy/flink-kubernetes-operator --timeout=300s
