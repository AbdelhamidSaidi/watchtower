#!/usr/bin/env python3
"""Carry autoscaled replica counts through a redeploy.

usage: kubectl kustomize ... | keep-scaled-replicas.py NAMESPACE | kubectl apply -f -

A KafkaNodePool REQUIRES spec.replicas, so the rendered manifest always
carries one -- and `kubectl apply --force-conflicts` would reset the broker
pool to it, undoing whatever the HorizontalPodAutoscaler had decided (and
triggering a rebalance for nothing). For every object an HPA in the same
stream targets, the replica count is replaced by the LIVE one, when the
object already exists. First deploys are unaffected.
"""

import json
import subprocess
import sys

import yaml

namespace = sys.argv[1]
docs = [d for d in yaml.safe_load_all(sys.stdin) if d]

targets = {
    (d["spec"]["scaleTargetRef"]["kind"], d["spec"]["scaleTargetRef"]["name"])
    for d in docs
    if d["kind"] == "HorizontalPodAutoscaler"
}

for doc in docs:
    key = (doc["kind"], doc["metadata"]["name"])
    if key not in targets:
        continue
    live = subprocess.run(
        ["kubectl", "-n", namespace, "get", doc["kind"].lower(), key[1], "-o", "json"],
        capture_output=True, text=True,
    )
    if live.returncode != 0:
        continue  # not deployed yet: use the manifest's count
    replicas = json.loads(live.stdout)["spec"].get("replicas")
    if replicas is not None and replicas != doc["spec"].get("replicas"):
        print(f"keeping autoscaled {key[0]}/{key[1]} at {replicas} replicas", file=sys.stderr)
        doc["spec"]["replicas"] = replicas

yaml.safe_dump_all(docs, sys.stdout, sort_keys=False)
