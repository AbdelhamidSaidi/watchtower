"""The ML detector: a LightGBM model, compiled to plain Python.

Trained offline (orchestration/ops/training.py) on the pipeline's own
features; scored here, per event, inside the Flink job.

WHY COMPILED, NOT lightgbm.predict. The job scores one event at a time.
LightGBM's predict() is built for batches: for a single row its per-call
overhead dominates. ONNX Runtime's converter drags in protobuf and
cloudpickle versions that break PyFlink's own dependencies. So the trained
model is dumped (JSON) and turned into nested `if` statements once, when
the job loads it: no library at scoring time, and the cost is only the
comparisons along each tree's path (tools/bench_model.py measures it).

The model sees exactly FEATURES, in this order, from the enriched and
windowed event -- the same numbers the rules see.
"""

import json
import math
import os

from core.rules import QUARANTINE_THRESHOLD, SUSPICIOUS_THRESHOLD, action_for

# The model alone may raise an event to `alert`; to `quarantine`, a rule must
# agree -- pulling a runner out of the farm on a score nobody can explain in
# rule terms is one an engineer cannot defend. Set true once the model has
# earned it.
ML_CAN_QUARANTINE = os.getenv("WATCHTOWER_ML_CAN_QUARANTINE", "false").lower() == "true"
_BELOW_QUARANTINE = QUARANTINE_THRESHOLD - 1e-4

# The model's input, in order. Fields the event already carries after
# enrich + features; changing this list means retraining.
FEATURES = (
    "failed_builds_1m", "failed_builds_5m", "unique_projects_5m", "events_1m",
    "oom_kills_5m", "distinct_exit_codes_5m", "compile_steps_5m", "build_frequency",
    "rogue_commands_5m", "failure_signatures_5m", "http_errors_5m", "dependency_404_1m",
    "distinct_artifacts_5m", "published_bytes_5m", "slow_steps_5m", "cache_misses_5m",
    "is_internal_ip", "is_night", "is_failure_signature", "is_untrusted_fetch",
    "is_rogue_command", "is_privileged", "is_slow_step", "is_cache_miss",
    "http_status", "exit_code", "dest_port", "bytes_sent", "response_time_ms",
    "duration_ms", "peak_memory_mb",
    "is_build_failure", "is_build_success", "is_compile_step", "is_dependency_fetch",
)

_EVENT_FLAGS = {
    "is_build_failure": "BUILD_FAILURE",
    "is_build_success": "BUILD_SUCCESS",
    "is_compile_step": "COMPILE_STEP",
    "is_dependency_fetch": "DEPENDENCY_FETCH",
}


def vector(event):
    """The event as the model's input: floats, in FEATURES order."""
    event_type = event.get("event_type")
    out = []
    for name in FEATURES:
        flag = _EVENT_FLAGS.get(name)
        if flag is not None:
            out.append(1.0 if event_type == flag else 0.0)
        else:
            out.append(float(event.get(name) or 0))
    return out


def _node(node, depth, lines):
    pad = "    " * depth
    if "leaf_value" in node:
        lines.append(f"{pad}s += {node['leaf_value']!r}")
        return
    if node.get("decision_type") != "<=":
        raise ValueError(f"unsupported split {node.get('decision_type')!r}: numeric features only")
    lines.append(f"{pad}if x[{node['split_feature']}] <= {node['threshold']!r}:")
    _node(node["left_child"], depth + 1, lines)
    lines.append(f"{pad}else:")
    _node(node["right_child"], depth + 1, lines)


def compile_model(dump):
    """A LightGBM model dump (Booster.dump_model()) -> Python source of
    `raw(x)`, the model's raw score for one input vector."""
    lines = ["def raw(x):", "    s = 0.0"]
    for tree in dump["tree_info"]:
        _node(tree["tree_structure"], 1, lines)
    lines.append("    return s")
    return "\n".join(lines)


class Model:
    """A compiled model and what the job needs to know about it."""

    def __init__(self, dump, version):
        if dump.get("objective", "").split(" ")[0] != "binary":
            raise ValueError(f"expected a binary model, got {dump.get('objective')!r}")
        names = tuple(dump.get("feature_names") or ())
        if names and names != FEATURES:
            raise ValueError("model was trained on different features -- retrain it")
        namespace = {}
        exec(compile(compile_model(dump), f"<model {version}>", "exec"), namespace)
        self._raw = namespace["raw"]
        self._trees = [tree["tree_structure"] for tree in dump["tree_info"]]
        self.version = version
        self.trees = len(self._trees)

    @classmethod
    def from_json(cls, text, version):
        return cls(json.loads(text), version)

    def score(self, event):
        """Probability that the event is a build-farm incident, 0..1."""
        raw = self._raw(vector(event))
        return 1.0 / (1.0 + math.exp(-raw)) if raw > -700 else 0.0

    def explain(self, event, top=3):
        """The features that pushed this event's score up the most, as
        "ml: a, b, c". Walks the trees again with each split's change in
        value credited to its feature -- a few times the cost of score(),
        so only for events whose decision the model changed."""
        x = vector(event)
        credit = [0.0] * len(FEATURES)
        for node in self._trees:
            while "leaf_value" not in node:
                child = node["left_child"] if x[node["split_feature"]] <= node["threshold"] else node["right_child"]
                after = child.get("leaf_value", child.get("internal_value", 0.0))
                credit[node["split_feature"]] += after - node.get("internal_value", 0.0)
                node = child
        ranked = sorted((c, i) for i, c in enumerate(credit) if c > 0)[::-1][:top]
        return "ml: " + ", ".join(FEATURES[i] for _, i in ranked)


def apply(event, model):
    """Add the model's columns and settle the decision from rules and model
    together. In place; the event already carries core.rules' scoring."""
    if model is None:
        event["ml_score"], event["ml_model"], event["ml_reason"] = 0.0, "", ""
        return event
    probability = model.score(event)
    share = probability if (ML_CAN_QUARANTINE or event["rule_hits"]) else min(probability, _BELOW_QUARANTINE)
    final = max(event["rule_score"], share)
    event["ml_score"] = probability
    event["ml_model"] = model.version
    # Explained only when the model changed the DECISION -- ok to alert,
    # alert to quarantine -- not merely the score: a rule's quarantine that
    # the model scores higher is still the rule's quarantine.
    changed = action_for(final) != action_for(event["rule_score"])
    event["ml_reason"] = model.explain(event) if changed else ""
    event["final_anomaly_score"] = final
    event["is_suspicious"] = 1 if final >= SUSPICIOUS_THRESHOLD else 0
    event["recommended_action"] = action_for(final)
    return event
