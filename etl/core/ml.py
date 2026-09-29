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

from core.rules import BLOCK_THRESHOLD, SUSPICIOUS_THRESHOLD, action_for

# The model alone may raise an event to `alert`; to `block`, a rule must
# agree -- a block the model cannot explain in rule terms is one an analyst
# cannot defend. Set true once the model has earned it.
ML_CAN_BLOCK = os.getenv("WATCHTOWER_ML_CAN_BLOCK", "false").lower() == "true"
_BELOW_BLOCK = BLOCK_THRESHOLD - 1e-4

# The model's input, in order. Fields the event already carries after
# enrich + features; changing this list means retraining.
FEATURES = (
    "failed_logins_1m", "failed_logins_5m", "unique_users_5m", "requests_1m",
    "port_scan_count_5m", "unique_ports_5m", "commands_executed_5m", "login_frequency",
    "sensitive_commands_5m", "attack_signatures_5m", "http_errors_5m", "http_404_1m",
    "distinct_paths_5m", "bytes_sent_5m",
    "is_internal_ip", "is_night", "is_attack_signature", "is_scanner_agent",
    "is_sensitive_path", "is_sensitive_command", "is_privileged",
    "http_status", "target_port", "dest_port", "bytes_sent", "response_time_ms",
    "is_login_failure", "is_login_success", "is_command", "is_http",
)

_EVENT_FLAGS = {
    "is_login_failure": "LOGIN_FAILURE",
    "is_login_success": "LOGIN_SUCCESS",
    "is_command": "COMMAND_EXECUTION",
    "is_http": "HTTP_REQUEST",
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
        """Probability that the event is an attack, 0..1."""
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
    share = probability if (ML_CAN_BLOCK or event["rule_hits"]) else min(probability, _BELOW_BLOCK)
    final = max(event["rule_score"], share)
    event["ml_score"] = probability
    event["ml_model"] = model.version
    changed = share > event["rule_score"] and share >= SUSPICIOUS_THRESHOLD
    event["ml_reason"] = model.explain(event) if changed else ""
    event["final_anomaly_score"] = final
    event["is_suspicious"] = 1 if final >= SUSPICIOUS_THRESHOLD else 0
    event["recommended_action"] = action_for(final)
    return event
