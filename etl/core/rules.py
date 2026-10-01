"""Deterministic rules for ONE event -- the streaming path's detector.

Each rule is (name, score, fired). An event's score is its strongest
rule's; `rule_hits` lists every rule that fired, strongest first. Scores
are how sure a rule is: signatures (wrong in themselves) score high, a lone
slow compile step only alerts. NOTE_TO_BUILD_ENGINEER.md explains each rule
and how to tune it.

The actions are the farm's: `ok` lets the runner carry on, `alert` asks an
engineer to look, `quarantine` is "stop scheduling builds on this runner".
"""

import os
import re

QUARANTINE_THRESHOLD = float(os.getenv("WATCHTOWER_QUARANTINE_THRESHOLD", "0.85"))
SUSPICIOUS_THRESHOLD = float(os.getenv("WATCHTOWER_THRESHOLD", "0.65"))

REVERSE_SHELL_REGEX = r"(?i)(?:\bnc\s+-e\b|/dev/tcp/|bash\s+-i\s*>&)"
_REVERSE_SHELL = re.compile(REVERSE_SHELL_REGEX)


def _rules(e):
    """(name, score, fired) for every rule, in table order."""
    n = lambda k: e.get(k) or 0  # noqa: E731
    event_type = e.get("event_type") or ""
    signature = e.get("failure_signature") or ""
    return [
        # --- signatures: wrong in themselves ------------------------------
        ("reverse_shell", 1.00, bool(_REVERSE_SHELL.search(str(e.get("command") or "")))),
        ("rogue_command_as_root", 0.97, n("is_rogue_command") == 1 and n("is_privileged") == 1),
        ("cache_poisoned", 0.95, signature == "checksum_mismatch"),
        ("compiler_crash", 0.95, signature == "ice"),
        ("disk_full", 0.90, signature == "disk_full"),
        ("rogue_command", 0.85, n("is_rogue_command") == 1),
        ("oom_kill", 0.70, signature == "oom"),
        ("untrusted_fetch", 0.70, n("is_untrusted_fetch") == 1),
        ("slow_step", 0.70, n("is_slow_step") == 1),
        # --- behaviour: the runner's recent history ----------------------
        ("pass_after_failure_storm", 0.70, event_type == "BUILD_SUCCESS" and n("failed_builds_5m") >= 20),
        ("failure_storm", 0.90, n("failed_builds_1m") >= 20),
        ("broken_toolchain", 0.90, n("unique_projects_5m") >= 8 and n("failed_builds_5m") >= 20),
        ("oom_kill_storm", 0.90, n("oom_kills_5m") >= 5),
        ("repeated_slow_steps", 0.90, n("slow_steps_5m") >= 5),
        ("dependency_not_found_storm", 0.85, n("dependency_404_1m") >= 30),
        ("artifact_bloat", 0.85, n("published_bytes_5m") >= 250_000_000),
        ("repeated_failure_signatures", 0.90, n("failure_signatures_5m") >= 5),
    ]


# Strongest first, table order among equals (a stable sort on -score).
_ORDER = sorted(range(len(_rules({}))), key=lambda i: -_rules({})[i][1])


def action_for(score):
    if score >= QUARANTINE_THRESHOLD:
        return "quarantine"
    if score >= SUSPICIOUS_THRESHOLD:
        return "alert"
    return "ok"


def score_event(e):
    """Add the detection columns to one event (in place) and return it.

    Rules only; core/ml.apply() then adds the model's score and settles
    the final decision.
    """
    rules = _rules(e)
    hits = [rules[i][0] for i in _ORDER if rules[i][2]]
    score = max((rules[i][1] for i in _ORDER if rules[i][2]), default=0.0)
    e["rule_score"] = score
    e["rule_hits"] = ",".join(hits)
    e["final_anomaly_score"] = score
    e["is_suspicious"] = 1 if score >= SUSPICIOUS_THRESHOLD else 0
    e["recommended_action"] = action_for(score)
    return e
