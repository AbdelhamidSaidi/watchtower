"""Deterministic rules for ONE event -- the streaming path's detector.

Each rule is (name, score, fired). An event's score is its strongest
rule's; `rule_hits` lists every rule that fired, strongest first. Scores
are how sure a rule is: signatures (bad in themselves) score high, a lone
probe of a sensitive path only alerts. NOTE_TO_SOC_ANALYST.md explains
each rule and how to tune it.
"""

import os
import re

BLOCK_THRESHOLD = float(os.getenv("WATCHTOWER_BLOCK_THRESHOLD", "0.85"))
SUSPICIOUS_THRESHOLD = float(os.getenv("WATCHTOWER_THRESHOLD", "0.65"))

REVERSE_SHELL_REGEX = r"(?i)(?:\bnc\s+-e\b|/dev/tcp/|bash\s+-i\s*>&)"
_REVERSE_SHELL = re.compile(REVERSE_SHELL_REGEX)


def _rules(e):
    """(name, score, fired) for every rule, in table order."""
    n = lambda k: e.get(k) or 0  # noqa: E731
    event_type = e.get("event_type") or ""
    signature = e.get("request_signature") or ""
    internal = n("is_internal_ip") == 1
    return [
        # --- signatures: bad in themselves --------------------------------
        ("reverse_shell", 1.00, bool(_REVERSE_SHELL.search(str(e.get("command") or "")))),
        ("sensitive_command_as_root", 0.97, n("is_sensitive_command") == 1 and n("is_privileged") == 1),
        ("sqli", 0.95, signature == "sqli"),
        ("path_traversal", 0.95, signature == "path_traversal"),
        ("xss", 0.90, signature == "xss"),
        ("sensitive_command", 0.85, n("is_sensitive_command") == 1),
        ("scanner_agent", 0.85, n("is_scanner_agent") == 1),
        ("sensitive_path_probe", 0.70,
         n("is_sensitive_path") == 1 and n("http_status") in (401, 403, 404) and not internal),
        # --- behaviour: the source's recent history ----------------------
        ("login_after_brute_force", 1.00, event_type == "LOGIN_SUCCESS" and n("failed_logins_5m") >= 20),
        ("brute_force", 0.90, n("failed_logins_1m") >= 20),
        ("password_spray", 0.90, n("unique_users_5m") >= 8 and n("failed_logins_5m") >= 20),
        ("port_scan", 0.90, n("unique_ports_5m") >= 10),
        ("lateral_movement", 0.90, internal and n("port_scan_count_5m") >= 5),
        ("web_scan", 0.85, n("http_404_1m") >= 30),
        ("data_exfiltration", 0.85, n("bytes_sent_5m") >= 250_000_000),
        ("repeated_attack_signatures", 0.90, n("attack_signatures_5m") >= 5),
    ]


# Strongest first, table order among equals (a stable sort on -score).
_ORDER = sorted(range(16), key=lambda i: -_rules({})[i][1])


def action_for(score):
    if score >= BLOCK_THRESHOLD:
        return "block"
    if score >= SUSPICIOUS_THRESHOLD:
        return "alert"
    return "allow"


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
