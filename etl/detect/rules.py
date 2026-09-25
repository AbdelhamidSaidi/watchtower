"""
Deterministic rules: activity that must be stopped whatever a model thinks.

Two kinds of evidence, combined per event:

  SIGNATURES   the event is bad in itself -- a SQL injection payload, a
               scanner's User-Agent, `nc -e` run as root. One is enough.
  BEHAVIOUR    the source's recent history is bad -- 40 failed logins a
               minute, 30 404s a minute, half a gigabyte out in 5 minutes.

Each rule carries a score: how certain a hit is that the activity must be
stopped. The event's rule_score is its highest-scoring hit, and every hit
is recorded in rule_hits so an analyst sees WHY, not just that.

    rule_score >= BLOCK_THRESHOLD      -> recommended_action = block
    rule_score >= SUSPICIOUS_THRESHOLD -> recommended_action = alert
    otherwise                          -> allow

These need no API and no key: with Groq unavailable, signature and
volumetric attacks are still stopped. The LLM is spent on the grey zone
the rules cannot settle. Thresholds were set against the simulation --
re-measure against real traffic (NOTE_TO_SOC_ANALYST.md).
"""

import os

import numpy as np
import pandas as pd

BLOCK_THRESHOLD = float(os.getenv("WATCHTOWER_BLOCK_THRESHOLD", "0.85"))
SUSPICIOUS_THRESHOLD = float(os.getenv("WATCHTOWER_THRESHOLD", "0.65"))

REVERSE_SHELL_REGEX = r"(?i)(?:\bnc\s+-e\b|/dev/tcp/|bash\s+-i\s*>&)"


def _col(pdf, name, default=0):
    if name in pdf.columns:
        return pdf[name].fillna(default)
    return pd.Series(default, index=pdf.index)


def _rules(pdf):
    """(name, score, boolean Series) for every rule, evaluated vectorised."""
    event_type = _col(pdf, "event_type", "")
    command = _col(pdf, "command", "").astype(str)
    signature = _col(pdf, "request_signature", "")
    status = _col(pdf, "http_status")
    internal = _col(pdf, "is_internal_ip") == 1

    return [
        # --- signatures: bad in themselves --------------------------------
        ("reverse_shell", 1.00, command.str.contains(REVERSE_SHELL_REGEX, regex=True)),
        ("sensitive_command_as_root", 0.97,
         (_col(pdf, "is_sensitive_command") == 1) & (_col(pdf, "is_privileged") == 1)),
        ("sqli", 0.95, signature == "sqli"),
        ("path_traversal", 0.95, signature == "path_traversal"),
        ("xss", 0.90, signature == "xss"),
        ("sensitive_command", 0.85, _col(pdf, "is_sensitive_command") == 1),
        ("scanner_agent", 0.85, _col(pdf, "is_scanner_agent") == 1),
        # a single probe of /.env is suspicious, not proof -- alert, not block
        ("sensitive_path_probe", 0.70,
         (_col(pdf, "is_sensitive_path") == 1) & status.isin([401, 403, 404]) & ~internal),

        # --- behaviour: the source's recent history ----------------------
        # The single most important sequence: a login that SUCCEEDS right
        # after a wall of failures is a brute force that worked.
        ("login_after_brute_force", 1.00,
         (event_type == "LOGIN_SUCCESS") & (_col(pdf, "failed_logins_5m") >= 20)),
        ("brute_force", 0.90, _col(pdf, "failed_logins_1m") >= 20),
        ("password_spray", 0.90,
         (_col(pdf, "unique_users_5m") >= 8) & (_col(pdf, "failed_logins_5m") >= 20)),
        ("port_scan", 0.90, _col(pdf, "unique_ports_5m") >= 10),
        # internal hosts never port-scan in normal operation
        ("lateral_movement", 0.90, internal & (_col(pdf, "port_scan_count_5m") >= 5)),
        ("web_scan", 0.85, _col(pdf, "http_404_1m") >= 30),
        ("data_exfiltration", 0.85, _col(pdf, "bytes_sent_5m") >= 250_000_000),
        ("repeated_attack_signatures", 0.90, _col(pdf, "attack_signatures_5m") >= 5),
    ]


def action_for(score):
    if score >= BLOCK_THRESHOLD:
        return "block"
    if score >= SUSPICIOUS_THRESHOLD:
        return "alert"
    return "allow"


def apply_rules(pdf):
    """Return (rule_score, rule_hits) Series aligned with pdf.

    rule_hits lists every rule that fired, strongest first, comma-separated.
    """
    if pdf.empty:
        return pd.Series([], dtype="float64"), pd.Series([], dtype="object")

    rules = _rules(pdf)
    scores = np.zeros(len(pdf))
    hits = [[] for _ in range(len(pdf))]

    for name, score, fired in sorted(rules, key=lambda r: -r[1]):
        mask = fired.fillna(False).to_numpy(dtype=bool)
        scores = np.where(mask, np.maximum(scores, score), scores)
        for i in np.flatnonzero(mask):
            hits[i].append(name)

    return (
        pd.Series(scores, index=pdf.index),
        pd.Series([",".join(h) for h in hits], index=pdf.index),
    )
