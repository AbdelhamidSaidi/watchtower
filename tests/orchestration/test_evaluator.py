"""tools/evaluate_detection.py: the report, from ground truth and decisions.

summarize() takes what the tool read from Kafka and ClickHouse, so these
tests hand it both directly.
"""

import pytest

pytest.importorskip("kafka")

from tools.evaluate_detection import CONTAINMENT_MS, attacks, summarize  # noqa: E402

SINCE = 1_000_000
WORKSTATION = "192.168.1.62"
BYSTANDER = "192.168.3.9"
HOSTILE = "45.134.26.7"


class Traffic:
    """Builds truth {event_id: (scenario, partition, offset)} and decided
    {event_id: (action, rule_hits, source_ip, ts, copies)} side by side."""

    def __init__(self):
        self.truth, self.decided, self.refused = {}, {}, {}

    def add(self, scenario, source_ip, ts, action="allow", hits="", copies=1, decided=True):
        event_id = f"e{len(self.truth)}"
        self.truth[event_id] = (scenario, 0, len(self.truth))
        if decided:
            self.decided[event_id] = (action, hits, source_ip, ts, copies)
        return event_id

    def report(self):
        return summarize(self.truth, 0, self.decided, self.refused, SINCE, 15)


def test_coverage_splits_missing_from_rejected():
    t = Traffic()
    t.add("normal", BYSTANDER, SINCE + 10_000)
    t.add("normal", BYSTANDER, SINCE + 11_000, decided=False)
    t.add("normal", BYSTANDER, SINCE + 12_000, decided=False)
    t.refused[(0, 2)] = "invalid_event_id"
    cov = t.report()["coverage"]
    assert (cov["decided"], cov["missing"], cov["rejected"]) == (1, 1, {"invalid_event_id": 1})


def test_replayed_copies_count_once():
    t = Traffic()
    t.add("normal", BYSTANDER, SINCE + 10_000, copies=3)
    r = t.report()
    assert r["scenarios"]["normal"]["events"] == 1 and r["coverage"]["duplicates"] == 2


def test_attack_time_to_first_flag():
    t = Traffic()
    base = SINCE + 60_000
    for i in range(10):
        t.add("ssh_brute_force", HOSTILE, base + i * 100, "block" if i >= 4 else "allow")
    [a] = t.report()["attacks"]
    assert (a["events"], a["flagged"], a["first_flag_events"], a["first_flag_s"]) == (10, 6, 4, 0.4)


def test_a_pause_splits_attacks_and_the_second_is_from_a_known_source():
    t = Traffic()
    base = SINCE + 60_000
    t.add("port_scan", HOSTILE, base, "block")
    t.add("port_scan", HOSTILE, base + 2 * 60_000, "block")   # after a 2-minute pause
    first, second = t.report()["attacks"]
    assert not first["known_source"] and second["known_source"]


def test_missed_attack():
    t = Traffic()
    t.add("data_exfiltration", WORKSTATION, SINCE + 60_000)
    r = t.report()
    assert r["attacks"][0]["first_flag_events"] is None
    assert (r["summary"]["attacks_seen"], r["summary"]["attacks_caught"]) == (1, 0)


def test_blocks_on_an_attacking_host_are_containment_not_false_positives():
    t = Traffic()
    start = SINCE + 60_000
    t.add("lateral_movement", WORKSTATION, start, "block", "lateral_movement")
    t.add("lateral_movement", WORKSTATION, start + 10_000, "block", "lateral_movement")
    # The same workstation's ordinary traffic, during and after the attack:
    t.add("normal", WORKSTATION, start + 5_000, "block")
    t.add("normal", WORKSTATION, start + 10_000 + CONTAINMENT_MS - 1, "block")
    # ...and once its evidence has aged out -- a false positive again:
    t.add("normal", WORKSTATION, start + 10_000 + CONTAINMENT_MS + 1, "block")
    # A host that never attacked:
    t.add("normal", BYSTANDER, start, "block")
    s = t.report()["summary"]
    assert (s["normal_blocked"], s["normal_blocked_contained"], s["normal_blocked_uninvolved"]) == (4, 2, 2)
    assert s["precision_block"] == pytest.approx(2 / 6)
    assert s["precision_block_with_containment"] == pytest.approx(4 / 6)


def test_median_time_to_flag_skips_known_sources_and_attacks_already_running():
    t = Traffic()
    # Running when the window opened: its first event is at the window edge.
    t.add("web_scan", "185.23.44.12", SINCE + 500, "allow")
    t.add("web_scan", "185.23.44.12", SINCE + 9_500, "block")
    # A fresh source, flagged after 2 s.
    t.add("password_spray", HOSTILE, SINCE + 60_000, "allow")
    t.add("password_spray", HOSTILE, SINCE + 62_000, "block")
    # The same source again, a minute later: known, flagged at once.
    t.add("sql_injection", HOSTILE, SINCE + 120_000, "block")
    assert t.report()["summary"]["median_time_to_flag_s"] == 2.0


def test_attacks_ignore_normal_traffic():
    joined = [("normal", "block", "", BYSTANDER, SINCE + 1)]
    assert attacks(joined, SINCE) == []


def test_the_models_own_alerts_are_checked_against_ground_truth():
    t = Traffic()
    t.add("port_scan", HOSTILE, SINCE + 60_000, "alert")               # model alone, right
    t.add("normal", "102.67.14.54", SINCE + 61_000, "alert")           # model alone, wrong
    t.add("sql_injection", HOSTILE, SINCE + 62_000, "block", "sqli")   # a rule: not the model's
    s = t.report()["summary"]
    assert (s["model_only_flags"], s["model_only_attacks"], s["model_only_precision"]) == (2, 1, 0.5)
