"""tools/evaluate_detection.py: the report, from ground truth and decisions.

summarize() takes what the tool read from Kafka and ClickHouse, so these
tests hand it both directly.
"""

import pytest

pytest.importorskip("kafka")

from tools.evaluate_detection import CONTAINMENT_MS, incidents, summarize  # noqa: E402

SINCE = 1_000_000
WORKSTATION = "192.168.1.62"
BYSTANDER = "192.168.3.9"
CULPRIT = "10.0.14.16"


class Traffic:
    """Builds truth {event_id: (scenario, partition, offset)} and decided
    {event_id: (action, rule_hits, runner_ip, ts, copies)} side by side."""

    def __init__(self):
        self.truth, self.decided, self.refused = {}, {}, {}

    def add(self, scenario, runner_ip, ts, action="ok", hits="", copies=1, decided=True):
        event_id = f"e{len(self.truth)}"
        self.truth[event_id] = (scenario, 0, len(self.truth))
        if decided:
            self.decided[event_id] = (action, hits, runner_ip, ts, copies)
        return event_id

    def report(self):
        return summarize(self.truth, 0, self.decided, self.refused, SINCE, 15)

    def report_with_lead(self, window_start, lead=5 * 60_000):
        return summarize(self.truth, 0, self.decided, self.refused, SINCE, 15, window_start, lead)


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


def test_incident_time_to_first_flag():
    t = Traffic()
    base = SINCE + 60_000
    for i in range(10):
        t.add("retry_storm", CULPRIT, base + i * 100, "quarantine" if i >= 4 else "ok")
    [a] = t.report()["incidents"]
    assert (a["events"], a["flagged"], a["first_flag_events"], a["first_flag_s"]) == (10, 6, 4, 0.4)


def test_a_pause_splits_incidents_and_the_second_is_from_a_known_source():
    t = Traffic()
    base = SINCE + 60_000
    t.add("oom_kill_storm", CULPRIT, base, "quarantine")
    t.add("oom_kill_storm", CULPRIT, base + 2 * 60_000, "quarantine")   # after a 2-minute pause
    first, second = t.report()["incidents"]
    assert not first["known_source"] and second["known_source"]


def test_missed_incident():
    t = Traffic()
    t.add("artifact_bloat", WORKSTATION, SINCE + 60_000)
    r = t.report()
    assert r["incidents"][0]["first_flag_events"] is None
    assert (r["summary"]["incidents_seen"], r["summary"]["incidents_caught"]) == (1, 0)


def test_quarantines_on_an_affected_runner_are_containment_not_false_positives():
    t = Traffic()
    start = SINCE + 60_000
    t.add("slow_compile", WORKSTATION, start, "quarantine", "slow_compile")
    t.add("slow_compile", WORKSTATION, start + 10_000, "quarantine", "slow_compile")
    # The same workstation's ordinary traffic, during and after the incident:
    t.add("normal", WORKSTATION, start + 5_000, "quarantine")
    t.add("normal", WORKSTATION, start + 10_000 + CONTAINMENT_MS - 1, "quarantine")
    # ...and once its evidence has aged out -- a false positive again:
    t.add("normal", WORKSTATION, start + 10_000 + CONTAINMENT_MS + 1, "quarantine")
    # A host that never hit:
    t.add("normal", BYSTANDER, start, "quarantine")
    s = t.report()["summary"]
    assert (s["normal_quarantined"], s["normal_quarantined_contained"], s["normal_quarantined_uninvolved"]) == (4, 2, 2)
    assert s["precision_quarantine"] == pytest.approx(2 / 6)
    assert s["precision_quarantine_with_containment"] == pytest.approx(4 / 6)


def test_median_time_to_flag_skips_known_sources_and_incidents_already_running():
    t = Traffic()
    # Running when the window opened: its first event is at the window edge.
    t.add("dependency_not_found", "10.0.14.17", SINCE + 500, "ok")
    t.add("dependency_not_found", "10.0.14.17", SINCE + 9_500, "quarantine")
    # A fresh source, flagged after 2 s.
    t.add("broken_toolchain", CULPRIT, SINCE + 60_000, "ok")
    t.add("broken_toolchain", CULPRIT, SINCE + 62_000, "quarantine")
    # The same source again, a minute later: known, flagged at once.
    t.add("cache_corruption", CULPRIT, SINCE + 120_000, "quarantine")
    assert t.report()["summary"]["median_time_to_flag_s"] == 2.0


def test_incidents_ignore_normal_traffic():
    joined = [("normal", "quarantine", "", BYSTANDER, SINCE + 1)]
    assert incidents(joined, SINCE) == []


def test_the_models_own_alerts_are_checked_against_ground_truth():
    t = Traffic()
    t.add("oom_kill_storm", CULPRIT, SINCE + 60_000, "alert")               # model alone, right
    t.add("normal", "102.67.14.54", SINCE + 61_000, "alert")           # model alone, wrong
    t.add("cache_corruption", CULPRIT, SINCE + 62_000, "quarantine", "cache_poisoned")   # a rule: not the model's
    s = t.report()["summary"]
    assert (s["model_only_flags"], s["model_only_incidents"], s["model_only_precision"]) == (2, 1, 0.5)


def test_an_incident_just_before_the_window_explains_the_runners_quarantines():
    """Its rolling windows still hold the evidence after the incident ends,
    so its normal events at the start of the window are containment -- if the
    tool read far enough back to see the incident."""
    lead = 5 * 60_000
    t = Traffic()
    before = SINCE - 60_000                              # inside the lead-in, ended 30 s before the window
    for i in range(5):
        t.add("retry_storm", CULPRIT, before + i * 1_000, "quarantine")
    t.add("normal", CULPRIT, SINCE + 10_000, "quarantine")
    t.add("normal", BYSTANDER, SINCE + 10_000)
    window_start = {0: 5}                                # the first 5 messages precede the window

    with_lead = summarize(t.truth, 0, t.decided, t.refused, SINCE, 15, window_start, lead)["summary"]
    assert (with_lead["normal_quarantined"], with_lead["normal_quarantined_contained"]) == (1, 1)
    assert with_lead["normal_quarantined_uninvolved"] == 0
    # only the window is counted: the lead-in's incident events are not
    assert with_lead["incident_events"] == 0 and with_lead["normal_events"] == 2

    # the same data read without the lead-in: the incident is invisible, the flag looks like a false positive
    blind = {k: v for k, v in t.decided.items() if k not in {f"e{i}" for i in range(5)}}
    blind_truth = {k: v for k, v in t.truth.items() if k not in {f"e{i}" for i in range(5)}}
    s = summarize(blind_truth, 0, blind, t.refused, SINCE, 15)["summary"]
    assert s["normal_quarantined_uninvolved"] == 1


def test_lead_in_messages_are_not_coverage():
    t = Traffic()
    t.add("normal", BYSTANDER, SINCE - 120_000, decided=False)    # before the window, never decided: not counted
    t.add("normal", BYSTANDER, SINCE + 10_000)
    cov = t.report_with_lead({0: 1})["coverage"]
    assert (cov["decoded"], cov["decided"], cov["missing"]) == (1, 1, 0)
