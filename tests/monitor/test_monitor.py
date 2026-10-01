"""monitor/: the live-audit exporter, without Kafka, ClickHouse or /proc.

The counting (Tally), the parsers and the exposition take plain values,
so each is checked directly; the collectors only feed them.
"""

import pytest

pytest.importorskip("kafka")    # monitor.truth reuses the evaluator's definitions

from monitor import procfs  # noqa: E402
from monitor.exposition import Registry, counter, gauge, histogram  # noqa: E402
from monitor.stored import Stored  # noqa: E402
from monitor.truth import Event, Tally  # noqa: E402
from tools.evaluate_detection import ATTACK_GAP_MS, CONTAINMENT_MS  # noqa: E402

HOSTILE = "45.134.26.7"
BYSTANDER = "192.168.3.9"
T0 = 1_000_000


def event(scenario, source, ts, n=[0]):
    n[0] += 1
    return Event(f"e{n[0]}", scenario, source, ts, 0, n[0], ts)


def samples(families, name):
    """{(suffix, labels as a sorted tuple): value} for one metric."""
    family = next(f for f in families if f.name == name)
    return {(suffix, tuple(sorted(labels.items()))): value for suffix, labels, value in family.samples}


def value(families, name, **labels):
    return samples(families, name)[("", tuple(sorted(labels.items())))]


# --- exposition --------------------------------------------------------------

def test_render_escapes_labels_and_skips_unknown_values():
    f = gauge("x", "help").add(1.5, path='a"b\\c').add(None, path="unknown")
    assert f.render().splitlines() == ["# HELP x help", "# TYPE x gauge", 'x{path="a\\"b\\\\c"} 1.5']


def test_histogram_is_cumulative_with_inf_sum_and_count():
    h = histogram("lat", "help", (10, 100), [2, 5], 321, 7)
    lines = h.render().splitlines()[2:]
    assert lines == ['lat_bucket{le="10.0"} 2', 'lat_bucket{le="100.0"} 5', 'lat_bucket{le="+Inf"} 7',
                     "lat_sum 321", "lat_count 7"]


def test_two_collectors_cannot_publish_the_same_metric():
    registry = Registry()
    registry.publish("a", [counter("n_total", "h").add(1)])
    with pytest.raises(ValueError):
        registry.publish("b", [counter("n_total", "h").add(2)])
    registry.publish("a", [counter("n_total", "h").add(3)])     # replacing its own is fine
    assert "n_total 3" in registry.render()
    registry.withdraw("a")
    assert "n_total" not in registry.render()


# --- /proc -------------------------------------------------------------------

def test_meminfo_vmstat_pressure_and_cpu():
    mem = procfs.meminfo("MemTotal:        4012336 kB\nMemAvailable:    1369660 kB\nHugePages_Total:       0\n")
    assert mem == {"MemTotal": 4012336 * 1024, "MemAvailable": 1369660 * 1024, "HugePages_Total": 0}
    assert procfs.vmstat("pswpin 417024\noom_kill 2\n") == {"pswpin": 417024, "oom_kill": 2}
    psi = procfs.pressure("some avg10=1.50 avg60=0.00 avg300=0.02 total=7684636\n"
                          "full avg10=0.25 avg60=0.00 avg300=0.02 total=6958456\n")
    assert psi["some"]["avg10"] == 1.5 and psi["full"]["total"] == 6958456
    stat = "cpu  200 0 100 700 0 0 0 0 0 0\ncpu0 100 0 50 350 0 0 0 0 0 0\ncpu1 100 0 50 350 0 0 0 0 0 0\n"
    assert procfs.cpu_seconds(stat, hz=100)["idle"] == 7.0
    assert procfs.cpu_count(stat) == 2


@pytest.mark.parametrize("name, cmdline, service", [
    ("java", "java -cp ... kafka.Kafka /opt/kafka/config/server.properties", "kafka"),
    ("java", "java ... org.apache.flink.runtime.taskexecutor.TaskManagerRunner --configDir", "flink-taskmanager"),
    ("java", "java ... org.apache.flink.container.entrypoint.StandaloneApplicationClusterEntryPoint", "flink-jobmanager"),
    ("clickhouse-serv", "/usr/bin/clickhouse-server --config-file=/etc/clickhouse-server/config.xml", "clickhouse"),
    ("postgres", "postgres: airflow airflow 172.18.0.9(41234) idle", "airflow-db"),
    ("airflow", "/usr/python/bin/python3.12 /home/airflow/.local/bin/airflow scheduler", "airflow"),
    ("python", "python producer/security_log_producer.py", "producer"),
    ("python", "python -m monitor", "monitor"),
    ("containerd", "/usr/bin/containerd", "other"),
])
def test_processes_are_attributed_to_their_service(name, cmdline, service):
    assert procfs.classify(name, cmdline) == service


def test_services_rss_sums_processes_and_skips_kernel_threads(tmp_path):
    for pid, name, cmd, rss in (("10", "java", "java kafka.Kafka", "1000"), ("11", "postgres", "postgres: x", "10"),
                                ("12", "postgres", "postgres: y", "20"), ("2", "kthreadd", "", None)):
        (tmp_path / pid).mkdir()
        status = f"Name:\t{name}\n" + (f"VmRSS:\t{rss} kB\n" if rss else "")
        (tmp_path / pid / "status").write_text(status)
        (tmp_path / pid / "cmdline").write_bytes(cmd.replace(" ", "\0").encode())
    (tmp_path / "meminfo").write_text("")      # not a pid
    assert procfs.services_rss(str(tmp_path)) == {"kafka": 1000 * 1024, "airflow-db": 30 * 1024}


# --- ground truth: detectors ---------------------------------------------------

def test_each_detector_is_judged_against_the_truth():
    t = Tally()
    # An attack the rules missed and the model caught (the model alone alerted).
    t.decided(event("port_scan", HOSTILE, T0), "alert", rule_score=0.0, ml_score=0.8, model="v1")
    # Normal traffic the model wrongly scored high; the final decision followed it.
    t.decided(event("normal", BYSTANDER, T0), "alert", rule_score=0.0, ml_score=0.7, model="v1")
    # An attack a rule blocked; the model agreed.
    t.decided(event("sql_injection", HOSTILE, T0 + 1), "block", rule_score=0.95, ml_score=0.99, model="v1")
    f = t.families()
    det = "watchtower_detector_events_total"
    assert value(f, det, detector="rules", truth="attack", verdict="flagged") == 1
    assert value(f, det, detector="rules", truth="attack", verdict="allowed") == 1
    assert value(f, det, detector="model", truth="attack", verdict="flagged") == 2
    assert value(f, det, detector="model", truth="normal", verdict="flagged") == 1
    assert value(f, det, detector="final", truth="normal", verdict="flagged") == 1
    assert value(f, "watchtower_model_only_flags_total", truth="attack") == 1
    assert value(f, "watchtower_model_only_flags_total", truth="normal") == 1
    assert value(f, "watchtower_model_raised_total", truth="normal") == 1
    assert value(f, "watchtower_truth_decisions_total", scenario="sql_injection", action="block") == 1


def test_without_a_model_the_model_detector_counts_nothing():
    t = Tally()
    t.decided(event("normal", BYSTANDER, T0), "allow", rule_score=0.0, ml_score=0.0, model="")
    f = t.families()
    assert value(f, "watchtower_detector_events_total", detector="model", truth="normal", verdict="allowed") == 0
    assert value(f, "watchtower_detector_events_total", detector="rules", truth="normal", verdict="allowed") == 1


def test_extra_stored_copies_are_counted():
    t = Tally()
    t.decided(event("normal", BYSTANDER, T0), "allow", 0.0, 0.1, "v1", copies=3)
    assert value(t.families(), "watchtower_truth_duplicate_rows_total") == 2


# --- ground truth: attacks and hosts -------------------------------------------

def test_an_attack_is_caught_and_timed_from_its_first_event():
    t = Tally()
    t.decided(event("normal", BYSTANDER, T0), "allow", 0.0, 0.0, "v1")          # the monitor starts here
    start = T0 + 60_000
    for i in range(5):
        t.decided(event("ssh_brute_force", HOSTILE, start + i * 500), "block" if i >= 3 else "allow",
                  0.9 if i >= 3 else 0.0, 0.0, "v1")
    t.decided(event("normal", BYSTANDER, start + ATTACK_GAP_MS + 10_000), "allow", 0.0, 0.0, "v1")
    t.close_quiet()
    f = t.families()
    assert value(f, "watchtower_attacks_total", scenario="ssh_brute_force", outcome="caught") == 1
    ttf = samples(f, "watchtower_attack_time_to_flag_seconds")
    assert ttf[("_count", (("known_source", "false"),))] == 1
    assert ttf[("_sum", (("known_source", "false"),))] == 1.5
    assert ttf[("_bucket", (("known_source", "false"), ("le", "1.0")))] == 0
    assert ttf[("_bucket", (("known_source", "false"), ("le", "2.0")))] == 1


def test_an_attack_never_flagged_is_missed_once_it_pauses():
    t = Tally()
    t.decided(event("normal", BYSTANDER, T0), "allow", 0.0, 0.0, "v1")
    t.decided(event("data_exfiltration", HOSTILE, T0 + 10_000), "allow", 0.0, 0.1, "v1")
    t.close_quiet()
    f = t.families()
    assert samples(f, "watchtower_attacks_total") == {}         # still running: not judged yet
    assert value(f, "watchtower_attacks_open") == 1
    t.decided(event("normal", BYSTANDER, T0 + 10_000 + ATTACK_GAP_MS + 1), "allow", 0.0, 0.0, "v1")
    t.close_quiet()
    f = t.families()
    assert value(f, "watchtower_attacks_total", scenario="data_exfiltration", outcome="missed") == 1
    assert value(f, "watchtower_attacks_open") == 0


def test_a_pause_splits_attacks_and_the_second_comes_from_a_known_source():
    t = Tally()
    t.decided(event("normal", BYSTANDER, T0), "allow", 0.0, 0.0, "v1")
    first = T0 + 60_000
    t.decided(event("port_scan", HOSTILE, first), "block", 0.9, 0.0, "v1")
    second = first + ATTACK_GAP_MS + 30_000
    t.decided(event("port_scan", HOSTILE, second), "block", 0.9, 0.0, "v1")
    f = t.families()
    assert value(f, "watchtower_attacks_total", scenario="port_scan", outcome="caught") == 1
    ttf = samples(f, "watchtower_attack_time_to_flag_seconds")
    assert ttf[("_count", (("known_source", "false"),))] == 1
    assert ttf[("_count", (("known_source", "true"),))] == 1


def test_attacks_already_running_when_the_monitor_started_are_not_timed():
    t = Tally()
    t.decided(event("web_scan", HOSTILE, T0), "allow", 0.0, 0.0, "v1")
    t.decided(event("web_scan", HOSTILE, T0 + 900), "block", 0.85, 0.0, "v1")
    ttf = samples(t.families(), "watchtower_attack_time_to_flag_seconds")
    assert ttf[("_count", (("known_source", "false"),))] == 0


def test_blocking_an_attacking_hosts_normal_traffic_is_containment():
    t = Tally()
    t.decided(event("normal", BYSTANDER, T0), "allow", 0.0, 0.0, "v1")
    attack = T0 + 60_000
    t.decided(event("lateral_movement", "192.168.1.62", attack), "block", 0.9, 0.0, "v1")
    t.decided(event("normal", "192.168.1.62", attack + CONTAINMENT_MS - 1), "block", 0.9, 0.0, "v1")
    t.decided(event("normal", "192.168.1.62", attack + CONTAINMENT_MS + 1), "block", 0.9, 0.0, "v1")
    t.decided(event("normal", BYSTANDER, attack), "block", 0.9, 0.0, "v1")
    f = t.families()
    assert value(f, "watchtower_normal_blocked_total", host="attacking") == 1
    assert value(f, "watchtower_normal_blocked_total", host="uninvolved") == 2


# --- stored ------------------------------------------------------------------

class FakeClickHouse:
    def __init__(self, window_rows):
        self.window_rows, self.calls = window_rows, []

    def row(self, sql, **params):
        self.calls.append(sql)
        if "- 2000 AS upto" in sql:
            return {"upto": 10_000 + 5_000 * sum(1 for c in self.calls if "- 2000 AS upto" in c)}
        if "quantilesExact" in sql:
            return {"n": 4, "q": [150, 300, 400], "top": 450, "age_ms": 120}
        raise AssertionError(sql)

    def rows(self, sql, **params):
        self.calls.append(sql)
        if "GROUP BY action, model, decided_by" in sql:
            assert params["upto"] > params["since"]
            return self.window_rows
        return [{"reason": "invalid_event_id", "n": 1}]


def test_stored_counts_each_window_once_and_accumulates_histograms():
    rows = [{"action": "block", "model": "v1", "decided_by": "rules", "n": 3, "latency_sum": 900,
             "latency_le": [0, 1] + [3] * 16, "scored": 3, "score_le": [0] * 19 + [3], "score_sum": 2.9},
            {"action": "allow", "model": "v1", "decided_by": "none", "n": 1, "latency_sum": 100,
             "latency_le": [0, 0, 1] + [1] * 15, "scored": 1, "score_le": [1] * 20, "score_sum": 0.01}]
    stored = Stored(FakeClickHouse(rows))
    stored.collect()                    # the first pass only sets where counting starts
    f = stored.collect()
    assert value(f, "watchtower_stored_events_total", action="block", model="v1", decided_by="rules") == 3
    assert value(f, "watchtower_refused_messages_total", reason="invalid_event_id") == 1
    lat = samples(f, "watchtower_e2e_latency_ms")
    assert lat[("_count", ())] == 4 and lat[("_sum", ())] == 1000
    assert lat[("_bucket", (("le", "50.0"),))] == 1 and lat[("_bucket", (("le", "100.0"),))] == 4
    assert value(f, "watchtower_e2e_latency_last_minute_ms", stat="p95") == 300
    f = stored.collect()
    assert value(f, "watchtower_stored_events_total", action="block", model="v1", decided_by="rules") == 6
