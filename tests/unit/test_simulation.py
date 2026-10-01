"""The simulator through the per-event path: the detector's own regression test.

tools/replay_offline.py runs the producer's generators through decode ->
validate -> normalize -> enrich -> window -> rules, with no Kafka and no
Flink. Every kind of incident the simulator can start must be flagged by the
rules, and a runner with no incident must never be flagged -- a CI farm that
alerts every morning is a detector nobody reads.
"""

import os

# The producer sizes the farm from LOGS_PER_SECOND when it is imported: a
# small one keeps this test to a second or two.
os.environ.setdefault("LOGS_PER_SECOND", "200")

from conftest import ROOT  # noqa: E402,F401  (puts etl/ and the repo root on the path)

import sys  # noqa: E402

sys.path.insert(0, os.path.join(ROOT, "tools"))

from replay_offline import replay  # noqa: E402

INCIDENT_KINDS = {"retry_storm", "broken_toolchain", "oom_kill_storm", "slow_compile", "dependency_not_found",
                  "cache_corruption", "compiler_crash", "rogue_build_step", "artifact_bloat"}


def test_every_incident_is_caught_and_no_uninvolved_runner_is_flagged():
    result = replay(seconds=300, seed=3, incident_chance=0.03, rate=200)
    assert result["rejected"] == 0
    # every kind of incident ran at least once in the replay
    assert set(result["kinds"]) == INCIDENT_KINDS
    missed = {kind: (k["caught"], k["incidents"]) for kind, k in result["kinds"].items()
              if k["caught"] != k["incidents"]}
    assert not missed, f"incidents never flagged: {missed}"
    assert not result["uninvolved"], f"normal runners flagged: {dict(result['uninvolved'])}"
