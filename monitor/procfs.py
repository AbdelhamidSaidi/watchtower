"""The Docker VM, read from /proc: memory, swap, pressure, OOM kills, CPU,
and memory per service.

A container shares the VM's kernel, so /proc/meminfo, /proc/vmstat and
/proc/pressure describe the whole VM, not the container: the numbers that
decide whether a ~4 GB VM can hold the stack. Swap and memory pressure,
not the pipeline, were behind every multi-second latency spike measured so
far (clickhouse/config/dev-limits.xml). Memory per service needs every
process in view, hence `pid: host` on the monitor (docker-compose.yml).

The parsers take the file's text, so tests feed them directly.
"""

import os

CPU_MODES = ("user", "nice", "system", "idle", "iowait", "irq", "softirq", "steal")


def meminfo(text):
    """{field: bytes} from /proc/meminfo."""
    values = {}
    for line in text.splitlines():
        name, _, rest = line.partition(":")
        parts = rest.split()
        if parts and parts[0].isdigit():
            values[name] = int(parts[0]) * (1024 if parts[1:2] == ["kB"] else 1)
    return values


def vmstat(text):
    """{counter: value} from /proc/vmstat."""
    values = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[1].lstrip("-").isdigit():
            values[parts[0]] = int(parts[1])
    return values


def pressure(text):
    """{"some"|"full": {"avg10": %, "avg60": %, "avg300": %, "total": µs}}
    from a /proc/pressure file (PSI): the share of time tasks stalled
    waiting for the resource. `full` is every runnable task stalled at once."""
    values = {}
    for line in text.splitlines():
        kind, *fields = line.split()
        values[kind] = {k: float(v) for k, v in (f.split("=", 1) for f in fields)}
    return values


def cpu_seconds(text, hz=100):
    """{mode: seconds} for all CPUs together, from /proc/stat."""
    for line in text.splitlines():
        if line.startswith("cpu "):
            ticks = [int(x) for x in line.split()[1:1 + len(CPU_MODES)]]
            return {mode: t / hz for mode, t in zip(CPU_MODES, ticks)}
    return {}


def cpu_count(text):
    return sum(1 for line in text.splitlines() if line.startswith("cpu") and line[3:4].isdigit())


# First match wins. airflow-db before airflow: Postgres titles its backends
# "postgres: airflow airflow 172.18.0.9(...)".
SERVICES = (
    ("airflow-db", lambda name, cmd: name == "postgres" or cmd.startswith("postgres")),
    ("kafka", lambda name, cmd: "kafka.Kafka" in cmd),
    ("flink-taskmanager", lambda name, cmd: "TaskManagerRunner" in cmd),
    ("flink-jobmanager", lambda name, cmd: "ClusterEntryPoint" in cmd or "ClusterEntrypoint" in cmd),
    ("clickhouse", lambda name, cmd: name.startswith("clickhouse")),
    ("schema-registry", lambda name, cmd: "karapace" in cmd),
    ("producer", lambda name, cmd: "security_log_producer" in cmd),
    ("monitor", lambda name, cmd: " -m monitor" in cmd),
    ("prometheus", lambda name, cmd: name == "prometheus"),
    ("grafana", lambda name, cmd: name.startswith("grafana")),
    ("airflow", lambda name, cmd: "airflow" in cmd),
)


def classify(name, cmdline):
    for service, test in SERVICES:
        if test(name, cmdline):
            return service
    return "other"


def services_rss(proc="/proc"):
    """{service: resident bytes}, summed over every process of the service.

    RSS counts a page shared by two processes twice (Airflow's forked
    workers): an upper bound per service, exact for the single-process JVMs
    and ClickHouse that dominate.
    """
    totals = {}
    for pid in os.listdir(proc):
        if not pid.isdigit():
            continue
        try:
            with open(f"{proc}/{pid}/status") as handle:
                status = handle.read()
            with open(f"{proc}/{pid}/cmdline", "rb") as handle:
                cmdline = handle.read().replace(b"\0", b" ").decode(errors="replace").strip()
        except OSError:
            continue    # exited between listdir and open
        fields = dict(line.split(":", 1) for line in status.splitlines() if ":" in line)
        rss = fields.get("VmRSS", "").split()
        if not rss:
            continue    # a kernel thread
        service = classify(fields.get("Name", "").strip(), cmdline)
        totals[service] = totals.get(service, 0) + int(rss[0]) * 1024
    return totals


def read(proc, name):
    with open(os.path.join(proc, name)) as handle:
        return handle.read()
