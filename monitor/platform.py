"""The platform under the pipeline: Kafka offsets and lag, the Flink job as
its REST API sees it, whether each service answers, and the Docker VM.
"""

import json
import os
import time
import urllib.request

from monitor import procfs
from monitor.exposition import counter, gauge
from orchestration.ops.pipeline import CLICKHOUSE_GROUP, FLINK_JOB


def get_json(url, timeout=5):
    with urllib.request.urlopen(url, timeout=timeout) as response:
        return json.load(response)


class KafkaOffsets:
    """End offsets per topic -- their rate is what arrives -- and each
    consumer group's lag, read without joining any group.

    Flink commits its offsets at checkpoints (every 10 s), so its group's
    lag here runs up to ~10 s of traffic behind; Flink's own records_lag_max
    is the live figure. ClickHouse commits after every insert."""

    name = "kafka"
    interval = 10.0

    def __init__(self, bootstrap, groups):
        self.bootstrap = bootstrap
        self.groups = groups        # {group: topic}
        self.consumer = self.admin = None

    def collect(self):
        from kafka import KafkaConsumer, TopicPartition
        from kafka.admin import KafkaAdminClient

        try:
            if self.consumer is None:
                self.consumer = KafkaConsumer(bootstrap_servers=self.bootstrap, enable_auto_commit=False,
                                              request_timeout_ms=15_000)
                self.admin = KafkaAdminClient(bootstrap_servers=self.bootstrap, request_timeout_ms=15_000)
            topics = sorted(set(self.groups.values()))
            partitions = {t: [TopicPartition(t, p) for p in sorted(self.consumer.partitions_for_topic(t) or ())]
                          for t in topics}
            ends = self.consumer.end_offsets([tp for tps in partitions.values() for tp in tps])
            committed = self.admin.list_group_offsets({g: partitions[t] for g, t in self.groups.items()})
            lags = {}
            for group, topic in self.groups.items():
                offsets = committed.get(group) or {}
                # A partition the group never committed on counts from its start.
                lags[group] = (topic, sum(
                    max(0, ends[tp] - (offsets[tp].offset if tp in offsets and offsets[tp].offset >= 0 else 0))
                    for tp in partitions[topic]))
        except Exception:
            self.close()
            raise

        appended = counter("watchtower_kafka_messages_appended_total",
                           "Messages appended to each topic (the sum of its partitions' end offsets).")
        for topic, tps in partitions.items():
            appended.add(sum(ends[tp] for tp in tps), topic=topic)
        lag = gauge("watchtower_kafka_consumer_lag_messages", "Messages each consumer group has yet to commit.")
        for group, (topic, n) in lags.items():
            lag.add(n, group=group, topic=topic)
        return [appended, lag]

    def close(self):
        for client in (self.consumer, self.admin):
            try:
                if client is not None:
                    client.close()
            except Exception:
                pass
        self.consumer = self.admin = None

    def after_error(self):
        return []


class FlinkJob:
    """The stream job as the JobManager's REST API sees it: its state, its
    tasks, and its checkpoints. A checkpoint that stops completing means
    offsets stop being committed and state stops being saved -- after a
    crash, everything since the last one is replayed."""

    name = "flink"
    interval = 10.0

    def __init__(self, url):
        self.url = url.rstrip("/")

    def collect(self):
        f = [gauge("watchtower_flink_taskmanagers", "TaskManagers registered with the JobManager.")
             .add(len(get_json(f"{self.url}/taskmanagers")["taskmanagers"]))]
        jobs = [j for j in get_json(f"{self.url}/jobs/overview")["jobs"] if j["name"] == FLINK_JOB]
        state = gauge("watchtower_flink_job_state", "The stream job's state (value 1); absent if no job.")
        f.append(state)
        if not jobs:
            return f
        job = max(jobs, key=lambda j: (j["state"] == "RUNNING", j.get("start-time", 0)))
        state.add(1, state=job["state"])
        tasks = gauge("watchtower_flink_tasks", "The job's tasks: running, and in all.")
        tasks.add(job.get("tasks", {}).get("running", 0), status="running")
        tasks.add(job.get("tasks", {}).get("total", 0), status="total")
        f.append(tasks)
        if job.get("start-time", 0) > 0:
            f.append(gauge("watchtower_flink_job_uptime_seconds", "Since the job (re)started.")
                     .add(time.time() - job["start-time"] / 1000))

        checkpoints = get_json(f"{self.url}/jobs/{job['jid']}/checkpoints")
        counts = gauge("watchtower_flink_checkpoints", "Checkpoints since the job started, by status.")
        for status in ("completed", "failed", "in_progress", "restored"):
            counts.add(checkpoints.get("counts", {}).get(status, 0), status=status)
        f.append(counts)
        latest = (checkpoints.get("latest") or {}).get("completed")
        if latest:
            f += [
                gauge("watchtower_flink_last_checkpoint_duration_seconds", "The newest completed checkpoint: "
                      "how long it took end to end.").add(latest.get("end_to_end_duration", 0) / 1000),
                gauge("watchtower_flink_last_checkpoint_size_bytes", "The newest completed checkpoint's size.")
                .add(latest.get("checkpointed_size", latest.get("state_size", 0))),
                gauge("watchtower_flink_last_checkpoint_age_seconds", "Since the newest checkpoint completed.")
                .add(max(0.0, time.time() - latest["latest_ack_timestamp"] / 1000)),
            ]
        return f

    def after_error(self):
        return []


class Services:
    """Does each service answer? The same questions a person would ask."""

    name = "services"
    interval = 15.0

    def __init__(self, probes, airflow_url):
        self.probes = probes        # {service: url}
        self.airflow_url = airflow_url

    def collect(self):
        up = gauge("watchtower_service_up", "1 when the service answered its probe.")
        took = gauge("watchtower_service_probe_seconds", "How long the probe took.")
        f = [up, took]
        for service, url in self.probes.items():
            started = time.monotonic()
            try:
                with urllib.request.urlopen(url, timeout=5) as response:
                    response.read()
                ok = True
            except Exception:
                ok = False
            up.add(int(ok), service=service)
            took.add(time.monotonic() - started, service=service)

        started = time.monotonic()
        try:
            health = get_json(f"{self.airflow_url}/api/v2/monitor/health")
        except Exception:
            health = None
        up.add(int(health is not None), service="airflow")
        took.add(time.monotonic() - started, service="airflow")
        if health:
            parts = gauge("watchtower_airflow_component_healthy",
                          "Airflow's own health, per component that runs (the triggerer does not here).")
            for component, status in sorted(health.items()):
                if isinstance(status, dict) and status.get("status") is not None:
                    parts.add(int(status["status"] == "healthy"), component=component)
            f.append(parts)
        return f


class DockerVm:
    """The VM every container shares: memory, swap, pressure, OOM kills,
    CPU. Its /proc counters run since the VM booted; rates are what matter."""

    name = "vm"
    interval = 5.0

    def __init__(self, proc="/proc"):
        self.proc = proc
        self.hz = os.sysconf("SC_CLK_TCK") if hasattr(os, "sysconf") else 100

    def collect(self):
        mem = procfs.meminfo(procfs.read(self.proc, "meminfo"))
        vm = procfs.vmstat(procfs.read(self.proc, "vmstat"))
        stat = procfs.read(self.proc, "stat")

        memory = gauge("watchtower_vm_memory_bytes", "The Docker VM's memory and swap.")
        for kind, field in (("total", "MemTotal"), ("available", "MemAvailable"), ("free", "MemFree"),
                            ("cached", "Cached"), ("swap_total", "SwapTotal"), ("swap_free", "SwapFree")):
            memory.add(mem.get(field), kind=kind)
        swapped = counter("watchtower_vm_swap_pages_total", "Pages swapped in and out since the VM booted.")
        swapped.add(vm.get("pswpin"), direction="in")
        swapped.add(vm.get("pswpout"), direction="out")
        f = [
            memory, swapped,
            counter("watchtower_vm_oom_kills_total", "Processes the kernel killed for memory since boot.")
            .add(vm.get("oom_kill")),
            counter("watchtower_vm_major_page_faults_total", "Major page faults (read back from disk or swap).")
            .add(vm.get("pgmajfault")),
        ]

        avg = gauge("watchtower_vm_pressure_avg10_percent",
                    "PSI: share of the last 10 s that some (or all) tasks stalled on the resource.")
        stall = counter("watchtower_vm_pressure_stall_seconds_total", "PSI: stalled time since boot.")
        for resource in ("memory", "cpu", "io"):
            try:
                psi = procfs.pressure(procfs.read(self.proc, f"pressure/{resource}"))
            except OSError:
                continue
            for kind, values in psi.items():
                avg.add(values.get("avg10"), resource=resource, kind=kind)
                stall.add(values.get("total", 0) / 1e6, resource=resource, kind=kind)
        f += [avg, stall]

        cpu = counter("watchtower_vm_cpu_seconds_total", "CPU time of the whole VM, by mode.")
        for mode, seconds in procfs.cpu_seconds(stat, self.hz).items():
            cpu.add(seconds, mode=mode)
        f += [cpu, gauge("watchtower_vm_cpus", "CPUs in the VM.").add(procfs.cpu_count(stat)),
              gauge("watchtower_vm_load1", "One-minute load average.")
              .add(float(procfs.read(self.proc, "loadavg").split()[0]))]
        return f

    def after_error(self):
        return []


class ServiceMemory:
    name = "processes"
    interval = 15.0

    def __init__(self, proc="/proc"):
        self.proc = proc

    def collect(self):
        rss = gauge("watchtower_service_memory_bytes",
                    "Resident memory per service, summed over its processes (needs `pid: host`).")
        for service, n in sorted(procfs.services_rss(self.proc).items()):
            rss.add(n, service=service)
        return [rss]

    def after_error(self):
        return []


def kafka_groups(config):
    """{consumer group: topic} for every reader of the pipeline's topics."""
    return {
        config.CONSUMER_GROUP: config.KAFKA_TOPIC,             # Flink
        CLICKHOUSE_GROUP: config.SCORED_TOPIC,                 # clickhouse/init/03_streaming_ingest.sql
        "clickhouse-rejected-events": config.REJECTED_TOPIC,
    }
