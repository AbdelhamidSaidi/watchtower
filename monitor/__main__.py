"""Run the monitor: every collector on its own thread, /metrics on :9400.

    python -m monitor        (docker compose --profile monitoring up -d)
"""

import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from etl import config
from monitor.clickhouse import ClickHouse
from monitor.exposition import CONTENT_TYPE, Registry, counter, gauge
from monitor.model import ModelLifecycle
from monitor.platform import DockerVm, FlinkJob, KafkaOffsets, ServiceMemory, Services, kafka_groups
from monitor.stored import Stored
from monitor.truth import GroundTruth
from monitor.verdicts import AirflowVerdicts

PORT = int(os.getenv("WATCHTOWER_MONITOR_PORT", "9400"))
FLINK_REST_URL = os.getenv("FLINK_REST_URL", "http://flink-jobmanager:8081")
AIRFLOW_URL = os.getenv("AIRFLOW_URL", "http://airflow:8080")
PROC = os.getenv("WATCHTOWER_MONITOR_PROC", "/proc")
# Ground truth exists only on synthetic traffic.
TRUTH = os.getenv("WATCHTOWER_SYNTHETIC_TRAFFIC", "true").lower() == "true"


def log(collector, message):
    print(f"{time.strftime('%H:%M:%S')} [{collector}] {message}", file=sys.stderr, flush=True)


class Health:
    """How each collector is doing, as metrics of its own."""

    def __init__(self, registry):
        self.registry, self.lock = registry, threading.Lock()
        self.up, self.took, self.errors, self.last = {}, {}, {}, {}

    def record(self, name, ok, took):
        with self.lock:
            self.up[name], self.took[name] = int(ok), took
            self.errors[name] = self.errors.get(name, 0) + (0 if ok else 1)
            if ok:
                self.last[name] = time.time()
            up = gauge("watchtower_monitor_collector_up", "1 when the collector's last pass succeeded.")
            took_f = gauge("watchtower_monitor_collector_seconds", "How long the collector's last pass took.")
            errors = counter("watchtower_monitor_collector_errors_total", "Failed passes per collector.")
            last = gauge("watchtower_monitor_collector_success_timestamp_seconds", "The last successful pass.")
            for n in sorted(self.up):
                up.add(self.up[n], collector=n)
                took_f.add(self.took[n], collector=n)
                errors.add(self.errors[n], collector=n)
                last.add(self.last.get(n), collector=n)
            self.registry.publish("_monitor", [up, took_f, errors, last])


def run(collector, registry, health):
    failing = False
    while True:
        started = time.monotonic()
        try:
            families = collector.collect()
            ok = True
        except Exception as exc:
            families = getattr(collector, "after_error", lambda: [])()
            ok = False
            if not failing:
                log(collector.name, f"failing: {type(exc).__name__}: {str(exc)[:300]}")
        if ok and failing:
            log(collector.name, "recovered")
        failing = not ok
        try:
            registry.publish(collector.name, families)
        except ValueError as exc:       # a programming error: say so loudly, keep the rest running
            log(collector.name, str(exc))
            registry.withdraw(collector.name)
        health.record(collector.name, ok, time.monotonic() - started)
        time.sleep(max(0.0, collector.interval - (time.monotonic() - started)))


def serve(registry, port):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            path = self.path.split("?", 1)[0]
            if path == "/metrics":
                body, status, kind = registry.render().encode(), 200, CONTENT_TYPE
            elif path in ("/", "/healthz"):
                body, status, kind = b"watchtower monitor: /metrics\n", 200, "text/plain"
            else:
                body, status, kind = b"not found\n", 404, "text/plain"
            self.send_response(status)
            self.send_header("Content-Type", kind)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()


def main():
    ch = ClickHouse(f"http://{config.CLICKHOUSE_HOST}:{config.CLICKHOUSE_PORT}", config.CLICKHOUSE_USER,
                    config.clickhouse_password() or "")
    collectors = [
        Stored(ch),
        ModelLifecycle(ch),
        AirflowVerdicts(ch),
        KafkaOffsets(config.KAFKA_BOOTSTRAP_SERVERS, kafka_groups(config)),
        FlinkJob(FLINK_REST_URL),
        Services({
            "clickhouse": f"http://{config.CLICKHOUSE_HOST}:{config.CLICKHOUSE_PORT}/ping",
            "schema_registry": f"{config.SCHEMA_REGISTRY_URL}/subjects",
            "flink": f"{FLINK_REST_URL}/overview",
        }, AIRFLOW_URL),
        DockerVm(PROC),
        ServiceMemory(PROC),
    ]
    if TRUTH:
        collectors.append(GroundTruth(ch, config.KAFKA_BOOTSTRAP_SERVERS, config.KAFKA_TOPIC,
                                      config.SCHEMA_REGISTRY_URL, config.SCHEMA_SUBJECT))
    registry = Registry()
    health = Health(registry)
    for collector in collectors:
        threading.Thread(target=run, args=(collector, registry, health), name=collector.name,
                         daemon=True).start()
    log("monitor", f"{len(collectors)} collectors; /metrics on :{PORT}")
    serve(registry, PORT)


if __name__ == "__main__":
    main()
