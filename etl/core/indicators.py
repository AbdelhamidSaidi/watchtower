"""Signatures and reference data for enrichment.

Regexes are Python `re`, kept portable -- inline (?i) at the start, no
possessive quantifiers, no lookbehind -- so ClickHouse's `match()` can run
the same pattern when an analyst re-checks stored events.
"""

# RFC1918 plus loopback. Anchored, and the 172.16/12 branch is spelled out
# rather than written as 172.1[6-9] etc, which would also match 172.1.x.
PRIVATE_IP_REGEX = (
    r"^(10\.)"
    r"|^(192\.168\.)"
    r"|^(172\.(1[6-9]|2[0-9]|3[0-1])\.)"
    r"|^(127\.)"
)

# --- request / command indicators ------------------------------------------
# Signatures of requests and commands that are bad IN THEMSELVES, whatever
# the volume. Matched on the raw, undecoded text: an attacker encodes
# payloads (%27, %2e%2e) precisely so decoded matching misses them.

# A request whose path or query carries an injection or traversal payload.
SQLI_REGEX = (
    r"(?i)(\bunion\b.+\bselect\b"
    r"|'\s*or\s*'?\d*'?\s*=\s*'?\d"
    r"|\bor\s+1\s*=\s*1\b"
    r"|%27|'--|;\s*drop\s+table)"
)
TRAVERSAL_REGEX = r"(?i)(\.\./|\.\.%2f|%2e%2e|\.\.\.\.//|/etc/(passwd|shadow|hosts))"
XSS_REGEX = r"(?i)(<script|%3cscript|javascript:|onerror\s*=)"

# Offensive tooling that announces itself in the User-Agent.
SCANNER_AGENT_REGEX = (
    r"(?i)(sqlmap|nikto|gobuster|dirbuster|wfuzz|ffuf|nmap|masscan|zgrab|nuclei|acunetix|burp)"
)

# Paths nobody browses to on purpose: secrets, VCS metadata, admin panels.
SENSITIVE_PATH_REGEX = (
    r"(?i)^/(\.env|\.git|\.aws|\.ds_store|wp-admin|wp-login|phpmyadmin|admin/|"
    r"server-status|actuator|backup|config\.php|vendor/phpunit)"
)

# Commands and files that post-compromise activity reaches for. `curl` on its
# own is not here -- the monitoring agent curls a health check all day -- only
# a download piped straight into a shell is.
SENSITIVE_COMMAND_REGEX = (
    r"(?i)(/etc/shadow|/etc/passwd|id_rsa|\buseradd\b|\busermod\b|history\s+-c|"
    r"\bnc\s+-e\b|/dev/tcp/|chmod\s+\+x\s+/tmp|wget\s+https?://|"
    r"curl\s+[^|]*\|\s*(ba)?sh|sudo\s+su\b)"
)
SENSITIVE_FILE_REGEX = r"(^/etc/shadow$|/\.ssh/id_rsa|^/root/)"

# Hours considered "off hours". A login at 03:00 is not an anomaly by
# itself, but it is a useful feature for the model.
NIGHT_START_HOUR = 22
NIGHT_END_HOUR = 6

# Placeholder for a real GeoIP database (MaxMind GeoLite2 or similar).
#
# Keyed on the /16 PREFIX, not the full address. Real GeoIP data maps
# ranges, not individual hosts, and exact-IP matching does not survive a
# realistic network -- with ~176 hosts an exact-match table would leave
# almost every row with an empty country.
#
# "--" marks private ranges: they have no country, and that is meaningfully
# different from "we do not know".
GEOIP_PREFIXES = [
    ("192.168", "--"),   # RFC1918 workstations
    ("10.0", "--"),      # RFC1918 servers and automation
    ("172.16", "--"),
    ("127.0", "--"),
    ("102.67", "ZA"),    # remote staff / VPN pool
    ("196.200", "MA"),   # partner and branch ranges
    ("185.23", "RU"),    # hostile
    ("41.251", "MA"),    # hostile
    ("45.134", "NL"),    # hostile
    ("193.201", "UA"),   # hostile
]
