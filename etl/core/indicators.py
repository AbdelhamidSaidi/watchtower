"""Signatures and reference data for enrichment.

Regexes are Python `re`, kept portable -- inline (?i) at the start, no
possessive quantifiers, no lookbehind -- so ClickHouse's `match()` can run
the same pattern when an engineer re-checks stored events.
"""

import os

# RFC1918 plus loopback. Anchored, and the 172.16/12 branch is spelled out
# rather than written as 172.1[6-9] etc, which would also match 172.1.x.
PRIVATE_IP_REGEX = (
    r"^(10\.)"
    r"|^(192\.168\.)"
    r"|^(172\.(1[6-9]|2[0-9]|3[0-1])\.)"
    r"|^(127\.)"
)

# --- failure signatures ----------------------------------------------------
# What a tool prints when the BUILD INFRASTRUCTURE is at fault, not the
# code: an engineer fixes a missing semicolon, but a compiler crash, a full
# disk or a corrupt cache entry is the farm's problem, whatever project hit
# it. Matched on the first line of the tool's error output. Ordinary
# compile and test errors ("expected ';'", "undefined reference",
# "AssertionError") match none of these -- they are the normal failures.

# The compiler itself crashed.
ICE_REGEX = r"(?i)(internal compiler error|segmentation fault|sigsegv|stack dump:|please submit a full bug report)"
# The kernel killed it for memory.
OOM_REGEX = r"(?i)(out of memory|\bkilled\b|oomkilled|cannot allocate memory|java\.lang\.outofmemoryerror)"
# The runner ran out of disk.
DISK_FULL_REGEX = r"(?i)(no space left on device|disk quota exceeded)"
# A cache entry or downloaded artifact does not match its digest.
CHECKSUM_REGEX = r"(?i)(checksum mismatch|sha-?256 mismatch|digest mismatch|corrupt(ed)? (cache|archive|entry)|unexpected end of archive)"

# --- commands ---------------------------------------------------------------
# Commands a build step has no business running: a miner, a download piped
# straight into a shell, credentials read or sent out, a reverse shell.
# `curl` on its own is not here -- the build tools curl all day -- only a
# download piped into a shell is.
ROGUE_COMMAND_REGEX = (
    r"(?i)(\bxmrig\b|\bminerd\b|stratum\+tcp|\bnc\s+-e\b|/dev/tcp/|bash\s+-i\s*>&|"
    r"(curl|wget)\s+[^|]*\|\s*(ba)?sh|base64\s+-d\s*\|\s*(ba)?sh|"
    r"printenv\s*\|\s*(curl|nc)|\.aws/credentials|id_rsa|chmod\s+\+x\s+/tmp|history\s+-c)"
)
ROGUE_FILE_REGEX = r"(/\.ssh/id_|/\.aws/credentials|^/etc/(shadow|passwd)$)"

# A dependency fetched from somewhere the build never resolves from: an
# unofficial or unsigned mirror, a script or executable instead of a
# library, a path that climbs out of the repository.
UNTRUSTED_FETCH_REGEX = (
    r"(?i)(^/(unofficial|unverified|snapshots-unsigned)/|\.(sh|exe|bat|ps1)(\?|$)|\.\./)"
)

# A compile step slower than this is a regression, not a big translation
# unit: the largest ordinary step in the farm links in about four minutes.
SLOW_STEP_MS = int(os.getenv("WATCHTOWER_SLOW_STEP_MS", str(5 * 60 * 1000)))

# Hours considered "off hours". Nightly builds make 03:00 perfectly
# ordinary, so it is a feature for the model, never a rule.
NIGHT_START_HOUR = 22
NIGHT_END_HOUR = 6

# Placeholder for a real inventory (a CMDB or the cloud provider's API).
#
# Keyed on the /16 PREFIX, not the full address: inventories map ranges, and
# exact-IP matching does not survive a farm of ~1,800 runners.
#
# "--" marks the on-prem datacenter ranges: they have no cloud region, and
# that is meaningfully different from "we do not know".
REGION_PREFIXES = [
    ("192.168", "--"),   # developer workstations
    ("10.0", "--"),      # build servers and the CI farm
    ("172.16", "--"),
    ("127.0", "--"),
    ("102.67", "cloud-af"),    # cloud spot runners
    ("196.200", "vendor-ma"),  # vendor build agents
]
