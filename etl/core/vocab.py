"""The event contract: fields, closed vocabularies, defaults."""

# Every field the pipeline reads, in order, with its kind. A schema version
# that lacks a field (added later, or removed) yields None for it.
# `scenario` is deliberately absent: it is simulation ground truth and must
# never reach detection.
EVENT_FIELDS = [
    ("event_id", "string"),
    ("timestamp", "string"),
    ("runner_ip", "string"),
    ("project", "string"),
    ("event_type", "string"),
    ("hostname", "string"),
    ("severity", "string"),
    ("reason", "string"),
    ("command", "string"),
    ("exit_code", "int"),
    ("log_source", "string"),
    ("outcome", "string"),
    ("build_id", "string"),
    ("dest_ip", "string"),
    ("dest_port", "int"),
    ("protocol", "string"),
    ("triggered_by", "string"),
    ("http_method", "string"),
    ("url_path", "string"),
    ("http_status", "int"),
    ("user_agent", "string"),
    ("bytes_sent", "long"),
    ("response_time_ms", "int"),
    ("process_name", "string"),
    ("process_id", "int"),
    ("parent_process", "string"),
    ("process_uid", "int"),
    ("step", "string"),
    ("file_path", "string"),
    ("duration_ms", "int"),
    ("peak_memory_mb", "int"),
    ("cache_status", "string"),
    ("error_message", "string"),
]

# Values the producer can emit. Anything else is suspicious in itself --
# either a producer bug or something injecting events.
KNOWN_EVENT_TYPES = [
    "BUILD_STARTED",
    "BUILD_SUCCESS",
    "BUILD_FAILURE",
    "COMPILE_STEP",
    "TEST_RUN",
    "DEPENDENCY_FETCH",
    "ARTIFACT_PUBLISH",
]

MAX_PORT = 65535

# A process exit status is one byte: 0-255 (128 + n is "killed by signal n",
# so 137 is SIGKILL and 139 SIGSEGV).
MAX_EXIT_CODE = 255

# A build that has run for a day is a stuck build, not a duration.
MAX_DURATION_MS = 24 * 3600 * 1000

# event_id lands in a ClickHouse UUID column. Anything else would fail the
# insert and stall the ClickHouse consumer, so it is rejected up front
# instead.
UUID_REGEX = r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"

# Everything the producer can put in `severity`. Anything else becomes
# UNKNOWN, so a dashboard filter never misses a value it did not expect.
KNOWN_SEVERITIES = ["INFO", "WARNING", "ERROR"]
DEFAULT_SEVERITY = "UNKNOWN"

# 0 is root, so "unknown" needs a value of its own.
UNKNOWN_UID = -1
