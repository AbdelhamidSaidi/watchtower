"""The event contract: fields, closed vocabularies, defaults."""

# Every field the pipeline reads, in order, with its kind. A schema version
# that lacks a field (added later, or removed) yields None for it.
# `scenario` is deliberately absent: it is simulation ground truth and must
# never reach detection.
EVENT_FIELDS = [
    ("event_id", "string"),
    ("timestamp", "string"),
    ("source_ip", "string"),
    ("user", "string"),
    ("event_type", "string"),
    ("hostname", "string"),
    ("severity", "string"),
    ("reason", "string"),
    ("command", "string"),
    ("target_port", "int"),
    # v2: request / network / process / file context
    ("log_source", "string"),
    ("outcome", "string"),
    ("session_id", "string"),
    ("dest_ip", "string"),
    ("dest_port", "int"),
    ("protocol", "string"),
    ("auth_method", "string"),
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
    ("file_path", "string"),
    ("file_operation", "string"),
]

# Values the producer can emit. Anything else is suspicious in itself --
# either a producer bug or something injecting events.
KNOWN_EVENT_TYPES = [
    "LOGIN_SUCCESS",
    "LOGIN_FAILURE",
    "SSH_CONNECTION",
    "FILE_ACCESS",
    "COMMAND_EXECUTION",
    "PORT_SCAN",
    "HTTP_REQUEST",
]

MAX_PORT = 65535

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
