"""The per-event stages: decode -> validate -> normalize -> enrich.

ONE event at a time -- this is what the Flink job runs.

`_trim` strips SPACES only, not all whitespace (it began as a mirror of
Spark's F.trim, and stored rows depend on it): a tab-only event_id is not
blank.
"""

import base64
import io
import json
import re
import struct
from datetime import datetime, timezone

import fastavro

from core import indicators as ind
from core.vocab import (
    DEFAULT_SEVERITY,
    EVENT_FIELDS,
    KNOWN_EVENT_TYPES,
    KNOWN_SEVERITIES,
    MAX_PORT,
    UNKNOWN_UID,
    UUID_REGEX,
)

MAGIC_BYTE = 0
_KNOWN_EVENT_TYPES = frozenset(KNOWN_EVENT_TYPES)
_KNOWN_SEVERITIES = frozenset(KNOWN_SEVERITIES)
_UUID = re.compile(UUID_REGEX)
_GEO = dict(ind.GEOIP_PREFIXES)


def _re(pattern):
    return re.compile(pattern)


_PRIVATE = _re(ind.PRIVATE_IP_REGEX)
_SQLI = _re(ind.SQLI_REGEX)
_TRAVERSAL = _re(ind.TRAVERSAL_REGEX)
_XSS = _re(ind.XSS_REGEX)
_SCANNER = _re(ind.SCANNER_AGENT_REGEX)
_SENSITIVE_PATH = _re(ind.SENSITIVE_PATH_REGEX)
_SENSITIVE_COMMAND = _re(ind.SENSITIVE_COMMAND_REGEX)
_SENSITIVE_FILE = _re(ind.SENSITIVE_FILE_REGEX)


def _trim(value):
    return value.strip(" ") if isinstance(value, str) else value


# --- decode ------------------------------------------------------------------

class Decoder:
    """Confluent wire format -> event dict, with every registered version.

        byte 0      magic byte, 0x00
        bytes 1-4   schema id (big-endian)
        bytes 5..   Avro binary, decodable ONLY with the schema that wrote it

    versions: {schema_id: schema_json}, fetched from the registry at startup.
    """

    def __init__(self, versions):
        if not versions:
            raise ValueError("Decoder needs at least one schema version")
        self._schemas = {}
        for schema_id, schema_json in versions.items():
            parsed = fastavro.parse_schema(json.loads(schema_json))
            present = {f["name"] for f in json.loads(schema_json)["fields"]}
            self._schemas[int(schema_id)] = (parsed, present)

    def decode(self, raw):
        """-> (event dict or None, wire_error or None, schema_id or None)"""
        if raw is None or len(raw) < 5 or raw[0] != MAGIC_BYTE:
            return None, "not_avro_framed", None
        schema_id = struct.unpack(">I", raw[1:5])[0]
        known = self._schemas.get(schema_id)
        if known is None:
            return None, "unknown_schema_version", schema_id
        parsed, present = known
        try:
            record = fastavro.schemaless_reader(io.BytesIO(raw[5:]), parsed)
        except Exception:
            return None, "undecodable_payload", schema_id
        if not isinstance(record, dict) or record.get("event_id") is None:
            return None, "undecodable_payload", schema_id
        event = {}
        for name, kind in EVENT_FIELDS:
            value = record.get(name) if name in present else None
            if value is not None and kind in ("int", "long"):
                value = int(value)
            event[name] = value
        return event, None, schema_id


# --- validate ------------------------------------------------------------------

def parse_timestamp(value):
    """ISO-8601 text -> aware UTC datetime, or None if it is not one.

    Accepts what the producer writes (datetime.isoformat(), with or without
    microseconds) plus a trailing Z and a space separator. A naive value is
    UTC.
    """
    if not isinstance(value, str):
        return None
    text = value.strip()
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _blank(value):
    return value is None or _trim(value) == ""


def _out_of(value, low, high):
    return value is not None and not (low <= value <= high)


def reject_reason(event, wire_error=None):
    """First failing check wins, in the same order as clean.validate().

    Sets event["_ts"] (the parsed timestamp) as a side effect when valid.
    """
    if wire_error:
        return wire_error
    if _blank(event.get("event_id")):
        return "missing_event_id"
    if not _UUID.match(_trim(event["event_id"])):
        return "invalid_event_id"
    ts = parse_timestamp(event.get("timestamp"))
    if ts is None:
        return "invalid_timestamp"
    if _blank(event.get("event_type")):
        return "missing_event_type"
    if _trim(event["event_type"]).upper() not in _KNOWN_EVENT_TYPES:
        return "unknown_event_type"
    if _blank(event.get("source_ip")):
        return "missing_source_ip"
    if _out_of(event.get("target_port"), 0, MAX_PORT) or _out_of(event.get("dest_port"), 0, MAX_PORT):
        return "port_out_of_range"
    if _out_of(event.get("http_status"), 100, 599):
        return "invalid_http_status"
    event["_ts"] = ts
    return None


# --- normalize ------------------------------------------------------------------

_LOWER = ["user", "hostname", "reason", "log_source", "outcome", "protocol",
          "auth_method", "file_operation", "process_name", "parent_process"]
_TEXT = ["command", "url_path", "user_agent", "file_path", "session_id", "dest_ip"]
_ZERO = ["target_port", "dest_port", "http_status", "bytes_sent", "response_time_ms", "process_id"]


def normalize(event):
    """One canonical spelling per value. In place."""
    for name in _LOWER:
        event[name] = _trim(event.get(name) or "").lower()
    for name in _TEXT:
        event[name] = _trim(event.get(name) or "")
    for name in _ZERO:
        if event.get(name) is None:
            event[name] = 0
    event["event_type"] = _trim(event["event_type"]).upper()
    event["http_method"] = _trim(event.get("http_method") or "").upper()
    severity = _trim(event.get("severity") or "").upper()
    event["severity"] = severity if severity in _KNOWN_SEVERITIES else DEFAULT_SEVERITY
    event["source_ip"] = _trim(event["source_ip"])
    if event.get("process_uid") is None:
        event["process_uid"] = UNKNOWN_UID
    return event


# --- enrich ------------------------------------------------------------------

def _flag(condition):
    return 1 if condition else 0


def enrich(event):
    """Indicators and GeoIP. In place."""
    url = event["url_path"]
    if _SQLI.search(url):
        signature = "sqli"
    elif _TRAVERSAL.search(url):
        signature = "path_traversal"
    elif _XSS.search(url):
        signature = "xss"
    else:
        signature = ""
    event["request_signature"] = signature
    event["is_attack_signature"] = _flag(signature)
    event["is_scanner_agent"] = _flag(_SCANNER.search(event["user_agent"]))
    event["is_sensitive_path"] = _flag(_SENSITIVE_PATH.search(url))
    event["is_sensitive_command"] = _flag(
        _SENSITIVE_COMMAND.search(event["command"]) or _SENSITIVE_FILE.search(event["file_path"])
    )
    event["is_privileged"] = _flag(event["process_uid"] == 0)
    event["is_internal_ip"] = _flag(_PRIVATE.search(event["source_ip"]))
    hour = event["_ts"].hour
    event["hour"] = hour
    event["is_night"] = _flag(hour >= ind.NIGHT_START_HOUR or hour < ind.NIGHT_END_HOUR)
    octets = event["source_ip"].split(".")
    event["country_code"] = _GEO.get(".".join(octets[:2]), "")
    return event


# --- output ------------------------------------------------------------------

def clickhouse_time(dt):
    """DateTime64(3) text that ClickHouse parses with its default settings."""
    return dt.strftime("%Y-%m-%d %H:%M:%S.") + f"{dt.microsecond // 1000:03d}"


def rejected_row(reason, schema_id, raw, topic, partition, offset, kafka_ts):
    """A dead-letter row (rejected_events), raw bytes kept as base64."""
    return {
        "reject_reason": reason,
        "schema_id": None if reason == "not_avro_framed" else schema_id,
        "raw_value": base64.b64encode(raw or b"").decode("ascii"),
        "kafka_topic": topic,
        "kafka_partition": partition,
        "kafka_offset": offset,
        "kafka_timestamp": clickhouse_time(kafka_ts),
    }
