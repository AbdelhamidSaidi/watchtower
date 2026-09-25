"""
The wire contract between producers and the pipeline.

Everything that decides whether a message can be read lives here: the Avro
schema file, the Confluent wire format, and the Schema Registry calls.
Stdlib only, so the producer, the Spark pipeline, the CLI and CI all import
the same code.

WIRE FORMAT (Confluent)
-----------------------
    byte 0      magic byte, always 0x00
    bytes 1-4   schema id, big-endian unsigned int
    bytes 5..   Avro binary, NOT self-describing

Avro binary carries no field names, so it can only be decoded with the exact
schema that wrote it. The schema id is how a reader finds that schema.

COMPATIBILITY
-------------
The subject is registered with BACKWARD compatibility: a new version must be
able to read data written by the previous one. In practice that means new
fields need a default and existing field types cannot change. The registry
enforces it -- an incompatible schema is refused with HTTP 409, which is the
whole point: a producer can no longer change the format silently.

Producers never auto-register. A schema reaches the registry only through
`tools/schema_registry.py register`, which CI runs after the compatibility
check passes.
"""

import json
import os
import struct
import urllib.error
import urllib.request

MAGIC_BYTE = 0
HEADER_SIZE = 5

DEFAULT_SUBJECT = "security-logs-value"
DEFAULT_COMPATIBILITY = "BACKWARD"

SCHEMA_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "security_event.avsc")

_CONTENT_TYPE = "application/vnd.schemaregistry.v1+json"


class RegistryError(Exception):
    """A registry call failed. Carries the registry's own error code."""

    def __init__(self, message, status=None, error_code=None):
        super().__init__(message)
        self.status = status
        self.error_code = error_code

    @property
    def transient(self):
        """Worth retrying: no answer at all, or a server-side error.

        A fresh registry answers reads before it has elected a leader for
        writes, so early writes can time out or 5xx while reads succeed.
        """
        return self.status is None or self.status >= 500


def load_local_schema(path=SCHEMA_PATH):
    """The schema as committed in the repo, as a canonical JSON string."""
    with open(path) as handle:
        return json.dumps(json.load(handle), separators=(",", ":"))


def frame(schema_id, avro_payload):
    """Prefix an Avro binary payload with the Confluent header."""
    return struct.pack(">bI", MAGIC_BYTE, schema_id) + avro_payload


def unframe(message):
    """Split a framed message into (schema_id, avro_payload).

    Raises ValueError for anything that is not Confluent-framed -- a JSON
    message from an old producer, say, starts with '{' (0x7B), not 0x00.
    """
    if len(message) < HEADER_SIZE:
        raise ValueError(f"message too short to be framed: {len(message)} bytes")

    magic, schema_id = struct.unpack(">bI", message[:HEADER_SIZE])
    if magic != MAGIC_BYTE:
        raise ValueError(f"bad magic byte {magic:#04x}, expected 0x00")

    return schema_id, message[HEADER_SIZE:]


class SchemaRegistry:
    """Minimal client for any Confluent-API-compatible registry (Karapace here)."""

    def __init__(self, url=None, timeout=30.0):
        self.url = (url or os.getenv("SCHEMA_REGISTRY_URL", "http://schema-registry:8081")).rstrip("/")
        self.timeout = timeout

    def _call(self, method, path, body=None):
        data = None if body is None else json.dumps(body).encode()
        request = urllib.request.Request(
            self.url + path,
            data=data,
            method=method,
            headers={"Content-Type": _CONTENT_TYPE, "Accept": _CONTENT_TYPE},
        )

        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                return json.loads(response.read() or b"null")
        except urllib.error.HTTPError as exc:
            try:
                detail = json.loads(exc.read())
            except Exception:
                detail = {}
            raise RegistryError(
                detail.get("message", str(exc)),
                status=exc.code,
                error_code=detail.get("error_code"),
            ) from None
        except urllib.error.URLError as exc:
            raise RegistryError(f"registry unreachable at {self.url}: {exc.reason}") from None
        except OSError as exc:
            # A timeout or reset while READING the response is not a URLError
            # -- it surfaces as a bare TimeoutError / ConnectionResetError.
            # Unwrapped, it escapes every caller's retry loop.
            raise RegistryError(f"registry at {self.url} did not answer: {exc!r}") from None

    def set_compatibility(self, subject, level=DEFAULT_COMPATIBILITY):
        return self._call("PUT", f"/config/{subject}", {"compatibility": level})

    def get_compatibility(self, subject):
        try:
            return self._call("GET", f"/config/{subject}")["compatibilityLevel"]
        except RegistryError as exc:
            if exc.status == 404:
                return None
            raise

    def register(self, subject, schema):
        """Register a version. The registry refuses (409) if incompatible."""
        return self._call("POST", f"/subjects/{subject}/versions", {"schema": schema})["id"]

    def lookup_id(self, subject, schema):
        """Id of an ALREADY-registered schema, or None. Never registers."""
        try:
            return self._call("POST", f"/subjects/{subject}", {"schema": schema})["id"]
        except RegistryError as exc:
            if exc.status == 404:
                return None
            raise

    def is_compatible(self, subject, schema):
        """(ok, messages) for `schema` against the latest registered version.

        A subject with no versions yet is trivially compatible.
        """
        try:
            result = self._call(
                "POST",
                f"/compatibility/subjects/{subject}/versions/latest?verbose=true",
                {"schema": schema},
            )
        except RegistryError as exc:
            if exc.status == 404:
                return True, ["subject has no versions yet"]
            raise

        return bool(result.get("is_compatible")), result.get("messages", [])

    def all_versions(self, subject):
        """{schema_id: schema_json} for every version of the subject.

        The pipeline decodes with ALL of them, so a producer that moves to a
        new compatible version does not strand messages written with the old
        one -- each message is decoded with the schema that actually wrote it.
        """
        versions = self._call("GET", f"/subjects/{subject}/versions")
        out = {}
        for version in versions:
            entry = self._call("GET", f"/subjects/{subject}/versions/{version}")
            out[int(entry["id"])] = entry["schema"]
        return out
