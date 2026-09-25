"""Wire format: the 5-byte Confluent header. Pure Python, no Spark."""

import pytest

from schemas.registry import HEADER_SIZE, frame, load_local_schema, unframe


def test_frame_roundtrip():
    framed = frame(42, b"payload")
    assert framed[:1] == b"\x00"
    assert unframe(framed) == (42, b"payload")


def test_header_is_five_bytes():
    assert len(frame(1, b"")) == HEADER_SIZE


def test_schema_id_is_big_endian():
    assert frame(258, b"")[1:5] == b"\x00\x00\x01\x02"


def test_json_message_is_not_framed():
    # An old producer's JSON starts with '{' (0x7B), not the 0x00 magic byte.
    with pytest.raises(ValueError, match="magic byte"):
        unframe(b'{"event_id": "x"}')


def test_too_short_is_rejected():
    with pytest.raises(ValueError, match="too short"):
        unframe(b"\x00\x00")


def test_local_schema_declares_ground_truth_as_optional():
    import json

    fields = {f["name"]: f for f in json.loads(load_local_schema())["fields"]}
    # scenario must default to null, or removing it later breaks compatibility
    assert fields["scenario"]["default"] is None


def test_read_timeout_becomes_a_retryable_registry_error(monkeypatch):
    """A timeout while reading the response is not a URLError. It must still
    surface as a RegistryError, or it escapes every caller's retry loop --
    which is how a fresh registry crashed schema registration."""
    import urllib.request

    from schemas.registry import RegistryError, SchemaRegistry

    def timeout(*_args, **_kwargs):
        raise TimeoutError("timed out")

    monkeypatch.setattr(urllib.request, "urlopen", timeout)

    with pytest.raises(RegistryError) as caught:
        SchemaRegistry("http://registry:8081").all_versions("security-logs-value")
    assert caught.value.transient


def test_client_errors_are_not_retried():
    from schemas.registry import RegistryError

    assert not RegistryError("incompatible", status=409).transient
    assert RegistryError("server error", status=503).transient
