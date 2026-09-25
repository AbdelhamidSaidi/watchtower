"""Startup shared by both engines: every registered schema version."""

import time

import config
from schemas.registry import RegistryError, SchemaRegistry

REGISTRY_WAIT_SECONDS = 300


def fetch_schema_versions():
    """{schema_id: schema_json} for every registered version, with retry."""
    registry = SchemaRegistry(config.SCHEMA_REGISTRY_URL)
    deadline = time.time() + REGISTRY_WAIT_SECONDS
    last_error = None

    while time.time() < deadline:
        try:
            versions = registry.all_versions(config.SCHEMA_SUBJECT)
            if versions:
                return versions
            last_error = "subject has no versions"
        except RegistryError as exc:
            # 404 included: under Kubernetes the registration Job may simply
            # not have run yet. "Not registered" at startup usually means
            # "about to be" -- wait for it instead of crash-looping.
            last_error = str(exc)
        print(f"[startup] waiting for schema {config.SCHEMA_SUBJECT}: {last_error}", flush=True)
        time.sleep(5)

    print(
        f"FATAL: no schema for subject {config.SCHEMA_SUBJECT} at "
        f"{config.SCHEMA_REGISTRY_URL} ({last_error}).\n"
        f"Register it first:  python tools/schema_registry.py register",
        flush=True,
    )
    raise SystemExit(2)
