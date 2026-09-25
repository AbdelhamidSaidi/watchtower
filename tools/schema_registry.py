"""
Schema Registry CLI -- the only path by which a schema reaches the registry.

    python tools/schema_registry.py check      # CI gate: is the local schema compatible?
    python tools/schema_registry.py register   # set BACKWARD compat, register the local schema
    python tools/schema_registry.py show       # list registered versions

Producers never register their own schema. If they did, a producer deploy
could change the wire format with nothing reviewing it -- which is exactly
the silent breakage the registry exists to prevent.

Exit codes: 0 ok, 1 incompatible or refused, 2 registry unreachable.
"""

import argparse
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from schemas.registry import (  # noqa: E402
    DEFAULT_COMPATIBILITY,
    DEFAULT_SUBJECT,
    RegistryError,
    SchemaRegistry,
    load_local_schema,
)


def cmd_check(registry, subject, schema):
    ok, messages = registry.is_compatible(subject, schema)
    if ok:
        print(f"compatible with latest {subject} ({'; '.join(messages) or 'ok'})")
        return 0
    print(f"INCOMPATIBLE with latest {subject}:")
    for message in messages:
        print(f"  - {message}")
    return 1


def cmd_register(registry, subject, schema):
    # Always pinned at SUBJECT level. Registries differ in what a bare
    # GET /config/{subject} returns when only a global default exists, and a
    # later change to that global default must not loosen this subject.
    registry.set_compatibility(subject, DEFAULT_COMPATIBILITY)
    print(f"compatibility for {subject}: {DEFAULT_COMPATIBILITY} (subject-level)")

    existing = registry.lookup_id(subject, schema)
    if existing is not None:
        print(f"already registered: {subject} id={existing}")
        return 0

    try:
        schema_id = registry.register(subject, schema)
    except RegistryError as exc:
        if exc.status == 409:
            print(f"REFUSED by registry (incompatible): {exc}")
            return 1
        raise

    print(f"registered: {subject} id={schema_id}")
    return 0


def cmd_show(registry, subject, _schema):
    versions = registry.all_versions(subject)
    print(f"{subject}: {len(versions)} version(s), compatibility={registry.get_compatibility(subject)}")
    for schema_id in sorted(versions):
        print(f"  id={schema_id}")
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    parser.add_argument("command", choices=["check", "register", "show"])
    parser.add_argument("--url", default=os.getenv("SCHEMA_REGISTRY_URL", "http://localhost:8081"))
    parser.add_argument("--subject", default=DEFAULT_SUBJECT)
    parser.add_argument("--schema-file", default=None)
    parser.add_argument(
        "--wait", type=int, default=180,
        help="seconds to keep retrying while the registry is not ready (default 180)",
    )
    args = parser.parse_args()

    registry = SchemaRegistry(args.url)
    schema = load_local_schema(args.schema_file) if args.schema_file else load_local_schema()
    handler = {"check": cmd_check, "register": cmd_register, "show": cmd_show}[args.command]

    # Retry transient failures. A registry that just started answers reads
    # (and so passes a healthcheck) before it can accept writes; the first
    # registration attempt can time out even though the service is "up".
    deadline = time.time() + args.wait
    while True:
        try:
            return handler(registry, args.subject, schema)
        except RegistryError as exc:
            if not exc.transient or time.time() >= deadline:
                print(f"registry error: {exc}")
                return 2
            print(f"registry not ready ({exc}); retrying...", flush=True)
            time.sleep(5)


if __name__ == "__main__":
    raise SystemExit(main())
