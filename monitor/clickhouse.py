"""ClickHouse over HTTP, read-only and capped. Stdlib only.

The same shape as orchestration/ops/clickhouse.py, with what an auditor
needs on top: every query runs with readonly=2 and a memory and time cap --
the monitor must never be what tips a 4 GB VM over -- and the SQL travels in
the POST body. Values reach SQL as query parameters ({name:Type} in the
text), never by string formatting: event ids come from log sources.
"""

import base64
import json
import urllib.error
import urllib.parse
import urllib.request

SETTINGS = {
    # 2, not 1: nothing can be written, but the caps below may still be set.
    "readonly": "2",
    "max_memory_usage": str(256 * 1024 * 1024),
    "max_execution_time": "20",
    "output_format_json_quote_64bit_integers": "0",
    # NaN and infinities come back as null, not as invalid JSON.
    "output_format_json_quote_denormals": "0",
}


class ClickHouseError(RuntimeError):
    pass


def param(value):
    """A query parameter in ClickHouse's text format; lists become arrays."""
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(
            "'" + v.replace("\\", "\\\\").replace("'", "\\'") + "'" if isinstance(v, str) else str(v)
            for v in value
        ) + "]"
    return str(value)


class ClickHouse:
    def __init__(self, url, user, password, timeout=30):
        self.url, self.timeout = url.rstrip("/"), timeout
        self._auth = "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()

    def rows(self, sql, **params):
        """The result as a list of dicts."""
        args = dict(SETTINGS)
        args.update({f"param_{k}": param(v) for k, v in params.items()})
        request = urllib.request.Request(
            f"{self.url}/?{urllib.parse.urlencode(args)}",
            data=(sql + "\nFORMAT JSONEachRow").encode(), method="POST",
            headers={"Authorization": self._auth},
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                text = response.read().decode()
        except urllib.error.HTTPError as exc:
            raise ClickHouseError(exc.read().decode(errors="replace")[:500]) from None
        return [json.loads(line) for line in text.splitlines() if line]

    def row(self, sql, **params):
        """The first row, or None."""
        rows = self.rows(sql, **params)
        return rows[0] if rows else None
