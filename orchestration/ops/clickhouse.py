"""ClickHouse over HTTP for the DAGs. Stdlib only.

Connection settings are the pipeline's own (etl/config.py): the same
CLICKHOUSE_* variables, and the password from CLICKHOUSE_PASSWORD_FILE --
a mounted secret, never an environment variable.

Values reach SQL as ClickHouse query parameters ({name:Type} in the text,
param_name on the wire), never by string formatting.
"""

import base64
import json
import urllib.error
import urllib.parse
import urllib.request

from etl import config


class ClickHouseError(RuntimeError):
    pass


class ClickHouse:
    def __init__(self, url=None, user=None, password=None, timeout=3600):
        self.url = url or f"http://{config.CLICKHOUSE_HOST}:{config.CLICKHOUSE_PORT}"
        self.user = user or config.CLICKHOUSE_USER
        self.password = config.clickhouse_password() if password is None else password
        # OPTIMIZE ... FINAL on a day's partition waits for the merge.
        self.timeout = timeout

    def _post(self, sql, params=None, body=b"", settings=None):
        args = {"query": sql}
        args.update({f"param_{k}": str(v) for k, v in (params or {}).items()})
        args.update(settings or {})
        token = base64.b64encode(f"{self.user}:{self.password}".encode()).decode()
        request = urllib.request.Request(
            f"{self.url}/?{urllib.parse.urlencode(args)}", data=body, method="POST",
            headers={"Authorization": f"Basic {token}"},
        )
        try:
            return urllib.request.urlopen(request, timeout=self.timeout).read().decode()
        except urllib.error.HTTPError as exc:
            raise ClickHouseError(exc.read().decode(errors="replace")[:2000]) from None

    def rows(self, sql, **params):
        """The result as a list of dicts."""
        text = self._post(sql + " FORMAT JSONEachRow", params, settings={
            "output_format_json_quote_64bit_integers": 0,
            # NaN and infinities come back as null, not as invalid JSON.
            "output_format_json_quote_denormals": 0,
        })
        return [json.loads(line) for line in text.splitlines() if line]

    def value(self, sql, **params):
        """The first column of the first row, or None."""
        rows = self.rows(sql, **params)
        return next(iter(rows[0].values())) if rows else None

    def command(self, sql, **params):
        self._post(sql, params)

    def insert(self, table, rows):
        if not rows:
            return
        body = "\n".join(json.dumps(row, default=str) for row in rows).encode()
        self._post(f"INSERT INTO {table} FORMAT JSONEachRow", body=body,
                   settings={"date_time_input_format": "best_effort"})
