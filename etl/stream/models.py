"""The active ML model, for the Flink job: fetched from ClickHouse, compiled,
and swapped in when training promotes a new one.

Airflow writes models to watchtower.ml_models and promotes one by inserting
into watchtower.ml_model_active (orchestration/ops/training.py). The job
asks every POLL_MS which version is active -- one tiny query -- and fetches
and compiles the model only when that version changes. Any failure keeps
the model it has: a ClickHouse outage must never stop detection, and until
a first model exists the job scores with rules alone.
"""

import base64
import json
import os
import sys
import urllib.parse
import urllib.request

import config
from core.ml import Model

POLL_MS = int(os.getenv("WATCHTOWER_MODEL_POLL_SECONDS", "300")) * 1000
# The kill switch: "off" scores with rules alone, whatever is promoted.
ENABLED = os.getenv("WATCHTOWER_ML", "on").lower() != "off"


def _clickhouse(sql, **params):
    args = {"query": sql, **{f"param_{k}": v for k, v in params.items()}}
    token = base64.b64encode(f"{config.CLICKHOUSE_USER}:{config.clickhouse_password()}".encode()).decode()
    request = urllib.request.Request(
        f"http://{config.CLICKHOUSE_HOST}:{config.CLICKHOUSE_PORT}/?{urllib.parse.urlencode(args)}",
        headers={"Authorization": f"Basic {token}"},
    )
    with urllib.request.urlopen(request, timeout=10) as response:
        return response.read().decode()


class ModelSource:
    def __init__(self, fetch=_clickhouse, enabled=None):
        self.fetch = fetch
        self.enabled = ENABLED if enabled is None else enabled
        self.model = None
        self.checked_at = None

    def active_version(self):
        return self.fetch("SELECT version FROM watchtower.ml_model_active "
                          "ORDER BY activated_at DESC LIMIT 1 FORMAT TSVRaw").strip() or None

    def refresh(self, now_ms):
        """The model to score with. Checks for a new one at most every POLL_MS."""
        if not self.enabled:
            return None
        if self.checked_at is not None and now_ms - self.checked_at < POLL_MS:
            return self.model
        self.checked_at = now_ms
        try:
            version = self.active_version()
            if version and (self.model is None or self.model.version != version):
                text = self.fetch("SELECT model FROM watchtower.ml_models WHERE version = {v:String} "
                                  "LIMIT 1 FORMAT TSVRaw", v=version)
                self.model = Model(json.loads(text), version)
                print(f"[models] now scoring with {version} ({self.model.trees} trees)", file=sys.stderr)
        except Exception as exc:
            print(f"[models] kept {self.model.version if self.model else 'rules only'}: {exc}",
                  file=sys.stderr)
        return self.model
