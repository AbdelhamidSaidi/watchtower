"""A second opinion on the pipeline's decisions: the Groq reviewer.

Hourly, for the closed hour, a sample of events goes to an LLM that judges
each one with its context. Where it disagrees confidently, its verdict
becomes a training label (orchestration/ops/training.py) -- and that starts
a retraining, so the model learns from its mistakes within the hour.

It learns in both directions:
    near_miss    passed (ok), with the highest model scores: just under the line
    unusual      passed, but extreme for the hour on a behaviour feature
    random       passed, a uniform sample: misses nothing else would find,
                 and an honest estimate of the miss rate
                 -> judged degraded/incident: a missed incident, label 1
    model_alert  alerted by the MODEL alone (no rule fired)
                 -> judged normal: the model's false alarm, label 0
Rule decisions are not reviewed: they are explicit and tuned by hand.

Capped per run and per day, so cost is bounded whatever the traffic does.
security_events is never rewritten: verdicts go to watchtower.event_reviews
beside it; disagreements show in watchtower.label_changes.
"""

import json
import os
import time
import urllib.error
import urllib.request
from collections import deque

from etl import config
from orchestration.ops import training

GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"
# A classifier built to judge content against a policy you give it (the
# system prompt below): a few thousand judgements a day, where reasoning
# matters. Override with GROQ_MODEL.
GROQ_MODEL = os.getenv("GROQ_MODEL", "openai/gpt-oss-safeguard-20b")
REASONING_EFFORT = os.getenv("GROQ_REASONING_EFFORT", "medium")
# The account's tokens-per-minute limit (Groq's free tier: 8,000 for this
# model). Requests are paginated to stay under it -- see TokenBudget.
TOKENS_PER_MINUTE = int(os.getenv("GROQ_TOKENS_PER_MINUTE", "8000"))
# What one page may cost at most: prompt + the longest answer allowed.
# Half the minute, so two pages fit in it.
PAGE_TOKENS = TOKENS_PER_MINUTE // 2
# The answer's allowance grows with the page: reasoning, then ~40 tokens of
# JSON per event. Reasoning tokens count against it, before the answer.
COMPLETION_BASE, COMPLETION_PER_EVENT = 600, 150
BATCH = 10                      # at most this many events per page
PER_RUN = {"near_miss": 50, "unusual": 50, "random": 30, "model_alert": 20}
PER_DAY = 3_000
# Confident enough to become a training label (training.REVIEW_MIN_CONFIDENCE
# is the same bar) -- and to page someone at once when it says incident.
LABEL_CONFIDENCE = training.REVIEW_MIN_CONFIDENCE
ALERT_CONFIDENCE = 0.9

BEHAVIOUR = ("failed_builds_5m", "unique_projects_5m", "oom_kills_5m", "slow_steps_5m",
             "dependency_404_1m", "rogue_commands_5m", "failure_signatures_5m", "published_bytes_5m")

SYSTEM_PROMPT = """You are a build-infrastructure engineer reviewing an automated detector's \
decisions on build-farm events. Each event was either PASSED (ok), or ALERTED by the \
detector's machine-learning model with no rule behind it. For each, decide what it really is.

Each line gives the runner (internal or external, time of day), its recent behaviour \
(failed builds, distinct projects, OOM kills, slow steps, 404s on dependencies, \
published MB over 1-5 minutes), the event itself, the model's score (0-1) and the \
detector's decision.

Judge behaviour, not a single field:
- many failed builds of ONE project -> a retry loop on a broken commit: the code, not the farm
- failed builds across many projects on one runner -> a broken toolchain or full disk: the runner
- exit 137 or "Killed" repeatedly, memory pinned -> an OOM-kill storm
- compile steps taking 6+ minutes where the project's usual is seconds -> a compile-time regression
- a flood of 404s on dependency paths -> a bad lockfile or registry outage
- "checksum mismatch", a corrupt cache entry, "internal compiler error" -> infrastructure fault
- a miner, `curl ... | sh`, credentials read or sent out, a mirror nobody uses -> a rogue build step
- uploads of hundreds of MB, never failing -> runaway artifacts
Busy is not bad: the CI farm is loud and healthy, builds start and fail all day, and \
containers run as root. Do not flag volume, an ordinary compile error, a failing test or \
uid 0 alone.

Reply with ONLY a JSON object:
{"verdicts": [{"id": "<id>", "verdict": "normal|degraded|incident", \
"confidence": <0.0-1.0>, "reason": "<max 20 words>"}]}
Include every id exactly once."""


class ReviewerUnavailable(RuntimeError):
    pass


def api_key():
    return config.read_secret("GROQ_API_KEY", default=None)


# --- candidates --------------------------------------------------------------------

_COLUMNS = ("toString(event_id) AS event_id, timestamp, runner_ip, project, event_type, hostname, "
            "is_internal_ip, is_night, events_1m, failed_builds_1m, failed_builds_5m, unique_projects_5m, "
            "oom_kills_5m, distinct_exit_codes_5m, compile_steps_5m, dependency_404_1m, rogue_commands_5m, "
            "failure_signatures_5m, published_bytes_5m, slow_steps_5m, cache_misses_5m, http_method, url_path, "
            "http_status, bytes_sent, command, process_uid, parent_process, step, file_path, duration_ms, "
            "peak_memory_mb, cache_status, error_message, exit_code, reason, triggered_by, dest_ip, "
            "rule_hits, ml_score, ml_reason, ml_model, recommended_action")
_WINDOW = ("timestamp >= toDateTime64({start:String}, 3, 'UTC') "
           "AND timestamp < toDateTime64({end:String}, 3, 'UTC') "
           "AND event_id NOT IN (SELECT event_id FROM watchtower.event_reviews "
           "                     WHERE reviewed_at > now() - INTERVAL 2 DAY)")
_HOUR = _WINDOW + " AND recommended_action = 'ok'"
# Alerted by the model alone: ml_reason is set only when the model raised
# the decision, and no rule fired.
_MODEL_ALERTS = _WINDOW + " AND recommended_action = 'alert' AND ml_reason != '' AND rule_hits = ''"


def reviewed_today(ch):
    return ch.value("SELECT count() FROM watchtower.event_reviews WHERE reviewed_at >= today()") or 0


def candidates(ch, start, end, caps=None):
    """Up to caps[kind] passed events of the hour per kind, no event twice."""
    caps = dict(caps or PER_RUN)
    params = {"start": start, "end": end}
    extremes = " OR ".join(f"{f} >= q.{f}" for f in BEHAVIOUR)
    quantiles = ", ".join(f"quantile(0.999)({f}) AS {f}" for f in BEHAVIOUR)
    queries = {
        # Highest model scores that still passed.
        "near_miss": f"SELECT {_COLUMNS} FROM watchtower.security_events "
                     f"WHERE {_HOUR} AND ml_score > 0.2 ORDER BY ml_score DESC LIMIT {{n:UInt32}}",
        # Extreme for this hour on any behaviour feature (its top 0.1%).
        "unusual": f"SELECT {_COLUMNS} FROM watchtower.security_events, "
                   f"(SELECT {quantiles} FROM watchtower.security_events WHERE {_HOUR}) AS q "
                   f"WHERE {_HOUR} AND ({extremes}) AND {' + '.join(BEHAVIOUR)} > 0 "
                   f"ORDER BY cityHash64(event_id) LIMIT {{n:UInt32}}",
        # Uniform: a hash of the id, cheaper than ORDER BY rand() over an hour.
        "random": f"SELECT {_COLUMNS} FROM watchtower.security_events "
                  f"WHERE {_HOUR} AND cityHash64(event_id) % 1000 < 5 "
                  f"ORDER BY cityHash64(event_id) LIMIT {{n:UInt32}}",
        # The model's own alarms: where it is wrong, it learns to be quieter.
        "model_alert": f"SELECT {_COLUMNS} FROM watchtower.security_events "
                       f"WHERE {_MODEL_ALERTS} ORDER BY ml_score LIMIT {{n:UInt32}}",
    }
    chosen, seen = [], set()
    for kind, sql in queries.items():
        if caps.get(kind, 0) <= 0:
            continue
        for row in ch.rows(sql, n=caps[kind], **params):
            if row["event_id"] not in seen:
                seen.add(row["event_id"])
                chosen.append({**row, "why_selected": kind})
    return chosen


def budget(ch, per_day=PER_DAY):
    """PER_RUN, cut to what is left of the day's budget. The random sample
    is served first: it is what keeps the miss-rate estimate honest."""
    left = max(0, per_day - reviewed_today(ch))
    caps = {}
    for kind in ("random", "model_alert", "near_miss", "unusual"):
        caps[kind] = min(PER_RUN[kind], left)
        left -= caps[kind]
    return caps


# --- the reviewer ------------------------------------------------------------------

def describe(row):
    """One event with its context, in few tokens."""
    where = "internal" if row.get("is_internal_ip") else "external"
    when = "night" if row.get("is_night") else "working hours"
    kind = row.get("event_type", "")
    project = row.get("project") or "?"
    if kind in ("DEPENDENCY_FETCH", "ARTIFACT_PUBLISH"):
        event = (f"{row.get('http_method', '')} {(row.get('url_path') or '')[:120]} -> {row.get('http_status')}, "
                 f"{int(row.get('bytes_sent') or 0):,} bytes")
    elif kind == "COMPILE_STEP":
        event = (f"{row.get('step') or 'compile'} `{(row.get('command') or '')[:100]}` of {project} as uid "
                 f"{row.get('process_uid')} (parent {row.get('parent_process') or '?'}): exit {row.get('exit_code')}, "
                 f"{int(row.get('duration_ms') or 0) / 1000:.0f}s, {row.get('peak_memory_mb') or 0} MB, "
                 f"cache {row.get('cache_status') or '?'}")
    elif kind == "TEST_RUN":
        event = f"tests of {project}: exit {row.get('exit_code')}, {int(row.get('duration_ms') or 0) / 1000:.0f}s"
    elif kind in ("BUILD_SUCCESS", "BUILD_FAILURE"):
        outcome = "succeeded" if kind == "BUILD_SUCCESS" else f"failed ({row.get('reason') or '?'})"
        event = f"build of {project} {outcome} after {int(row.get('duration_ms') or 0) / 1000:.0f}s"
    else:
        event = f"{kind} of {project}"
    if row.get("error_message"):
        event += f", error: '{row['error_message'][:100]}'"
    text = (f"{where} runner {row['runner_ip']}, {when}: {row.get('events_1m', 0)} events/min, "
            f"{row.get('failed_builds_1m', 0)} failed builds/min, {row.get('failed_builds_5m', 0)}/5min, "
            f"{row.get('unique_projects_5m', 0)} projects, {row.get('oom_kills_5m', 0)} OOM kills, "
            f"{row.get('slow_steps_5m', 0)} slow steps, {row.get('dependency_404_1m', 0)} 404s/min, "
            f"{float(row.get('published_bytes_5m') or 0) / 1e6:.0f} MB published/5min. "
            f"Event: {event}. Model score {float(row.get('ml_score') or 0):.2f}, "
            f"decision: {row.get('recommended_action', 'ok')}")
    if row.get("rule_hits"):
        text += f", rules matched: {row['rule_hits']}"
    return text


# Groq sits behind a firewall that refuses Python's default user agent
# ("Python-urllib/3.x") with HTTP 403, error code 1010 -- before the key is
# even looked at. Any honest client name passes.
USER_AGENT = "watchtower-review/1.0"


def _post(body, key, timeout=60):
    request = urllib.request.Request(
        GROQ_URL, data=json.dumps(body).encode(), method="POST",
        headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json",
                 "User-Agent": USER_AGENT},
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.load(response)


def _retry_after(exc, attempt):
    """Seconds to wait before retrying: the server's Retry-After, else
    exponential backoff, capped at a minute."""
    try:
        return min(60.0, float(exc.headers.get("retry-after")))
    except (AttributeError, TypeError, ValueError):
        return min(60.0, 5.0 * 2 ** attempt)


def estimate_tokens(text):
    """An upper estimate: ~4 characters a token in English, counted as 3."""
    return len(text) // 3 + 1


def completion_tokens(n_events):
    return COMPLETION_BASE + COMPLETION_PER_EVENT * n_events


def _user_prompt(batch):
    return "Events:\n" + "\n".join(f"{i}: {describe(row)}" for i, row in enumerate(batch))


def page_cost(batch):
    """The most one page can cost: its prompt and its longest answer."""
    return estimate_tokens(SYSTEM_PROMPT + _user_prompt(batch)) + completion_tokens(len(batch))


def pages(rows):
    """Rows cut into pages of at most BATCH events, each costing at most
    PAGE_TOKENS (a page of one event goes through regardless)."""
    page = []
    for row in rows:
        if page and (len(page) == BATCH or page_cost(page + [row]) > PAGE_TOKENS):
            yield page
            page = []
        page.append(row)
    if page:
        yield page


class TokenBudget:
    """A sliding one-minute ledger of tokens, to stay under a
    tokens-per-minute limit: before a page goes out its worst-case cost is
    booked, and the call waits until that fits in the last 60 seconds; when
    the answer comes back the booking is corrected to what it really cost."""

    WINDOW = 60.0

    def __init__(self, per_minute, clock=time.monotonic, sleep=time.sleep, margin=0.9):
        self.limit = per_minute * margin
        self.clock, self.sleep = clock, sleep
        self.ledger = deque()               # [booked at, tokens], oldest first

    def _spent(self, now):
        while self.ledger and now - self.ledger[0][0] >= self.WINDOW:
            self.ledger.popleft()
        return sum(tokens for _, tokens in self.ledger)

    def book(self, tokens):
        tokens = min(tokens, self.limit)
        while True:
            now = self.clock()
            if self._spent(now) + tokens <= self.limit:
                entry = [now, tokens]
                self.ledger.append(entry)
                return entry
            # Wait for the oldest booking to leave the window.
            self.sleep(max(0.5, self.WINDOW - (now - self.ledger[0][0])))

    @staticmethod
    def settle(entry, actual):
        if actual:
            entry[1] = actual


def ask(batch, key, post=_post, retries=6, sleep=time.sleep):
    """{id: (verdict, confidence, reason)} for one page, and the tokens it
    used. Retries 429 and 5xx as the server asks; any id the model dropped
    is simply absent (not reviewed)."""
    body = {"model": GROQ_MODEL, "reasoning_effort": REASONING_EFFORT,
            "max_completion_tokens": completion_tokens(len(batch)), "stream": False,
            "messages": [{"role": "system", "content": SYSTEM_PROMPT},
                         {"role": "user", "content": _user_prompt(batch)}]}
    for attempt in range(retries):
        try:
            reply = post(body, key)
            break
        except urllib.error.HTTPError as exc:
            if exc.code in (429, 500, 502, 503) and attempt < retries - 1:
                sleep(_retry_after(exc, attempt))
                continue
            raise ReviewerUnavailable(f"Groq HTTP {exc.code}") from None
    verdicts = {}
    for v in _answer(reply["choices"][0]["message"]["content"]).get("verdicts", []):
        try:
            index = int(v["id"])
            verdict = str(v["verdict"]).lower()
            if verdict in ("normal", "degraded", "incident") and 0 <= index < len(batch):
                verdicts[index] = (verdict, max(0.0, min(1.0, float(v["confidence"]))), str(v.get("reason", ""))[:300])
        except (KeyError, TypeError, ValueError):
            continue
    return verdicts, int((reply.get("usage") or {}).get("total_tokens") or 0)


def _answer(content):
    """The JSON object in the model's reply. Without JSON mode a model may
    wrap it in prose or a code fence: take the outermost braces."""
    start, end = content.find("{"), content.rfind("}")
    if start < 0 or end < start:
        return {}
    try:
        return json.loads(content[start:end + 1])
    except json.JSONDecodeError:
        return {}


def review(rows, key, run_id, post=_post, sleep=time.sleep, clock=time.monotonic):
    """Event-review rows for everything the reviewer judged.

    Paginated to the tokens-per-minute limit (pages(), TokenBudget). If Groq
    still refuses mid-run, what was judged so far is returned, not thrown
    away; the rest waits for the next hour."""
    out, done = [], 0
    budget = TokenBudget(TOKENS_PER_MINUTE, clock=clock, sleep=sleep)
    for batch in pages(rows):
        booking = budget.book(page_cost(batch))
        try:
            verdicts, tokens = ask(batch, key, post, sleep=sleep)
        except ReviewerUnavailable as exc:
            print(f"[review] stopped after {done} of {len(rows)} events: {exc}")
            break
        budget.settle(booking, tokens)
        done += len(batch)
        for index, (verdict, confidence, reason) in verdicts.items():
            row = batch[index]
            out.append({
                "run_id": run_id, "event_id": row["event_id"], "event_time": row["timestamp"],
                "runner_ip": row["runner_ip"], "event_type": row["event_type"],
                "pipeline_action": row["recommended_action"], "ml_score": float(row.get("ml_score") or 0),
                "ml_model": row.get("ml_model") or "",
                "why_selected": row["why_selected"], "verdict": verdict, "confidence": confidence,
                "reason": reason, "reviewer": GROQ_MODEL,
            })
    return out


def labels_from(reviews):
    """Confident disagreements, as training labels, in both directions:
    a passed event judged degraded or incident is a missed incident (1);
    a model-only alert judged normal is a false alarm (0)."""
    labels = []
    for r in reviews:
        if r["confidence"] < LABEL_CONFIDENCE:
            continue
        if r["pipeline_action"] == "ok" and r["verdict"] != "normal":
            label = 1
        elif r["why_selected"] == "model_alert" and r["verdict"] == "normal":
            label = 0
        else:
            continue
        labels.append({"event_id": r["event_id"], "label": label, "source": "reviewer",
                       "weight": training.REVIEW_WEIGHT, "detail": f"{r['verdict']}: {r['reason']}"})
    return labels


def urgent(reviews):
    """Passed events the reviewer is sure were incidents: someone should
    look now, not after tomorrow's retraining."""
    return [r for r in reviews
            if r["pipeline_action"] == "ok" and r["verdict"] == "incident" and r["confidence"] >= ALERT_CONFIDENCE]
