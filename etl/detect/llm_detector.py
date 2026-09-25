"""
LLM-based detection via the Groq API.

An LLM is asked directly whether a behaviour pattern looks malicious, and
its verdict fills the score columns. Nothing is fitted or trained.

WHY THIS IS NOT ONE API CALL PER EVENT
--------------------------------------
At 100 events/sec that is 6,000 calls/minute. No rate limit survives it,
and the stream would block on network latency. Three things make it work:

    1. TRIAGE     a cheap deterministic gate picks candidates. Measured
                  on 59k labelled events: 5.7% reach the API, and only
                  0.1% of BENIGN traffic does.
    2. BATCH      all candidates in a micro-batch go in ONE call.
    3. CACHE      an attacking IP emits hundreds of near-identical rows.
                  Behaviour is bucketed into a signature and the verdict is
                  reused for TTL seconds.

Measured recall ceiling: 92.7% of attack events reach the API. The gate
cannot decide anything -- it only decides what is worth asking about -- but
whatever it filters out can never be flagged, so it, not the prompt, sets
the detection ceiling. See NOTE_TO_SOC_ANALYST.md.

FAIL-OPEN
---------
Any API failure scores 0 with an explicit reason, and the stream keeps
running. That means an outage looks exactly like a quiet network. Alert on
llm_reason LIKE 'llm_error%' -- it is the only signal that detection has
silently stopped.

The API key is resolved by config.read_secret("GROQ_API_KEY"): a mounted
secret file (GROQ_API_KEY_FILE) first. It is never logged and never stored
in the repo.
"""

import json
import os
import time

GROQ_API_KEY_ENV = "GROQ_API_KEY"

# llama-3.1-8b-instant is the default deliberately: this is a high-volume
# classification job, not a reasoning job, and latency per batch matters
# more than depth. llama-3.3-70b-versatile is available if verdict quality
# turns out to be the bottleneck.
GROQ_MODEL = os.getenv("GROQ_MODEL", "llama-3.1-8b-instant")

GROQ_TIMEOUT_SECONDS = float(os.getenv("GROQ_TIMEOUT", "20"))
GROQ_MAX_CANDIDATES_PER_CALL = int(os.getenv("GROQ_BATCH_SIZE", "25"))

# Verdict cache lifetime, seconds. An attack lasting a minute produces
# thousands of rows with near-identical behaviour; asking once is enough.
VERDICT_TTL_SECONDS = float(os.getenv("GROQ_VERDICT_TTL", "60"))

# Minimum gap between calls, a crude client-side rate limit.
MIN_SECONDS_BETWEEN_CALLS = float(os.getenv("GROQ_MIN_INTERVAL", "0.5"))

SUSPICIOUS_THRESHOLD = float(os.getenv("WATCHTOWER_THRESHOLD", "0.65"))

# --- triage gate ----------------------------------------------------------
# Any ONE of these makes an event a candidate. Tuned to be generous: the
# cost of a false candidate is a few tokens, the cost of a missed one is a
# missed detection.
# Defaults are MEASURED, not guessed: each sits just above the maximum the
# feature reaches on 55k events of labelled benign traffic from the company
# simulation. Set below those maxima, the gate fires on half of all normal
# traffic and the batching/caching design stops paying for itself.
#
#   feature               benign max    threshold
#   failed_logins_1m               9           12
#   failed_logins_5m              21           30
#   unique_ports_5m                5            6
#   unique_users_5m                5            8
#   requests_1m                  771          900
#
# Re-measure these against YOUR traffic before trusting them -- they encode
# what this simulation's automation hosts happen to do.
TRIAGE_RULES = {
    "failed_logins_1m": int(os.getenv("TRIAGE_FAILED_1M", "12")),
    "failed_logins_5m": int(os.getenv("TRIAGE_FAILED_5M", "30")),
    "unique_ports_5m": int(os.getenv("TRIAGE_PORTS_5M", "6")),
    # benign traffic never port-scans, so this one stays tight
    "port_scan_count_5m": int(os.getenv("TRIAGE_SCANS_5M", "4")),
    "unique_users_5m": int(os.getenv("TRIAGE_USERS_5M", "8")),
    "requests_1m": int(os.getenv("TRIAGE_REQUESTS_1M", "900")),
    # v2 -- below the rules' block thresholds on purpose: the rules settle
    # the obvious cases, these send the ambiguous ones for judgement.
    "http_404_1m": int(os.getenv("TRIAGE_404_1M", "10")),
    "http_errors_5m": int(os.getenv("TRIAGE_HTTP_ERRORS_5M", "30")),
    "sensitive_commands_5m": int(os.getenv("TRIAGE_SENSITIVE_CMDS_5M", "1")),
    "bytes_sent_5m": int(os.getenv("TRIAGE_BYTES_5M", str(50_000_000))),
}

# DELIBERATELY ABSENT: commands_executed_5m.
#
# Measured on labelled data, privilege escalation peaks at 144 commands in
# 5 minutes while the CI runners and backup jobs legitimately reach 1762.
# No threshold separates them, so a rule here would either miss the attack
# entirely or flag automation constantly. Catching this needs a feature
# describing WHAT was run, not how much -- see NOTE_TO_SOC_ANALYST.md.

FEATURE_COLUMNS = [
    "requests_1m",
    "failed_logins_1m",
    "failed_logins_5m",
    "unique_users_5m",
    "port_scan_count_5m",
    "unique_ports_5m",
    "commands_executed_5m",
    "login_frequency",
    "is_internal_ip",
    "is_night",
]

SYSTEM_PROMPT = """You are a security triage assistant for a SOC.

You receive one line per candidate: what one source IP has been doing over \
the last 1-5 minutes, plus the event that made it a candidate -- the HTTP \
request (method, path, status, user agent), or the command and the uid it \
ran as, and any deterministic rules it already matched.

For each candidate, decide how likely it is that this represents an attack.

Judge on behaviour, not on any single field:
- many failed logins against one account -> brute force
- failed logins across many accounts -> password spraying
- many distinct ports touched -> port scanning
- a successful login right after many failures -> possible compromise
- high volume from an external IP at night -> more suspicious than the same \
from an internal IP during work hours
- injection or traversal payloads in a URL, or a scanner's user agent -> attack
- reading /etc/shadow or ~/.ssh, adding users, clearing history -> compromise
- a normal browser pulling hundreds of MB from an export endpoint -> exfiltration

Legitimate activity can also look busy. Backup jobs, monitoring agents, CI \
runners and misconfigured clients all produce high volume without being \
attacks, and the backup job legitimately runs as root. Do not flag volume, \
404s, or uid 0 alone.

Reply with ONLY a JSON object, no prose, in exactly this form:

{"verdicts": [{"id": "<candidate id>", "score": <0.0-1.0>, \
"reason": "<max 15 words>"}]}

score 0.0 = certainly benign, 1.0 = certainly an attack. Include every \
candidate id you were given, exactly once."""


def _api_key():
    from config import read_secret

    return read_secret(GROQ_API_KEY_ENV)


def api_key_present():
    return bool(_api_key())


def _bucket(value, edges):
    """Coarse binning so near-identical behaviour shares a cache entry."""
    for index, edge in enumerate(edges):
        if value <= edge:
            return index
    return len(edges)


def signature(row):
    """Stable key for 'this IP behaving roughly like this'."""
    return (
        row.get("source_ip", ""),
        _bucket(row.get("failed_logins_1m", 0) or 0, [0, 2, 5, 10, 25, 50]),
        _bucket(row.get("failed_logins_5m", 0) or 0, [0, 5, 15, 40, 100, 250]),
        _bucket(row.get("unique_ports_5m", 0) or 0, [0, 2, 5, 10, 20]),
        _bucket(row.get("port_scan_count_5m", 0) or 0, [0, 3, 10, 30, 80]),
        _bucket(row.get("unique_users_5m", 0) or 0, [0, 2, 4, 6]),
        _bucket(row.get("requests_1m", 0) or 0, [0, 50, 150, 300, 600]),
        int(row.get("is_internal_ip", 0) or 0),
        int(row.get("is_night", 0) or 0),
        # The event's own nature. Without these a SQL-injection request would
        # share a cached verdict with a normal page load from the same IP.
        row.get("event_type", ""),
        row.get("request_signature", ""),
        int(row.get("is_scanner_agent", 0) or 0),
        int(row.get("is_sensitive_command", 0) or 0),
        int(row.get("is_privileged", 0) or 0),
        _bucket(row.get("http_404_1m", 0) or 0, [0, 5, 10, 30, 100]),
        _bucket((row.get("bytes_sent_5m", 0) or 0) / 1e6, [1, 10, 50, 250, 1000]),
    )


def is_candidate(row):
    """Cheap deterministic gate. True -> worth asking the LLM about."""
    # A rule already fired but below block level: exactly the grey zone the
    # LLM exists for (rows at block level never reach this function).
    if row.get("rule_hits"):
        return True
    for column, threshold in TRIAGE_RULES.items():
        value = row.get(column) or 0
        if value >= threshold:
            return True
    return False


def _event_context(row):
    """The concrete event, in a few words: what makes it this event."""
    kind = row.get("event_type", "")
    if kind == "HTTP_REQUEST":
        agent = (row.get("user_agent") or "")[:60]
        return (f"{row.get('http_method', '')} {(row.get('url_path') or '')[:120]} -> "
                f"{int(row.get('http_status') or 0)}, "
                f"{int(row.get('bytes_sent') or 0):,} bytes, agent '{agent}'")
    if kind == "COMMAND_EXECUTION":
        return (f"ran `{(row.get('command') or '')[:100]}` as uid "
                f"{int(row.get('process_uid', -1))} (parent {row.get('parent_process') or '?'})")
    if kind == "FILE_ACCESS":
        return (f"{row.get('file_operation') or 'accessed'} {row.get('file_path') or '?'} "
                f"as uid {int(row.get('process_uid', -1))}")
    if kind in ("LOGIN_SUCCESS", "LOGIN_FAILURE"):
        outcome = "succeeded" if kind == "LOGIN_SUCCESS" else "failed"
        return (f"{row.get('auth_method') or '?'} login as '{row.get('user')}' {outcome} "
                f"to {row.get('dest_ip') or '?'}")
    return f"{kind} to {row.get('dest_ip') or '?'}:{int(row.get('dest_port') or 0)}"


def describe(row):
    """Compact natural description. Cheaper in tokens than raw JSON."""
    where = "internal" if row.get("is_internal_ip") else "external"
    when = "night" if row.get("is_night") else "working hours"

    text = (
        f"{where} IP {row.get('source_ip')}, {when}: "
        f"{int(row.get('requests_1m') or 0)} events/min, "
        f"{int(row.get('failed_logins_1m') or 0)} failed logins/min, "
        f"{int(row.get('failed_logins_5m') or 0)} failed logins/5min, "
        f"{int(row.get('unique_users_5m') or 0)} distinct accounts, "
        f"{int(row.get('port_scan_count_5m') or 0)} port scans, "
        f"{int(row.get('unique_ports_5m') or 0)} distinct ports, "
        f"{int(row.get('commands_executed_5m') or 0)} commands run, "
        f"{int(row.get('http_404_1m') or 0)} 404s/min, "
        f"{(row.get('bytes_sent_5m') or 0) / 1e6:.0f} MB sent/5min. "
        f"Event: {_event_context(row)}"
    )
    if row.get("rule_hits"):
        text += f". Rules matched: {row['rule_hits']}"
    return text


class GroqDetector:
    """Batched, cached, rate-limited Groq scoring. Safe to reuse."""

    def __init__(self, model=GROQ_MODEL, threshold=SUSPICIOUS_THRESHOLD):
        self.model = model
        self.threshold = threshold
        self._client = None
        self._cache = {}
        self._last_call = 0.0
        self.calls_made = 0
        self.cache_hits = 0

    def _get_client(self):
        if self._client is None:
            from groq import Groq

            self._client = Groq(
                api_key=_api_key(),
                timeout=GROQ_TIMEOUT_SECONDS,
            )
        return self._client

    def _cached(self, sig):
        entry = self._cache.get(sig)
        if entry is None:
            return None

        verdict, stored_at = entry
        if time.time() - stored_at > VERDICT_TTL_SECONDS:
            del self._cache[sig]
            return None

        self.cache_hits += 1
        return verdict

    def _throttle(self):
        gap = time.time() - self._last_call
        if gap < MIN_SECONDS_BETWEEN_CALLS:
            time.sleep(MIN_SECONDS_BETWEEN_CALLS - gap)

    def _ask(self, candidates):
        """One API call for up to GROQ_MAX_CANDIDATES_PER_CALL candidates.

        Returns {id: (score, reason)}. On ANY failure returns error verdicts
        rather than raising -- the stream must not die because an API is
        having a bad day.
        """
        lines = [f'{cid}: {text}' for cid, text in candidates]
        user_prompt = "Candidates:\n" + "\n".join(lines)

        try:
            self._throttle()
            self._last_call = time.time()
            self.calls_made += 1

            response = self._get_client().chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": user_prompt},
                ],
                temperature=0,
                response_format={"type": "json_object"},
            )

            payload = json.loads(response.choices[0].message.content)

            out = {}
            for verdict in payload.get("verdicts", []):
                cid = str(verdict.get("id"))
                try:
                    score = float(verdict.get("score", 0.0))
                except (TypeError, ValueError):
                    score = 0.0
                score = min(max(score, 0.0), 1.0)
                out[cid] = (score, str(verdict.get("reason", ""))[:200])

            # A candidate the model silently dropped must not inherit
            # another's verdict.
            for cid, _ in candidates:
                out.setdefault(cid, (0.0, "llm_error:no_verdict_returned"))

            return out

        except Exception as exc:
            kind = type(exc).__name__
            print(f"[detect] groq call failed ({kind}): {exc}", flush=True)
            return {cid: (0.0, f"llm_error:{kind}") for cid, _ in candidates}

    def score_frame(self, pdf):
        """Add llm_score / llm_reason / llm_model.

        Input and output are the same pandas frame, one row in, one row out.
        """
        pdf = pdf.copy()

        scores = [0.0] * len(pdf)
        reasons = ["below_triage_threshold"] * len(pdf)

        rows = pdf.to_dict("records")

        # Group candidate rows by behavioural signature so identical
        # behaviour is asked about once.
        pending = {}
        row_signature = {}

        for index, row in enumerate(rows):
            if not is_candidate(row):
                continue

            sig = signature(row)
            row_signature[index] = sig

            hit = self._cached(sig)
            if hit is not None:
                scores[index], reasons[index] = hit
                continue

            pending.setdefault(sig, describe(row))

        if pending and not api_key_present():
            for index, sig in row_signature.items():
                if sig in pending:
                    scores[index] = 0.0
                    reasons[index] = "llm_error:no_api_key"
            pending = {}

        if pending:
            sig_list = list(pending.items())
            id_to_sig = {}
            batch = []

            for number, (sig, text) in enumerate(sig_list):
                cid = f"c{number}"
                id_to_sig[cid] = sig
                batch.append((cid, text))

            verdicts = {}
            for start in range(0, len(batch), GROQ_MAX_CANDIDATES_PER_CALL):
                chunk = batch[start : start + GROQ_MAX_CANDIDATES_PER_CALL]
                verdicts.update(self._ask(chunk))

            fresh = {}
            now = time.time()
            for cid, verdict in verdicts.items():
                sig = id_to_sig.get(cid)
                if sig is None:
                    continue
                fresh[sig] = verdict
                # Never cache a failure. A transient API error would otherwise
                # lock every IP in this batch out of detection for the whole
                # TTL, long after the API recovered.
                if not verdict[1].startswith("llm_error"):
                    self._cache[sig] = (verdict, now)

            # Rows are filled from THIS batch's verdicts directly, not read
            # back through the cache -- errors are deliberately absent from it.
            for index, sig in row_signature.items():
                if sig in fresh:
                    scores[index], reasons[index] = fresh[sig]

        pdf["llm_score"] = [float(s) for s in scores]
        pdf["llm_reason"] = reasons
        pdf["llm_model"] = self.model

        # The LLM's opinion only. detect/score.py combines it with the
        # deterministic rules into the final score and action.
        return pdf
