"""Detection: triage gate, signature cache, batching and every fail-open path."""

import json
from types import SimpleNamespace

import pandas as pd
import pytest

from detect import llm_detector
from detect.llm_detector import GroqDetector, describe, is_candidate, signature

NORMAL = dict(
    source_ip="192.168.1.10", requests_1m=40, failed_logins_1m=1, failed_logins_5m=3,
    unique_users_5m=2, port_scan_count_5m=0, unique_ports_5m=0, commands_executed_5m=5,
    login_frequency=4.0, is_internal_ip=1, is_night=0,
)
BRUTE = dict(NORMAL, source_ip="45.134.26.7", failed_logins_1m=38, failed_logins_5m=180,
             unique_users_5m=1, is_internal_ip=0, is_night=1)
SCAN = dict(NORMAL, source_ip="185.23.44.12", unique_ports_5m=14, port_scan_count_5m=96,
            is_internal_ip=0)


class FakeGroq:
    """Stands in for groq.Groq: records calls, returns scripted verdicts."""

    def __init__(self, respond):
        self.respond = respond
        self.calls = []
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self._create))

    def _create(self, **kwargs):
        self.calls.append(kwargs)
        content = self.respond(kwargs["messages"][1]["content"])
        return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content=content))])


def _verdicts_for_all(score, reason="looks like an attack"):
    def respond(prompt):
        ids = [line.split(":")[0] for line in prompt.splitlines()[1:]]
        return json.dumps({"verdicts": [{"id": i, "score": score, "reason": reason} for i in ids]})
    return respond


@pytest.fixture
def key_file(tmp_path, monkeypatch):
    path = tmp_path / "groq_api_key"
    path.write_text("test-key\n")
    monkeypatch.setenv("GROQ_API_KEY_FILE", str(path))
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    monkeypatch.setattr(llm_detector, "MIN_SECONDS_BETWEEN_CALLS", 0.0)
    return path


@pytest.fixture
def no_key(monkeypatch):
    monkeypatch.delenv("GROQ_API_KEY_FILE", raising=False)
    monkeypatch.delenv("GROQ_API_KEY", raising=False)


def _detector(respond):
    detector = GroqDetector()
    detector._client = FakeGroq(respond)
    return detector


def test_triage_passes_attacks_and_holds_back_normal_traffic():
    assert not is_candidate(NORMAL)
    assert is_candidate(BRUTE)
    assert is_candidate(SCAN)


def test_near_identical_behaviour_shares_a_signature():
    assert signature(BRUTE) == signature(dict(BRUTE, failed_logins_1m=39, failed_logins_5m=185))
    assert signature(BRUTE) != signature(dict(BRUTE, failed_logins_1m=2, failed_logins_5m=4))


def test_prompt_describes_behaviour_not_log_lines():
    text = describe(BRUTE)
    assert "external IP 45.134.26.7" in text and "night" in text
    assert "38 failed logins/min" in text


def test_verdict_fills_the_score_columns(key_file):
    detector = _detector(_verdicts_for_all(0.92))
    out = detector.score_frame(pd.DataFrame([NORMAL, BRUTE]))

    normal, brute = out.to_dict("records")
    assert normal["llm_reason"] == "below_triage_threshold" and normal["llm_score"] == 0.0
    assert brute["llm_score"] == pytest.approx(0.92)
    # the final decision is detect/score.py's job, not the LLM's
    assert "recommended_action" not in out.columns


def test_every_candidate_goes_in_one_call(key_file):
    detector = _detector(_verdicts_for_all(0.8))
    detector.score_frame(pd.DataFrame([BRUTE, SCAN]))
    assert detector.calls_made == 1


def test_repeated_behaviour_hits_the_cache(key_file):
    detector = _detector(_verdicts_for_all(0.8))
    detector.score_frame(pd.DataFrame([BRUTE]))
    detector.score_frame(pd.DataFrame([dict(BRUTE, failed_logins_1m=39)]))
    assert detector.calls_made == 1
    assert detector.cache_hits >= 1


def test_api_failure_fails_open_with_a_visible_reason(key_file):
    def boom(_prompt):
        raise RuntimeError("503 from upstream")

    out = _detector(boom).score_frame(pd.DataFrame([BRUTE]))
    assert out.iloc[0]["llm_score"] == 0.0
    assert out.iloc[0]["llm_reason"] == "llm_error:RuntimeError"


def test_dropped_candidate_does_not_inherit_a_verdict(key_file):
    out = _detector(lambda _p: json.dumps({"verdicts": []})).score_frame(pd.DataFrame([BRUTE]))
    assert out.iloc[0]["llm_reason"] == "llm_error:no_verdict_returned"


def test_malformed_score_is_clamped_not_crashed(key_file):
    respond = lambda p: json.dumps({"verdicts": [{"id": "c0", "score": 7, "reason": "x"}]})  # noqa: E731
    out = _detector(respond).score_frame(pd.DataFrame([BRUTE]))
    assert out.iloc[0]["llm_score"] == 1.0


def test_missing_key_is_explicit_and_never_calls_out(no_key):
    detector = _detector(_verdicts_for_all(0.9))
    out = detector.score_frame(pd.DataFrame([BRUTE]))
    assert out.iloc[0]["llm_reason"] == "llm_error:no_api_key"
    assert detector.calls_made == 0


def test_a_failure_is_retried_next_batch_not_cached(key_file):
    """One transient error must not blind detection for the whole cache TTL."""
    state = {"fail": True}

    def flaky(prompt):
        if state["fail"]:
            raise TimeoutError("upstream timeout")
        return _verdicts_for_all(0.9)(prompt)

    detector = _detector(flaky)
    first = detector.score_frame(pd.DataFrame([BRUTE]))
    assert first.iloc[0]["llm_reason"] == "llm_error:TimeoutError"

    state["fail"] = False
    second = detector.score_frame(pd.DataFrame([BRUTE]))
    assert detector.calls_made == 2                     # asked again, not served from cache
    assert second.iloc[0]["llm_score"] == pytest.approx(0.9)


SQLI = dict(NORMAL, source_ip="193.201.9.88", is_internal_ip=0, event_type="HTTP_REQUEST",
            http_method="GET", url_path="/api/v1/products?id=42' OR '1'='1", http_status=500,
            user_agent="sqlmap/1.8.2", bytes_sent=4000, request_signature="sqli")


def test_prompt_shows_the_actual_request():
    text = describe(SQLI)
    assert "/api/v1/products?id=42' OR '1'='1" in text
    assert "sqlmap" in text and "-> 500" in text


def test_prompt_shows_the_command_and_uid():
    row = dict(NORMAL, event_type="COMMAND_EXECUTION", command="cat /etc/shadow",
               process_uid=0, parent_process="sshd")
    assert "`cat /etc/shadow` as uid 0 (parent sshd)" in describe(row)


def test_injection_never_shares_a_verdict_with_a_normal_request():
    normal_request = dict(SQLI, url_path="/dashboard", request_signature="", user_agent="Mozilla/5.0")
    assert signature(SQLI) != signature(normal_request)


def test_a_rule_hit_makes_a_row_a_candidate():
    assert is_candidate(dict(NORMAL, rule_hits="sensitive_path_probe"))
