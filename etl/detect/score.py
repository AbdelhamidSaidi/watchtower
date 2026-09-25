"""
Detection: deterministic rules + LLM -> one decision per event.

    rules  (detect/rules.py)        -> rule_score, rule_hits
    LLM    (detect/llm_detector.py) -> llm_score, llm_reason     [grey zone only]

    final_anomaly_score = max(rule_score, llm_score)
    is_suspicious       = final >= SUSPICIOUS_THRESHOLD
    recommended_action  = block | alert | allow

MAX, NOT AVERAGE. A rule hit is a specific, known-bad pattern; averaging it
with an LLM that found nothing would water a SQL injection down to "maybe".
Either source being sure is enough.

WHAT REACHES THE LLM. Events the rules already settle at block level are not
sent: a SQL-injection flood is unambiguous, and paying per request to have a
model agree buys nothing. Those rows carry llm_reason='skipped:rule_decided'.
The API budget is spent on what the rules cannot settle.

WITHOUT A KEY. Rules still run -- signature and volumetric attacks are still
blocked. Only the grey-zone judgement and the written explanation are lost.

Scoring runs on the DRIVER, inside foreachBatch: the Groq detector holds a
rate limiter and a verdict cache that only work if there is exactly one.
"""

from detect.llm_detector import GroqDetector, api_key_present
from detect.rules import BLOCK_THRESHOLD, SUSPICIOUS_THRESHOLD, action_for, apply_rules


def _combine(pdf):
    final = pdf[["rule_score", "llm_score"]].max(axis=1)
    pdf["final_anomaly_score"] = final.astype("float32")
    pdf["is_suspicious"] = (final >= SUSPICIOUS_THRESHOLD).astype("int32")
    pdf["recommended_action"] = final.map(action_for)
    return pdf


def make_scorer(llm=None):
    """A pandas-frame scorer for the sink. llm=None means rules only."""

    def score(pdf):
        pdf = pdf.copy()
        pdf["rule_score"], pdf["rule_hits"] = apply_rules(pdf)
        pdf["llm_score"] = 0.0
        pdf["llm_model"] = llm.model if llm else ""

        decided = pdf["rule_score"] >= BLOCK_THRESHOLD
        pdf["llm_reason"] = "skipped:rule_decided"

        if llm is None:
            pdf.loc[~decided, "llm_reason"] = "detection_disabled:no_api_key"
        elif (~decided).any():
            judged = llm.score_frame(pdf.loc[~decided])
            pdf.loc[~decided, "llm_score"] = judged["llm_score"]
            pdf.loc[~decided, "llm_reason"] = judged["llm_reason"]

        return _combine(pdf)

    return score


def get_scorer():
    """The scorer the sink should use: rules always, the LLM if keyed."""
    if not api_key_present():
        print(
            "[detect] GROQ_API_KEY not set -- rules only. Signature and volumetric "
            "attacks are still blocked; grey-zone judgement is off.",
            flush=True,
        )
        return make_scorer(llm=None)

    detector = GroqDetector()
    print(f"[detect] rules + groq detection enabled, model={detector.model}", flush=True)
    return make_scorer(llm=detector)
