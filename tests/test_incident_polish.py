"""Tests for the advanced incident report's section polish + fact guard.

The polish is injected (no crewai here), so these exercise the guard's honesty
discipline directly: a clean rewrite is kept, a rewrite that drops a hard fact
is reverted, the 'impact' honest-limit keywords are protected, and a polish that
RAISES degrades to deterministic instead of crashing.
"""
from panda_tdr.detections import MultiStageChain
from panda_tdr.incident_polish import guard, render_advanced_report, required_facts


def _chain():
    return MultiStageChain(
        src_ip="10.0.2.3", account="eviluser", host="HOST1",
        failure_count=12, first_failure="2026-08-22T08:37:25.000+00:00",
        success_time="2026-08-22T08:38:53.000+00:00",
        created_accounts=("backdoor",), creators=("bmleg",),
        creation_time="2026-08-22T08:39:43.000+00:00",
    )


def test_required_facts_lists_the_hard_facts():
    facts = required_facts(_chain())
    assert "10.0.2.3" in facts and "eviluser" in facts
    assert "12" in facts and "backdoor" in facts


def test_guard_keeps_polish_that_preserves_facts():
    det = "Source 10.0.2.3 compromised eviluser after 12 attempts; made backdoor."
    polished = "After 12 tries, 10.0.2.3 cracked eviluser and created backdoor."
    assert guard("executive_summary", det, polished, required_facts(_chain())) is polished


def test_guard_reverts_polish_that_drops_a_fact():
    det = "Source 10.0.2.3 compromised eviluser after 12 attempts."
    polished = "An attacker compromised the account."  # facts gone
    assert guard("executive_summary", det, polished, required_facts(_chain())) == det


def test_guard_protects_impact_honest_limit_keywords():
    det = "No evidence of lateral movement or exfiltration was found."
    polished = "The blast radius is contained."  # drops the honest-limit words
    assert guard("impact", det, polished, required_facts(_chain())) == det


def test_render_advanced_deterministic_when_no_polisher():
    text, npol, nrev = render_advanced_report(_chain(), section_polisher=None)
    assert npol == 0 and nrev == 0
    assert "MITRE" in text and "10.0.2.3" in text     # full technical report


def test_render_advanced_keeps_clean_polish():
    text, npol, nrev = render_advanced_report(_chain(), lambda s: "POLISHED " + s)
    assert npol == 2 and nrev == 0                     # both PROSE_SECTIONS kept
    assert text.count("POLISHED ") == 2


def test_render_advanced_reverts_fact_dropping_polish():
    text, npol, nrev = render_advanced_report(_chain(), lambda s: "reworded, no facts")
    assert npol == 0 and nrev == 2
    assert "reworded" not in text and "10.0.2.3" in text


def test_render_advanced_survives_a_raising_polish():
    def boom(_s):
        raise RuntimeError("API down")
    text, npol, nrev = render_advanced_report(_chain(), boom)
    assert npol == 0 and nrev == 2
    assert "10.0.2.3" in text                          # deterministic, no crash
