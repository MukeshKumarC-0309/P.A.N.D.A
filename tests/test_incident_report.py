"""Unit tests for the incident report generator (Phase 2.6).

Covers the two audience modes: the technical (advanced) report keeps the facts
and MITRE mapping; the plain-language (normal) report is deterministic, jargon-
free, and preserves the honest "not confirmed" caveat. No LLM is involved here —
these test the deterministic layer only.
"""
from panda_tdr.detections import MultiStageChain
from panda_tdr.incident_report import render_incident_report


def _chain():
    return MultiStageChain(
        src_ip="10.0.0.3", account="eviluser", host="HOST1",
        failure_count=12, first_failure="2026-08-22T08:37:25.000+00:00",
        success_time="2026-08-22T08:38:53.000+00:00",
        created_accounts=("backdoor",), creators=("bmleg",),
        creation_time="2026-08-22T08:39:43.000+00:00",
    )


def test_advanced_report_carries_facts_and_mitre():
    r = render_incident_report(_chain(), mode="advanced")
    for token in ("10.0.0.3", "eviluser", "backdoor", "T1110", "T1136", "MITRE"):
        assert token in r


def test_normal_report_is_deterministic():
    # no LLM in normal mode -> byte-identical across runs
    assert render_incident_report(_chain(), mode="normal") == render_incident_report(_chain(), mode="normal")


def test_normal_report_is_plain_but_keeps_facts_and_caveat():
    r = render_incident_report(_chain(), mode="normal")
    assert "MITRE" not in r and "T1110" not in r          # no jargon
    assert "10.0.0.3" in r and "backdoor" in r            # facts preserved
    assert "cannot rule it out" in r                      # honest caveat survives


def test_modes_produce_different_output():
    assert render_incident_report(_chain(), mode="normal") != render_incident_report(_chain(), mode="advanced")
