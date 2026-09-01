"""
Case store tests (panda.cases + the cases/detections/reports schema).

Verify that a TDR run can persist a case with detections and reports,
that the vault reads them back and filters them, that ids link up, and
that the foreign keys reject an orphan detection. The `db` fixture wipes
the tables (including cases/detections/reports) around each test.
"""
import sqlite3

import pytest

from panda import cases


def _seed_case():
    case_id = cases.record_case(
        title="SSH brute-force into Windows host",
        severity="high", confidence="high", source_ip="10.0.0.9",
        summary="Same IP seen on the honeypot and the Windows Security log.")
    cases.record_detection(case_id, rule="brute-force", source="cowrie",
                           severity="medium", confidence="high",
                           source_ip="10.0.0.9", username="root",
                           evidence="42 failed SSH logins in 30s")
    cases.record_detection(case_id, rule="account-creation", source="windows",
                           severity="high", confidence="medium",
                           source_ip="10.0.0.9", username="svc_backup",
                           evidence="Event 4720 after a 4624")
    tech = cases.record_report(case_id, "technical", "Kill chain: 4625* -> 4624 -> 4720 ...")
    plain = cases.record_report(case_id, "plain", "An attacker guessed a password and made an account.")
    return case_id, tech, plain


def test_record_case_returns_id(db):
    case_id = cases.record_case(title="test", severity="low")
    assert isinstance(case_id, int) and case_id > 0


def test_case_with_detections_and_reports(db):
    case_id, tech, plain = _seed_case()
    assert len(cases.list_cases()) == 1
    assert len(cases.get_detections(case_id)) == 2
    assert len(cases.get_reports(case_id)) == 2
    # get_report returns the row; body is the last column.
    assert cases.get_report(tech)[2] == "technical"
    assert "attacker" in cases.get_report(plain)[4]


def test_list_cases_filter_by_severity(db):
    cases.record_case(title="a", severity="high")
    cases.record_case(title="b", severity="low")
    cases.record_case(title="c", severity="high")
    assert len(cases.list_cases()) == 3
    assert len(cases.list_cases(severity="high")) == 2
    assert len(cases.list_cases(severity="low")) == 1


def test_foreign_key_rejects_orphan_detection(db):
    # No such case_id -> the FK (PRAGMA foreign_keys=ON) must reject it.
    with pytest.raises(sqlite3.IntegrityError):
        cases.record_detection(999999, rule="brute-force")


def test_get_report_missing_returns_none(db):
    assert cases.get_report(123456) is None


def test_get_case_returns_row_or_none(db):
    cid = cases.record_case(title="a", severity="high", source_ip="10.0.0.9")
    assert cases.get_case(cid)[2] == "a"
    assert cases.get_case(999999) is None


def test_related_by_source_ip_links_and_excludes_self(db):
    a = cases.record_case(title="chain", severity="high", source_ip="10.0.2.3")
    b = cases.record_case(title="correlation", severity="medium", source_ip="10.0.2.3")
    cases.record_case(title="other", severity="low", source_ip="10.0.0.9")
    # From a's perspective, b is related; a excludes itself; the other IP is out.
    related = cases.related_by_source_ip("10.0.2.3", exclude_case_id=a)
    assert [r[0] for r in related] == [b]


def test_clear_all_empties_the_case_store(db):
    cid = cases.record_case(title="t", severity="high")
    cases.record_detection(cid, rule="brute-force")
    cases.record_report(cid, "technical", "body")
    cases.clear_all()
    assert cases.list_cases() == []
    assert cases.get_detections(cid) == []
    assert cases.get_reports(cid) == []


def test_related_by_source_ip_null_ip_is_empty(db):
    # Account-creation cases carry no source_ip -> never spuriously "related".
    cases.record_case(title="acct", severity="high", source_ip=None)
    assert cases.related_by_source_ip(None) == []
