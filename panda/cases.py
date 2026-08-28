"""
Case store: how a TDR run persists its findings, and how the vault reads
them back.

A *case* is an incident — a correlated group of activity, or a single
standalone detection. Each case has one or more *detections* (the
individual signals TDR raised) and one or more *reports* (the incident
write-up, one row per audience: technical and plain-language).

Everything lives in the same SQLite vault, so it is encrypted at rest and
readable only after the vault is unlocked (login). Writing therefore
requires an unlocked vault (the caller — a TDR run — unlocks, records,
then locks).

TDR persists with record_case / record_detection / record_report; the
vault browses with list_cases / get_detections / get_reports / get_report.
"""
from datetime import datetime, timezone

from panda import db


def _now():
    """Current UTC time as an ISO-8601 string (stored as TEXT)."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# --- write API (used by a TDR run) -----------------------------------------

def record_case(title, severity=None, confidence=None, source_ip=None,
                summary=None, status="open"):
    """Create a case; return its new case_id."""
    return db.insert_row("cases", {
        "created_at": _now(),
        "title": title,
        "severity": severity,
        "confidence": confidence,
        "status": status,
        "source_ip": source_ip,
        "summary": summary,
    })


def record_detection(case_id, rule, source=None, severity=None, confidence=None,
                     source_ip=None, username=None, evidence=None):
    """Attach a detection to a case; return its new detection_id."""
    return db.insert_row("detections", {
        "case_id": case_id,
        "detected_at": _now(),
        "rule": rule,
        "source": source,
        "severity": severity,
        "confidence": confidence,
        "source_ip": source_ip,
        "username": username,
        "evidence": evidence,
    })


def record_report(case_id, audience, body):
    """Attach an incident report (per audience) to a case; return report_id."""
    return db.insert_row("reports", {
        "case_id": case_id,
        "audience": audience,
        "created_at": _now(),
        "body": body,
    })


# --- read API (used by the vault browse UI) --------------------------------

def list_cases(severity=None):
    """All cases, or only those of a given severity."""
    if severity is None:
        return db.fetch_all("cases", order_by="case_id")
    return db.fetch_where("cases", "severity", severity)


def get_detections(case_id):
    """All detections belonging to a case."""
    return db.fetch_where("detections", "case_id", case_id)


def get_reports(case_id):
    """All reports belonging to a case."""
    return db.fetch_where("reports", "case_id", case_id)


def get_report(report_id):
    """One report row, or None if it does not exist."""
    rows = db.fetch_where("reports", "report_id", report_id)
    return rows[0] if rows else None


def get_case(case_id):
    """One case row, or None if it does not exist."""
    rows = db.fetch_where("cases", "case_id", case_id)
    return rows[0] if rows else None


def related_by_source_ip(source_ip, exclude_case_id=None):
    """Other cases that share a source IP — the link across detection lenses.

    A single actor surfaces in more than one case (e.g. a Windows kill chain
    and a cross-source correlation both keyed on the same IP). These are kept
    as separate cases on purpose (different evidence, no double-counting); the
    shared source_ip is how an analyst connects them. Returns [] for a null IP.
    """
    if not source_ip:
        return []
    return [r for r in db.fetch_where("cases", "source_ip", source_ip)
            if r[0] != exclude_case_id]
