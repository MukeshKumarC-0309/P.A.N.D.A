"""
Data-access helper tests (panda.db).

These exercise the shared DAO used by the vault and the TDR case store:
identifier validation, parameter-bound values, and the CRUD helpers, against
the temp vault created by conftest. The sample table is `cases` (the vault's
canonical built-in table); the helpers are table-agnostic. The `db` fixture
wipes the case-store tables around each test.
"""
import sqlite3

import pytest

from panda import db as dao

# Positional row matching the `cases` columns:
# (case_id, created_at, title, severity, confidence, status, source_ip, summary,
#  disposition)
ROW = (1, "2026-01-01T00:00:00+00:00", "SSH brute-force", "high", "high",
       "open", "10.0.0.9", "Same IP on the honeypot and the Windows log.", None)


def test_insert_and_fetch_all(db):
    dao.insert("cases", ROW)
    assert dao.fetch_all("cases") == [ROW]


def test_fetch_where_binds_value(db):
    dao.insert("cases", ROW)
    assert dao.fetch_where("cases", "source_ip", "10.0.0.9") == [ROW]
    assert dao.fetch_where("cases", "source_ip", "nope") == []


def test_update(db):
    dao.insert("cases", ROW)
    affected = dao.update("cases", "severity", "low", "case_id", 1)
    assert affected == 1
    assert dao.fetch_where("cases", "case_id", 1)[0][3] == "low"


def test_delete(db):
    dao.insert("cases", ROW)
    assert dao.delete("cases", "case_id", 1) == 1
    assert dao.fetch_all("cases") == []


def test_insert_or_ignore_dedupes_on_primary_key(db):
    dao.insert("cases", ROW)
    with pytest.raises(sqlite3.IntegrityError):
        dao.insert("cases", ROW)              # duplicate PK -> raises
    dao.insert("cases", ROW, or_ignore=True)  # duplicate PK -> skipped
    assert len(dao.fetch_all("cases")) == 1


def test_injection_identifier_rejected(db):
    for bad in ("x; drop table cases", "a b", "1abc"):
        with pytest.raises(ValueError):
            dao.fetch_all(bad)
        with pytest.raises(ValueError):
            dao.fetch_where("cases", bad, "x")


def test_injection_value_is_inert(db):
    dao.insert("cases", ROW)
    # A classic payload as a VALUE matches nothing (bound as a literal).
    assert dao.fetch_where("cases", "title", "' OR '1'='1") == []
