"""
Vault encryption lifecycle tests (panda.db unlock/lock).

Verify that locking writes an encrypted file, unlocking restores the in-memory
data, a wrong password is rejected, and no plaintext leaks onto disk. The
sample table is `cases` (the vault's canonical built-in table). Uses tmp_path
so the real vault is never touched.
"""
import pytest

from panda import db as dao
from panda import crypto

# (case_id, created_at, title, severity, confidence, status, source_ip, summary,
#  disposition, fingerprint)
ROW = (1, "2026-01-01T00:00:00+00:00", "SSH brute-force", "high", "high",
       "open", "10.0.0.9", "Same IP on the honeypot and the Windows log.", None, None)


def test_lock_then_unlock_roundtrip(db, tmp_path):
    path = tmp_path / "vault.db"
    dao.insert("cases", ROW)
    dao.lock("pw", path=path)
    assert path.exists()

    # Wipe memory; unlocking must bring the row back.
    dao.cursor.execute("delete from cases")
    dao.connection.commit()
    assert dao.fetch_all("cases") == []

    dao.unlock("pw", path=path)
    assert dao.fetch_all("cases") == [ROW]


def test_unlock_wrong_password_raises(db, tmp_path):
    path = tmp_path / "vault.db"
    dao.insert("cases", ROW)
    dao.lock("pw", path=path)
    with pytest.raises(crypto.BadPassword):
        dao.unlock("wrong-password", path=path)


def test_unlock_missing_file_is_noop(db, tmp_path):
    # First run: no file yet -> unlock leaves the empty in-memory schema.
    dao.unlock("pw", path=tmp_path / "does-not-exist.db")
    assert dao.fetch_all("cases") == []


def test_unlock_migrates_an_older_vault(tmp_path):
    # A vault written by an older build lacks the later `cases` columns; unlock
    # must add them (and preserve the existing data), not fail.
    import sqlite3

    old = sqlite3.connect(":memory:")
    old.executescript(
        "CREATE TABLE cases (case_id INTEGER PRIMARY KEY AUTOINCREMENT,"
        " created_at TEXT, title TEXT, severity TEXT, confidence TEXT,"
        " status TEXT, source_ip TEXT, summary TEXT);"
        "CREATE TABLE detections (detection_id INTEGER PRIMARY KEY AUTOINCREMENT,"
        " case_id INTEGER, detected_at TEXT, rule TEXT, source TEXT, severity TEXT,"
        " confidence TEXT, source_ip TEXT, username TEXT, evidence TEXT);"
        "CREATE TABLE reports (report_id INTEGER PRIMARY KEY AUTOINCREMENT,"
        " case_id INTEGER, audience TEXT, created_at TEXT, body TEXT);")
    old.execute("INSERT INTO cases (created_at, title) VALUES ('t', 'old case')")
    old.commit()

    path = tmp_path / "old.db"
    salt = crypto.new_salt()
    path.write_bytes(salt + crypto.encrypt(old.serialize(), "pw", salt))

    try:
        dao.unlock("pw", path=path)
        cols = {r[1] for r in dao.cursor.execute("PRAGMA table_info(cases)")}
        assert "disposition" in cols and "fingerprint" in cols   # columns added
        assert dao.cursor.execute("select title from cases").fetchone()[0] == "old case"
    finally:
        # Restore the shared connection to a pristine schema for other tests.
        dao.connection.deserialize(dao.init_db().serialize())


def test_file_has_no_plaintext(db, tmp_path):
    path = tmp_path / "vault.db"
    dao.insert("cases", (1, "2026-01-01T00:00:00+00:00", "ZEDNAME", "high",
                         "high", "open", "10.0.0.9", "SEEKRIT_ID", None, None))
    dao.lock("pw", path=path)
    blob = path.read_bytes()
    assert b"SEEKRIT_ID" not in blob
    assert b"ZEDNAME" not in blob
