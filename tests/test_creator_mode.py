"""Security regression tests for CREATOR mode.

CREATOR mode lets a user define and fill their own tables. It must go through
the validated DAO — table/column names checked against the identifier
whitelist, values bound as parameters — so no user input reaches SQL as code.
These drive the real DATABASE() menu to prove a value payload is stored inert
and a malicious table name is rejected. (The old arbitrary-SQL DEVELOPER mode
was removed; there is no raw-SQL path left to test.)
"""
import builtins

from panda import vault, cases


def _run(steps, monkeypatch):
    it = iter(steps)
    monkeypatch.setattr(builtins, "input", lambda *a, **k: next(it))
    vault.DATABASE()


def test_creator_mode_refuses_the_builtin_evidence_tables(db, monkeypatch, capsys):
    # CREATOR mode must not be able to forge/alter the TDR evidence tables.
    cases.record_case(title="real case", severity="high")
    before = len(cases.list_cases())
    _run(["CREATOR",
          "ADD", "cases",              # try to insert a forged row into cases
          "CREATE", "reports",         # try to create/alter a reserved table
          "QUIT", "QUIT"], monkeypatch)
    out = capsys.readouterr().out.lower()
    assert out.count("reserved") >= 2          # both attempts refused
    assert len(cases.list_cases()) == before   # no forged rows landed


def test_creator_value_is_bound_not_injected(db, monkeypatch):
    payload = "'); drop table cases;--"
    _run(["CREATOR",
          "CREATE", "notes_t", "body", "exit", "YES",   # create notes_t(Serial_No, body)
          "notes_t", "2", "YES", "x", payload, "NO",     # add row: ('x', payload)
          "QUIT", "QUIT"], monkeypatch)
    try:
        # The payload did nothing as SQL — the cases table is untouched...
        vault.cur.execute(
            "select name from sqlite_master where type='table' and name='cases'")
        assert vault.cur.fetchone() is not None
        # ...and it was stored verbatim as a value.
        vault.cur.execute("select body from notes_t")
        assert vault.cur.fetchall() == [(payload,)]
    finally:
        vault.cur.execute("drop table if exists notes_t")
        vault.conobj.commit()


def test_creator_rejects_malicious_table_name(db, monkeypatch, capsys):
    _run(["CREATOR", "CREATE", "bad; drop table cases", "QUIT", "QUIT"], monkeypatch)
    assert "Invalid table name" in capsys.readouterr().out
    vault.cur.execute(
        "select name from sqlite_master where type='table' and name='cases'")
    assert vault.cur.fetchone() is not None
