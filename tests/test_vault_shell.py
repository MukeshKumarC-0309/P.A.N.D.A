"""Characterization tests for the interactive vault shell (vault.DATABASE()).

These lock the shell's observable behavior BEFORE it is refactored, so the
refactor can be proven behavior-preserving. They drive the real menu loop with a
scripted `input` and capture stdout. `DATABASE()` stays the public entry point
(main.py calls it), so these hold across the refactor unchanged.
"""
import builtins

from panda import vault, cases


def _run(steps, monkeypatch):
    it = iter(steps)
    monkeypatch.setattr(builtins, "input", lambda *a, **k: next(it))
    vault.DATABASE()


def test_help_lists_commands(db, monkeypatch, capsys):
    _run(["HELP", "QUIT"], monkeypatch)
    out = capsys.readouterr().out
    assert "Browse the TDR evidence store" in out
    assert "CREATOR MODE" in out


def test_show_tables_lists_builtin_tables(db, monkeypatch, capsys):
    _run(["SHOW", "QUIT"], monkeypatch)
    out = capsys.readouterr().out
    assert "cases" in out and "detections" in out and "reports" in out


def test_cases_routes_to_browse(db, monkeypatch, capsys):
    # CASES -> browse_cases: blank severity, blank case id (go back), then QUIT.
    _run(["CASES", "", "", "QUIT"], monkeypatch)
    out = capsys.readouterr().out
    assert "Case ID" in out and "Severity" in out          # the cases list header


def test_search_rejects_bad_identifier(db, monkeypatch, capsys):
    _run(["SEARCH", "bad name", "field", "value", "QUIT"], monkeypatch)
    out = capsys.readouterr().out
    assert "Invalid table or field name" in out


def test_search_returns_matching_rows(db, monkeypatch, capsys):
    cases.record_case(title="Findme", severity="high", source_ip="1.2.3.4")
    _run(["SEARCH", "cases", "severity", "high", "QUIT"], monkeypatch)
    out = capsys.readouterr().out
    assert "Findme" in out                                  # the matched row printed


def test_add_records_handles_non_numeric_field_count(db, monkeypatch, capsys):
    # A non-number for "how many fields" must not crash the shell.
    _run(["CREATOR", "ADD", "mytable", "notanumber", "QUIT", "QUIT"], monkeypatch)
    out = capsys.readouterr().out
    assert "whole number" in out                          # friendly message, no traceback


def test_show_rejects_bad_identifier_in_creator_view(db, monkeypatch, capsys):
    # CREATOR -> VIEW -> NO -> SHOW(user table) with an invalid name.
    _run(["CREATOR", "VIEW", "NO", "bad name", "QUIT", "QUIT"], monkeypatch)
    out = capsys.readouterr().out
    assert "Invalid table name" in out
