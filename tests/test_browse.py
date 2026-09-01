"""Regression test for the CASES browse view's column wrapping.

The browse tables cap their free-text columns so a long title / summary /
evidence wraps instead of pushing the table past the terminal width. This drives
the real browse_cases() with an extreme case and asserts the rendered output
stays bounded — a guard against the overflow returning if the caps are dropped.
"""
import builtins

from panda import browse, cases

MAX_LINE = 200  # generous bound; unwrapped, a 500-char summary alone blows past it


def test_browse_empty_vault_does_not_crash(db, capsys, monkeypatch):
    # Column wrapping (maxcolwidths) must not trip tabulate on an empty row list:
    # browsing a vault with no cases renders the header, not an IndexError.
    steps = iter([""])  # blank severity -> empty list -> blank case id returns
    monkeypatch.setattr(builtins, "input", lambda *a, **k: next(steps, ""))
    browse.browse_cases()
    assert "Case ID" in capsys.readouterr().out


def test_browse_wraps_wide_columns(db, capsys, monkeypatch):
    cid = cases.record_case(title="T" * 200, severity="high",
                            source_ip="10.0.2.3", summary="S" * 500)
    cases.record_detection(cid, rule="correlation", source="cowrie+windows",
                           evidence="E" * 400)

    # severity filter (blank) -> open the case -> report id (blank).
    steps = iter(["", str(cid), ""])
    monkeypatch.setattr(builtins, "input", lambda *a, **k: next(steps))
    browse.browse_cases()

    out = capsys.readouterr().out
    longest = max((len(line) for line in out.splitlines()), default=0)
    assert longest <= MAX_LINE
    # The data is still there — wrapped across lines, not truncated away.
    assert "10.0.2.3" in out
