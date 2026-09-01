"""Characterization tests for the main command handlers.

These lock the auth/unlock/relock control flow BEFORE main.py is DRYed up, so
the refactor can be proven behavior-preserving. Crypto is mocked (db.unlock /
db.lock are spies) — the encryption itself is covered in test_encryption; here
we only assert the control flow: authenticate, run the action, always re-lock,
and degrade cleanly when the password is wrong or unset.
"""
import builtins

import bcrypt

import main
from panda import auth, db


def _set_password(pw="pw"):
    auth.PASSWORD_PATH.parent.mkdir(parents=True, exist_ok=True)
    auth.PASSWORD_PATH.write_text(bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode())


def _mock_crypto(monkeypatch, log):
    monkeypatch.setattr(db, "unlock", lambda p: log.append("unlock"))
    monkeypatch.setattr(db, "lock", lambda p: log.append("lock"))


def test_cases_unlocks_runs_then_relocks(clean_password, monkeypatch):
    _set_password()
    log = []
    _mock_crypto(monkeypatch, log)
    monkeypatch.setattr(main, "browse_cases", lambda: log.append("action"))
    monkeypatch.setattr(builtins, "input", lambda *a, **k: "pw")
    main.handle_cases("cases")
    assert log == ["unlock", "action", "lock"]          # ran inside an unlocked session


def test_relocks_even_if_action_raises(clean_password, monkeypatch):
    _set_password()
    log = []
    _mock_crypto(monkeypatch, log)
    def boom():
        log.append("action")
        raise RuntimeError("kaboom")
    monkeypatch.setattr(main, "browse_cases", boom)
    monkeypatch.setattr(builtins, "input", lambda *a, **k: "pw")
    try:
        main.handle_cases("cases")
    except RuntimeError:
        pass
    assert log == ["unlock", "action", "lock"]          # re-locked despite the error


def test_wrong_password_denies_and_never_unlocks(clean_password, monkeypatch, capsys):
    _set_password()
    log = []
    _mock_crypto(monkeypatch, log)
    monkeypatch.setattr(main, "browse_cases", lambda: log.append("action"))
    monkeypatch.setattr(builtins, "input", lambda *a, **k: "WRONG")
    main.handle_cases("cases")
    assert log == []                                    # never unlocked, never ran
    assert "ACCESS DENIED" in capsys.readouterr().out


def test_no_password_set_prompts_to_set_one(clean_password, monkeypatch, capsys):
    calls = []
    monkeypatch.setattr(main, "password", lambda: calls.append("set"))
    monkeypatch.setattr(builtins, "input", lambda *a, **k: "anything")
    main.handle_cases("cases")                           # no password file exists
    assert "Password hasn't been set" in capsys.readouterr().out
    assert calls == ["set"]


def test_loop_survives_a_handler_error(monkeypatch, capsys):
    # A handler blowing up must print a message and return to the prompt, not
    # crash the whole session.
    queries = iter(["boom", "quit"])
    monkeypatch.setattr(main, "takecommand", lambda: next(queries))
    monkeypatch.setattr(main, "banner", lambda: None)

    def dispatch(query, fb):
        raise RuntimeError("kaboom")
    monkeypatch.setattr(main.router, "dispatch", dispatch)

    main.main()  # reaches "quit" and returns despite the error on "boom"
    assert "went wrong" in capsys.readouterr().out.lower()


def test_tdr_passes_live_flag(clean_password, monkeypatch):
    _set_password()
    _mock_crypto(monkeypatch, [])
    seen = {}
    monkeypatch.setattr(main.bridge, "scan_and_persist",
                        lambda **kw: seen.update(kw) or {"source": "x"})
    monkeypatch.setattr(main, "_print_scan_summary", lambda s: None)
    monkeypatch.setattr(builtins, "input", lambda *a, **k: "pw")
    main.handle_tdr("tdr")
    assert seen.get("live") is False and seen.get("fresh") is False
    main.handle_tdr("run tdr live now")
    assert seen.get("live") is True
    main.handle_tdr("tdr fresh")
    assert seen.get("fresh") is True


def test_tdr_anomaly_routes_to_anomaly_scan(clean_password, monkeypatch):
    _set_password()
    _mock_crypto(monkeypatch, [])
    calls = []
    monkeypatch.setattr(main.bridge, "scan_anomalies",
                        lambda **kw: calls.append("anomaly") or
                        {"source": "snapshot", "n_sources": 1, "insufficient": True,
                         "min_sources": 8, "persisted": 0, "candidates": []})
    monkeypatch.setattr(main.bridge, "scan_and_persist",
                        lambda **kw: calls.append("scan") or {})
    monkeypatch.setattr(builtins, "input", lambda *a, **k: "pw")
    main.handle_tdr("tdr anomaly")
    assert calls == ["anomaly"]                          # routed to the anomaly pass, not the scan
