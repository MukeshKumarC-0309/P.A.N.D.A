"""
Password hashing and verification (bcrypt) round-trips.

password() reads the new password via input(); tests feed it with
monkeypatch. PASSWORD_PATH resolves under the temp vault dir (see
conftest), so these never touch a real password file.
"""
import pytest

from panda import auth


def _feed_input(monkeypatch, value):
    monkeypatch.setattr("builtins.input", lambda *a, **k: value)


def test_password_roundtrip(clean_password, monkeypatch):
    _feed_input(monkeypatch, "hunter2")
    auth.password()
    assert auth.check_password("hunter2") is True
    assert auth.check_password("wrong") is False


def test_check_password_missing_raises(clean_password):
    with pytest.raises(FileNotFoundError):
        auth.check_password("anything")


def test_stored_value_is_bcrypt_not_plaintext(clean_password, monkeypatch):
    _feed_input(monkeypatch, "hunter2")
    auth.password()
    stored = auth.PASSWORD_PATH.read_text()
    assert "hunter2" not in stored           # never stored in the clear
    assert stored.startswith("$2")           # bcrypt hash identifier


def test_path_is_under_vault_dir():
    # Resolved from config.DB_PATH, not the current working directory.
    from config import DB_PATH
    assert auth.PASSWORD_PATH.parent == DB_PATH.parent
    assert auth.PASSWORD_PATH.name == "password.hash"


class _FakeStdin:
    def __init__(self, tty):
        self._tty = tty

    def isatty(self):
        return self._tty


def test_read_password_masks_at_a_terminal(monkeypatch):
    monkeypatch.setattr(auth.sys, "stdin", _FakeStdin(True))
    monkeypatch.setattr(auth.getpass, "getpass", lambda prompt="": "secret")
    monkeypatch.setattr("builtins.input",
                        lambda *a, **k: pytest.fail("input() must not echo the password at a TTY"))
    assert auth.read_password("pw: ") == "secret"


def test_read_password_falls_back_without_a_tty(monkeypatch):
    monkeypatch.setattr(auth.sys, "stdin", _FakeStdin(False))
    monkeypatch.setattr(auth.getpass, "getpass",
                        lambda prompt="": pytest.fail("getpass must not be used off a TTY"))
    monkeypatch.setattr("builtins.input", lambda *a, **k: "typed")
    assert auth.read_password("pw: ") == "typed"


def test_check_password_corrupt_hash_returns_false(clean_password):
    auth.PASSWORD_PATH.parent.mkdir(parents=True, exist_ok=True)
    auth.PASSWORD_PATH.write_text("not-a-valid-bcrypt-hash")
    assert auth.check_password("anything") is False    # deny, not a traceback
