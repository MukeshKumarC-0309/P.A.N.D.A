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
