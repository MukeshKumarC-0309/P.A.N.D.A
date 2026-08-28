"""
Tests for the vault encryption primitives (panda.crypto).

Verify a clean round-trip, that a wrong password is rejected (not
silently wrong), that tampering is detected, and that the salt actually
affects the derived key.
"""
import pytest

from panda import crypto


def test_encrypt_decrypt_roundtrip():
    salt = crypto.new_salt()
    token = crypto.encrypt(b"top secret vault bytes", "hunter2", salt)
    assert token != b"top secret vault bytes"           # actually encrypted
    assert crypto.decrypt(token, "hunter2", salt) == b"top secret vault bytes"


def test_wrong_password_is_rejected():
    salt = crypto.new_salt()
    token = crypto.encrypt(b"data", "correct", salt)
    with pytest.raises(crypto.BadPassword):
        crypto.decrypt(token, "wrong", salt)


def test_tampered_ciphertext_is_detected():
    salt = crypto.new_salt()
    token = bytearray(crypto.encrypt(b"data", "pw", salt))
    token[-1] ^= 0x01                                    # flip one bit
    with pytest.raises(crypto.BadPassword):
        crypto.decrypt(bytes(token), "pw", salt)


def test_salt_changes_the_key():
    k1 = crypto.derive_key("pw", crypto.new_salt())
    k2 = crypto.derive_key("pw", crypto.new_salt())
    assert k1 != k2                                      # different salt -> different key


def test_same_password_and_salt_is_deterministic():
    salt = crypto.new_salt()
    assert crypto.derive_key("pw", salt) == crypto.derive_key("pw", salt)
