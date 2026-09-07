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


# --- envelope encryption (recovery-key support) ----------------------------

def test_data_key_wrap_unwrap_roundtrip():
    dek = crypto.new_data_key()
    kek = crypto.derive_key("pw", crypto.new_salt())
    assert crypto.unwrap_key(crypto.wrap_key(dek, kek), kek) == dek


def test_wrap_unwrap_with_recovery_key():
    dek = crypto.new_data_key()
    rk = crypto.new_recovery_key()
    assert crypto.unwrap_key(crypto.wrap_key(dek, rk), rk) == dek


def test_unwrap_with_wrong_key_is_rejected():
    dek = crypto.new_data_key()
    wrapped = crypto.wrap_key(dek, crypto.new_recovery_key())
    with pytest.raises(crypto.BadPassword):
        crypto.unwrap_key(wrapped, crypto.new_recovery_key())   # different key


def test_tampered_wrapped_key_is_detected():
    dek = crypto.new_data_key()
    rk = crypto.new_recovery_key()
    wrapped = bytearray(crypto.wrap_key(dek, rk))
    wrapped[-1] ^= 0x01
    with pytest.raises(crypto.BadPassword):
        crypto.unwrap_key(bytes(wrapped), rk)


def test_encrypt_with_data_key_roundtrip():
    dek = crypto.new_data_key()
    token = crypto.encrypt_with(b"vault bytes", dek)
    assert token != b"vault bytes"
    assert crypto.decrypt_with(token, dek) == b"vault bytes"


def test_two_secrets_unwrap_the_same_data_key():
    # The whole point: password OR recovery key both recover the same DEK.
    dek = crypto.new_data_key()
    kek = crypto.derive_key("pw", crypto.new_salt())
    rk = crypto.new_recovery_key()
    from_pw = crypto.unwrap_key(crypto.wrap_key(dek, kek), kek)
    from_rk = crypto.unwrap_key(crypto.wrap_key(dek, rk), rk)
    assert from_pw == from_rk == dek
