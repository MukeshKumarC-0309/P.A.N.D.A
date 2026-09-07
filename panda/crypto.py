"""
Encryption primitives for the vault at rest.

The vault file is encrypted with a key derived from the user's vault
password, so the data on disk is unreadable without it:

* derive_key  - scrypt (memory-hard) turns password + salt into a key.
* encrypt     - Fernet (AES-128-CBC + HMAC) authenticated encryption, so
                tampering or a wrong password is detected, not silently
                accepted.
* new_salt    - a fresh random salt to store alongside the ciphertext.

This module is pure crypto with no knowledge of SQLite or files; the db
layer wires it into the unlock/lock lifecycle.
"""
import base64
import os

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

# scrypt cost parameters. N is the CPU/memory cost (must be a power of 2);
# 2**14 is a common interactive default — expensive for attackers, fine here.
_SCRYPT_N = 2 ** 14
_SCRYPT_R = 8
_SCRYPT_P = 1

KEY_LENGTH = 32   # bytes; Fernet wants a 32-byte key (base64-encoded)
SALT_LENGTH = 16  # bytes

# Re-exported so callers can catch a wrong password / tampered file without
# importing cryptography directly.
BadPassword = InvalidToken


def new_salt():
    """Return a fresh cryptographically-random salt."""
    return os.urandom(SALT_LENGTH)


def derive_key(password, salt):
    """Derive a Fernet key (url-safe base64 of 32 bytes) from password+salt."""
    kdf = Scrypt(salt=salt, length=KEY_LENGTH, n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P)
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))


def encrypt(plaintext, password, salt):
    """Encrypt bytes with a key derived from password+salt. Returns a token."""
    return Fernet(derive_key(password, salt)).encrypt(plaintext)


def decrypt(token, password, salt):
    """Decrypt a token. Raises BadPassword on a wrong password or tampering."""
    return Fernet(derive_key(password, salt)).decrypt(token)


# --------------------------------------------------------------------------
# Envelope encryption (recovery-key support).
#
# The vault is encrypted with a random *data key* (DEK); the DEK is then
# "wrapped" (encrypted) once under the password and once under a recovery key,
# so either can unlock. This adds recovery WITHOUT a backdoor — you still need
# one of two secrets you deliberately kept, and losing both leaves the data
# unrecoverable (the guarantee holds). A password change just re-wraps the DEK
# rather than re-encrypting the whole vault. Everything stays authenticated
# (Fernet), so tampering is still detected at every layer.
# --------------------------------------------------------------------------

def new_data_key():
    """A fresh random data key (DEK) — encrypts the vault contents."""
    return Fernet.generate_key()


def new_recovery_key():
    """A fresh random recovery key — a high-entropy secret shown to the user
    once. It needs no KDF (it is already a full-strength key)."""
    return Fernet.generate_key()


def wrap_key(data_key, wrapping_key):
    """Encrypt (wrap) the DEK under a wrapping key. Returns the wrapped bytes."""
    return Fernet(wrapping_key).encrypt(data_key)


def unwrap_key(wrapped, wrapping_key):
    """Recover the DEK from its wrapped form. Raises BadPassword if the wrapping
    key is wrong or the wrapped bytes were tampered with."""
    return Fernet(wrapping_key).decrypt(wrapped)


def encrypt_with(plaintext, data_key):
    """Encrypt bytes directly under a data key (not password-derived)."""
    return Fernet(data_key).encrypt(plaintext)


def decrypt_with(token, data_key):
    """Decrypt bytes encrypted under a data key. Raises BadPassword on tamper."""
    return Fernet(data_key).decrypt(token)
