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
