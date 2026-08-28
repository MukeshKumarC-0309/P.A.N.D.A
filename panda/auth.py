"""
Authentication for PandaVault access.

Passwords are stored as bcrypt hashes (salted, deliberately slow),
never in plaintext. bcrypt generates a unique random salt per password,
so identical passwords hash differently and precomputed rainbow tables
do not apply.
"""
import bcrypt

from config import DB_PATH

# The password hash lives next to the vault (in ~/.pandavault/), resolved
# from config — NOT the current working directory. This keeps a single
# password per device regardless of where PANDA is launched from.
PASSWORD_PATH = DB_PATH.parent / "password.hash"


def password():
    PASSWORD_PATH.parent.mkdir(parents=True, exist_ok=True)
    passw = input('P.A.N.D.A : Enter the password - ')
    hashed = bcrypt.hashpw(passw.encode(), bcrypt.gensalt())
    with open(PASSWORD_PATH, 'w') as f:
        f.write(hashed.decode())  # bcrypt hashes are ASCII; store as text
    print("P.A.N.D.A : Password created.", end=' ')
    print("Make sure you remember it. ")
    return passw  # raw password, so callers can also derive the vault key


def check_password(typed_password):
    """
    Compares a freshly typed password against the stored bcrypt hash.
    Returns True/False. Raises FileNotFoundError if no password has
    been set yet (caller should catch this and prompt password()).
    """
    with open(PASSWORD_PATH, 'r') as f:
        stored_hash = f.read()
    return bcrypt.checkpw(typed_password.encode(), stored_hash.encode())
