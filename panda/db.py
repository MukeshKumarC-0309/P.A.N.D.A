"""
Shared SQLite connection for PandaVault, encrypted at rest.

The live database is held IN MEMORY; on disk there is only an encrypted
blob (config.DB_PATH). unlock(password) decrypts that blob into memory;
lock(password) serializes memory back out, encrypted. So plaintext vault
data never touches the disk.

This module owns the one connection so any capability can share it — the
personal-records vault (panda/vault.py) today, a future TDR (threat
detection) component tomorrow, persisting into the same encrypted vault.
"""
import base64
import json
import re
import sqlite3
from pathlib import Path

from config import DB_PATH
from panda import crypto

# v2 (envelope / recovery-enabled) vault files start with this marker; anything
# else is read as the legacy v1 format (a 16-byte salt + a Fernet token).
_MAGIC_V2 = b"PANDAv2\n"

# Envelope session state for the currently-open vault: the data key (DEK) and
# the recovery-wrapped DEK. None => this vault is legacy v1 (password-only, no
# recovery). Set by unlock / recover / init_envelope; used by lock to re-wrap.
_data_key = None
_wrapped_rk = None

# schema.sql lives at the repo root (one level up from this panda/ package).
# Resolve it from __file__ so it is found regardless of the launch directory.
SCHEMA_PATH = Path(__file__).resolve().parent.parent / "schema.sql"


def init_db():
    """Create a fresh in-memory database with the built-in schema applied.

    This is the empty/locked state. Real data is loaded by unlock().
    """
    conn = sqlite3.connect(":memory:")
    conn.execute("PRAGMA foreign_keys = ON")  # enforce FKs (future TDR tables)
    with open(SCHEMA_PATH, "r") as f:
        conn.executescript(f.read())
    conn.commit()
    return conn


# The one shared in-memory connection/cursor for the process.
connection = init_db()
cursor = connection.cursor()

# Columns added to `cases` after the first release. A vault created by an older
# build won't have them, so _migrate() adds any that are missing after a vault
# is loaded — schema evolution without a wipe or a manual migration step.
_CASES_ADDED_COLUMNS = {"disposition": "TEXT", "fingerprint": "TEXT"}


def _migrate():
    """Add any post-release `cases` columns missing from the loaded vault."""
    existing = {row[1] for row in cursor.execute("PRAGMA table_info(cases)")}
    for column, coltype in _CASES_ADDED_COLUMNS.items():
        if column not in existing:
            cursor.execute("ALTER TABLE cases ADD COLUMN {} {}".format(column, coltype))
    connection.commit()


def _reset_envelope():
    """Clear envelope session state (back to legacy v1 mode)."""
    global _data_key, _wrapped_rk
    _data_key, _wrapped_rk = None, None


def has_recovery():
    """True if the currently-open vault has recovery enabled (v2 envelope)."""
    return _data_key is not None


def init_envelope():
    """Start a fresh envelope for a new (or upgraded) vault.

    Generates a random data key and a random recovery key, wraps the data key
    under the recovery key, and holds both in session state. Returns the
    recovery key to show the user ONCE; the next lock() writes the vault in v2
    (recovery-enabled) format. Call this at vault creation, or to upgrade a v1
    vault (unlock it first, then init_envelope(), then lock()).
    """
    global _data_key, _wrapped_rk
    recovery_key = crypto.new_recovery_key()
    _data_key = crypto.new_data_key()
    _wrapped_rk = crypto.wrap_key(_data_key, recovery_key)
    return recovery_key


def unlock(password, path=DB_PATH):
    """Decrypt the vault file into the in-memory database (via the password).

    On first run (no file yet) this is a no-op: memory keeps the empty schema
    from init_db(). Reads both formats: v2 (envelope) unwraps the data key with
    the password; v1 (legacy) decrypts the whole blob. Raises crypto.BadPassword
    on a wrong password or a tampered file.
    """
    global _data_key, _wrapped_rk
    path = Path(path)
    if not path.exists():
        _reset_envelope()
        return
    blob = path.read_bytes()
    if blob.startswith(_MAGIC_V2):
        header = json.loads(blob[len(_MAGIC_V2):].decode("utf-8"))
        kek = crypto.derive_key(password, base64.b64decode(header["salt_pw"]))
        dek = crypto.unwrap_key(header["wrapped_pw"].encode(), kek)  # BadPassword if wrong
        data = crypto.decrypt_with(header["vault"].encode(), dek)
        _data_key, _wrapped_rk = dek, header["wrapped_rk"].encode()
    else:
        salt, token = blob[:crypto.SALT_LENGTH], blob[crypto.SALT_LENGTH:]
        data = crypto.decrypt(token, password, salt)
        _reset_envelope()  # legacy v1 has no envelope
    connection.deserialize(data)
    _migrate()  # bring an older vault's schema up to date (adds new columns)


def recover(recovery_key, path=DB_PATH):
    """Unlock a v2 vault with its recovery key (when the password is lost).

    Loads the vault so a new password can then be set (the next lock() re-wraps
    the data key under it). Raises crypto.BadPassword if the recovery key is
    wrong/tampered, or ValueError if the vault is missing or has no recovery
    (a v1 vault created before recovery was enabled).
    """
    global _data_key, _wrapped_rk
    if isinstance(recovery_key, str):
        recovery_key = recovery_key.strip().encode()
    path = Path(path)
    if not path.exists():
        raise ValueError("No vault to recover.")
    blob = path.read_bytes()
    if not blob.startswith(_MAGIC_V2):
        raise ValueError("This vault has no recovery key.")
    header = json.loads(blob[len(_MAGIC_V2):].decode("utf-8"))
    dek = crypto.unwrap_key(header["wrapped_rk"].encode(), recovery_key)  # BadPassword if wrong
    data = crypto.decrypt_with(header["vault"].encode(), dek)
    _data_key, _wrapped_rk = dek, header["wrapped_rk"].encode()
    connection.deserialize(data)
    _migrate()


def lock(password, path=DB_PATH):
    """Serialize the in-memory database and write it out encrypted.

    v2 (envelope) when recovery is enabled: re-wrap the data key under the
    password (fresh salt) and keep the recovery wrap, so a password change is a
    cheap re-wrap, not a full re-encrypt. v1 (legacy) otherwise: the whole blob
    under a password-derived key. Everything is authenticated (Fernet).
    """
    connection.commit()
    data = connection.serialize()
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if _data_key is None:
        salt = crypto.new_salt()
        path.write_bytes(salt + crypto.encrypt(data, password, salt))
        return
    salt_pw = crypto.new_salt()
    kek = crypto.derive_key(password, salt_pw)
    header = {
        "version": 2,
        "salt_pw": base64.b64encode(salt_pw).decode(),
        "wrapped_pw": crypto.wrap_key(_data_key, kek).decode(),
        "wrapped_rk": _wrapped_rk.decode(),
        "vault": crypto.encrypt_with(data, _data_key).decode(),
    }
    path.write_bytes(_MAGIC_V2 + json.dumps(header).encode("utf-8"))


# ---------------------------------------------------------------------------
# Data-access helpers.
#
# SQL parameters (?) can bind VALUES but never IDENTIFIERS (table/column
# names). These helpers bind every value as a parameter and validate every
# identifier against a strict whitelist, so callers (the vault today, TDR
# tomorrow) get a safe, DRY query surface instead of hand-writing SQL.
# ---------------------------------------------------------------------------

_IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def safe_identifier(name):
    """Return name if it is a valid SQL identifier, else raise ValueError.

    A valid identifier is a letter/underscore followed by any number of
    letters, digits, or underscores — so quotes, spaces, semicolons and
    other injection vectors are rejected. Identifiers cannot be bound as
    parameters, so this validation is how table/column names are made safe.
    """
    if _IDENTIFIER_RE.match(name):
        return name
    raise ValueError("Invalid identifier: {!r}".format(name))


def fetch_all(table, order_by=None):
    """Return all rows of a table, optionally ordered by a column."""
    sql = "select * from {}".format(safe_identifier(table))
    if order_by is not None:
        sql += " order by {}".format(safe_identifier(order_by))
    return cursor.execute(sql).fetchall()


def fetch_where(table, column, value):
    """Return rows of a table where column == value (value is bound)."""
    sql = "select * from {} where {} = ?".format(
        safe_identifier(table), safe_identifier(column))
    return cursor.execute(sql, (value,)).fetchall()


def insert(table, values, or_ignore=False):
    """Insert one row (all columns, positional). Returns rows affected.

    or_ignore=True uses INSERT OR IGNORE, so a row that would violate a
    UNIQUE/PRIMARY KEY constraint is skipped instead of raising.
    """
    verb = "insert or ignore into" if or_ignore else "insert into"
    placeholders = ",".join(["?"] * len(values))
    sql = "{} {} values ({})".format(verb, safe_identifier(table), placeholders)
    with connection:
        cursor.execute(sql, tuple(values))
    return cursor.rowcount


def insert_row(table, data):
    """Insert a row from a {column: value} mapping; return the new row id.

    Only the named columns are set, so the rest take their defaults (e.g.
    an AUTOINCREMENT id or a DEFAULT status). Column names are validated;
    values are bound as parameters. This is the write API for the case
    store, where the database assigns ids.
    """
    columns = [safe_identifier(c) for c in data]
    placeholders = ",".join(["?"] * len(columns))
    sql = "insert into {} ({}) values ({})".format(
        safe_identifier(table), ",".join(columns), placeholders)
    with connection:
        cursor.execute(sql, tuple(data.values()))
    return cursor.lastrowid


def update(table, set_column, value, where_column, where_value):
    """Set one column where another column matches. Returns rows affected."""
    sql = "update {} set {} = ? where {} = ?".format(
        safe_identifier(table), safe_identifier(set_column),
        safe_identifier(where_column))
    with connection:
        cursor.execute(sql, (value, where_value))
    return cursor.rowcount


def delete(table, column, value):
    """Delete rows where column == value (value is bound). Returns count."""
    sql = "delete from {} where {} = ?".format(
        safe_identifier(table), safe_identifier(column))
    with connection:
        cursor.execute(sql, (value,))
    return cursor.rowcount
