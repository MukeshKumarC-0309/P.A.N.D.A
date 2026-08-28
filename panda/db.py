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
import re
import sqlite3
from pathlib import Path

from config import DB_PATH
from panda import crypto

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


def unlock(password, path=DB_PATH):
    """Decrypt the vault file into the in-memory database.

    On first run (no file yet) this is a no-op: memory keeps the empty
    schema from init_db(). Raises crypto.BadPassword on a wrong password
    or a tampered file.
    """
    path = Path(path)
    if not path.exists():
        return
    blob = path.read_bytes()
    salt, token = blob[:crypto.SALT_LENGTH], blob[crypto.SALT_LENGTH:]
    data = crypto.decrypt(token, password, salt)
    connection.deserialize(data)


def lock(password, path=DB_PATH):
    """Serialize the in-memory database and write it out encrypted.

    A fresh salt is used each time and stored as the first bytes of the
    file, ahead of the ciphertext.
    """
    connection.commit()
    data = connection.serialize()
    salt = crypto.new_salt()
    token = crypto.encrypt(data, password, salt)
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(salt + token)


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
