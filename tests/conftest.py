"""
Shared pytest setup.

IMPORTANT: PANDA_DB_PATH must be set BEFORE anything imports the package,
because db.py builds the in-memory connection at import time and resolves
the on-disk (encrypted) vault path from config. conftest.py is imported by
pytest before the test modules, so setting os.environ here (above the
package imports) is what makes that ordering work.

PANDA_DB_PATH is forced to a throwaway temp file so tests never read or
write the real ~/.panda vault or password.
"""
import os
import tempfile
from pathlib import Path

_TMPDIR = tempfile.mkdtemp(prefix="panda-test-")
os.environ["PANDA_DB_PATH"] = str(Path(_TMPDIR) / "vault.db")

import pytest

from panda import vault, auth

# Children before parents, so foreign keys don't block the deletes.
WIPE_ORDER = ("reports", "detections", "cases")


def _wipe():
    for table in WIPE_ORDER:
        vault.cur.execute("delete from {}".format(table))
    vault.conobj.commit()


@pytest.fixture
def db():
    """Give a test a clean vault: empty built-in tables before and after."""
    _wipe()
    yield vault.cur
    _wipe()


@pytest.fixture
def clean_password():
    """Ensure no password file exists before/after the test."""
    auth.PASSWORD_PATH.unlink(missing_ok=True)
    yield
    auth.PASSWORD_PATH.unlink(missing_ok=True)
