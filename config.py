"""
Configuration for PANDA.

PANDA is an embedded, offline security tool: the vault is a single local
encrypted file per device. There is no server and no external API — so no
credentials or API keys are required or read here.

The vault lives in the user's home directory so it survives regardless of
where PANDA is launched from. Override with PANDA_DB_PATH (handy for tests
or a custom location).
"""
import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()  # reads .env into environment variables, if present

DEFAULT_DB_PATH = Path.home() / ".panda" / "vault.db"
DB_PATH = Path(os.environ.get("PANDA_DB_PATH", DEFAULT_DB_PATH))
