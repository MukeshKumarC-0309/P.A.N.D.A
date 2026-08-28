"""
Command router for P.A.N.D.A.

A small registry that maps keywords to handlers, replacing the original
if/elif chain in main.py. Two properties matter:

* Matching is on whole words (\\bkeyword\\b), so "set" no longer fires on
  "sunset" and "time" no longer fires on "bedtime".
* Selection is by best score (most keywords matched), not the first
  substring hit, so ordering bugs go away.

It is also an extension seam: any capability can register its own
commands here without editing the main loop — the personal-records vault
today, and a TDR (threat detection) component in the future.
"""
import re
from collections import namedtuple

Command = namedtuple("Command", "name keywords handler")

_registry = []


def register(name, keywords, handler):
    """Add a command: a name, its trigger keywords, and a handler(query)."""
    _registry.append(Command(name, keywords, handler))


def matches(keyword, query):
    """True if keyword appears as a whole word in query (case-insensitive)."""
    return re.search(r"\b" + re.escape(keyword) + r"\b", query.lower()) is not None


def select(query):
    """Return the best-matching Command for query, or None if none match."""
    best, best_score = None, 0
    for cmd in _registry:
        score = sum(1 for kw in cmd.keywords if matches(kw, query))
        if score > best_score:
            best, best_score = cmd, score
    return best


def dispatch(query, fallback):
    """Run the best-matching command's handler, or fallback(query)."""
    cmd = select(query)
    (cmd.handler if cmd else fallback)(query)
