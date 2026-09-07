"""Shared rich console + small styling helpers for the PANDA CLI.

One Console instance keeps the look consistent, and rich degrades gracefully on
its own: it renders plain text when output isn't a terminal (tests, pipes),
respects NO_COLOR, and picks safe box characters on legacy Windows consoles — so
we don't hand-manage ANSI or Unicode fallbacks.

Kept deliberately restrained: a calm, consistent palette (severity / disposition
/ status), not decoration for its own sake — the goal is a tool that's pleasant
to use daily, not flashy for ten seconds.
"""
import sys

from rich.console import Console
from rich.theme import Theme

_THEME = Theme({
    "title": "bold cyan",
    "muted": "dim",
    "ok": "bold green",
    "warn": "yellow",
    "err": "bold red",
    "sev.critical": "bold red",
    "sev.high": "red",
    "sev.medium": "yellow",
    "sev.low": "dim",
    "disp.confirmed": "red",
    "disp.false_positive": "dim",
    "disp.benign": "green",
})

# In a real terminal, let rich auto-detect the width; when output is captured or
# piped (no tty), fix a comfortable width so tables aren't crushed to 80 columns.
_interactive = bool(getattr(sys.stdout, "isatty", lambda: False)())
console = Console(theme=_THEME, highlight=False,
                  width=None if _interactive else 120)


def _tagged(value, prefix):
    """Return value wrapped in a theme style named "<prefix>.<value>", if that
    style exists — else the value unchanged. Used for severity / disposition."""
    if not value:
        return value or ""
    style = "{}.{}".format(prefix, value.lower())
    return "[{0}]{1}[/{0}]".format(style, value) if style in _THEME.styles else value


def severity(value):
    """Rich-markup severity string, colored by level (plain if unknown/None)."""
    return _tagged(value, "sev")


def disposition(value):
    """Rich-markup analyst-verdict string (plain if unknown/None/unreviewed)."""
    return _tagged(value, "disp")


def ok(message):
    console.print("[ok]✓[/ok] " + message)


def warn(message):
    console.print("[warn]⚠[/warn] " + message)


def err(message):
    console.print("[err]✗[/err] " + message)
