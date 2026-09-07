"""
Console I/O for the PANDA CLI: the startup banner, the help text, and the
command prompt.

The banner and help render with rich (see panda/ui.py); the prompt uses a small
ANSI helper so the monkeypatch-friendly builtins.input still drives it. Both
degrade gracefully — plain text when output isn't a terminal or NO_COLOR is set.
"""
import os
import sys

# ANSI SGR codes used below.
_RESET = "\033[0m"
BOLD, DIM, BRIGHT_GREEN = 1, 2, 92


def _color_supported():
    if os.environ.get("NO_COLOR"):
        return False
    if not sys.stdout.isatty():
        return False
    if os.name == "nt":
        # Enable virtual-terminal processing so ANSI works in legacy consoles.
        try:
            import ctypes
            k = ctypes.windll.kernel32
            h = k.GetStdHandle(-11)
            mode = ctypes.c_uint32()
            k.GetConsoleMode(h, ctypes.byref(mode))
            k.SetConsoleMode(h, mode.value | 0x0004)
        except Exception:
            return False
    return True


def _unicode_supported():
    return "utf" in (getattr(sys.stdout, "encoding", "") or "").lower()


_COLOR = _color_supported()
_FANCY = _unicode_supported()


def _style(text, *codes):
    """Wrap text in ANSI codes when color is on, else return it unchanged."""
    if not _COLOR or not codes:
        return text
    return "".join("\033[{}m".format(c) for c in codes) + text + _RESET


def _version():
    try:
        from importlib.metadata import version
        return "v" + version("panda-tdr")
    except Exception:
        return ""


def banner():
    from rich.panel import Panel
    from panda import ui

    version = _version()
    logo = "[title]🐼  P.A.N.D.A[/title]" + (f"  [muted]{version}[/muted]" if version else "")
    body = logo + "\n[cyan]Secure vault · threat-detection platform[/cyan]"
    ui.console.print()
    ui.console.print(Panel.fit(body, border_style="cyan", padding=(0, 2)))
    ui.console.print(
        "[muted]Type[/muted] [bold]HELP[/bold] [muted]for commands ·[/muted] "
        "[bold]QUIT[/bold] [muted]to exit[/muted]")
    ui.console.print()


def help():
    from rich import box
    from rich.panel import Panel
    from rich.table import Table
    from panda import ui

    t = Table(box=box.SIMPLE, show_header=False, padding=(0, 2), expand=False)
    t.add_column(style="bold green", no_wrap=True)
    t.add_column()
    t.add_row("VAULT", "Unlock the encrypted vault to view/edit your records")
    t.add_row("TDR", "Scan the threat telemetry and store findings as cases")
    t.add_row("", "[muted]TDR FRESH rebuilds · TDR LIVE pulls from Splunk · "
                  "TDR ANOMALY runs the anomaly layer[/muted]")
    t.add_row("CASES", "Browse the stored TDR cases, detections and reports")
    t.add_row("SET", "Set the vault password (first-time setup)")
    t.add_row("CHANGE", "Change the vault password (re-encrypts the vault)")
    t.add_row("HELP", "Show this list")
    t.add_row("QUIT", "Exit PANDA")
    ui.console.print(Panel(t, title="[title]COMMANDS[/title]",
                           border_style="cyan", expand=False))


def takecommand():
    arrow = "› " if _FANCY else "> "
    return input(_style("YOU ", BOLD, BRIGHT_GREEN) + _style(arrow, DIM))
