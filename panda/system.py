"""
Console I/O for the PANDA CLI: a styled startup banner, the command prompt, and
the help text.

Styling is stdlib-only and degrades gracefully — no ANSI color when the output
isn't a terminal or NO_COLOR is set, and ASCII fallbacks when the console can't
encode box-drawing characters / emoji. So it looks good in a modern terminal and
stays correct everywhere else (tests, pipes, legacy code pages).
"""
import os
import sys

# ANSI SGR codes used below.
_RESET = "\033[0m"
BOLD, DIM = 1, 2
GREEN, BRIGHT_GREEN = 32, 92
CYAN, BRIGHT_CYAN = 36, 96


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


def _rule(width=62):
    return _style((("═" if _FANCY else "=") * width), DIM, CYAN)


def banner():
    logo = ("🐼  " if _FANCY else "") + "P.A.N.D.A"
    version = _version()
    dot = " · " if _FANCY else " | "
    print()
    print(_rule())
    print("  " + _style(logo, BOLD, BRIGHT_CYAN)
          + (("   " + _style(version, DIM)) if version else ""))
    print("  " + _style("Secure vault " + ("·" if _FANCY else "+")
                        + " threat-detection platform", CYAN))
    print(_rule())
    print("  " + _style("Type ", DIM) + _style("HELP", BOLD)
          + _style(dot, DIM) + _style("QUIT", BOLD) + _style(" to exit", DIM))
    print()


def help():
    sep = ("─" if _FANCY else "-") * 58
    dot = " · " if _FANCY else " - "

    def cmd(name, desc):
        print("  " + _style(name.ljust(7), BOLD, GREEN) + _style(dot, DIM) + desc)

    print()
    print("  " + _style("COMMANDS", BOLD, BRIGHT_CYAN))
    print("  " + _style(sep, DIM))
    cmd("VAULT", "Unlock the encrypted vault to view/edit your records")
    cmd("TDR", "Scan the threat telemetry and store findings as cases")
    print("  " + _style(" " * 10 + "TDR FRESH rebuilds  ·  TDR LIVE pulls from Splunk", DIM))
    print("  " + _style(" " * 10 + "TDR ANOMALY runs the unsupervised anomaly layer", DIM))
    cmd("CASES", "Browse the stored TDR cases, detections and reports")
    cmd("SET", "Set the vault password (first-time setup)")
    cmd("CHANGE", "Change the vault password (re-encrypts the vault)")
    cmd("HELP", "Show this list")
    cmd("QUIT", "Exit PANDA")
    print("  " + _style(sep, DIM))
    print()


def takecommand():
    arrow = "› " if _FANCY else "> "
    return input(_style("YOU ", BOLD, BRIGHT_GREEN) + _style(arrow, DIM))
