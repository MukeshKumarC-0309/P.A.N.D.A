"""
P.A.N.D.A entry point: startup banner, command loop, and command
registration.

PANDA is a security platform. Its record system is an encrypted vault
(hardened auth, AES + HMAC at rest) that serves as the secure store for
the PANDA TDR threat-detection engine. Routing is handled by
panda/router.py: each command registers keywords and a handler(query);
new capabilities (e.g. TDR commands) register without editing this loop.
"""
from panda.system import help, banner, takecommand
from panda.auth import password, check_password
from panda.vault import DATABASE
from panda.browse import browse_cases
from panda import router, db, bridge, ui
import config


# ---------------------------------------------------------------------------
# Command handlers. Each takes the raw query string (some ignore it).
# ---------------------------------------------------------------------------

def _password_not_set():
    """The shared 'no password yet' notice, printed before prompting to set one."""
    print("P.A.N.D.A : Password hasn't been set yet.")
    print('P.A.N.D.A : Please set the password now.')


def _in_unlocked_vault(action):
    """Authenticate (up to 3 tries), unlock the vault, run action(), re-lock.

    The one auth+unlock+lock primitive, shared by every command that needs an
    unlocked vault (VAULT / TDR / CASES). The vault is re-encrypted in a
    `finally`, so a normal return or an error inside action() still saves.
    Raises FileNotFoundError (from check_password) when no password is set yet,
    so the caller can prompt the user to set one.
    """
    n = 0
    while n < 3:
        p = input("P.A.N.D.A : Enter your password - ")
        if check_password(p):
            db.unlock(p)
            try:
                action()
            finally:
                db.lock(p)        # re-encrypt on exit, even if action() errors
            return
        print("P.A.N.D.A : Incorrect Password.")
        print("P.A.N.D.A : Try Again")
        n += 1
    print("P.A.N.D.A : ACCESS DENIED")
    print("P.A.N.D.A : You do not have access to the vault.")


def _open_vault_session():
    """The VAULT command's action: print the banner, then run the record shell."""
    print("-" * 60)
    print('PANDA VAULT')
    print('-' * 60)
    DATABASE()


def handle_vault(query):
    try:
        _in_unlocked_vault(_open_vault_session)
    except FileNotFoundError:
        _password_not_set()
        password()
        _in_unlocked_vault(_open_vault_session)


def handle_change(query):
    try:
        p = input("P.A.N.D.A : Enter current password - ")
        if check_password(p):
            print('P.A.N.D.A : You can change your password now. ')
            db.unlock(p)                 # load the vault with the current key
            new_password = password()    # sets the new hash, returns the raw pw
            db.lock(new_password)        # re-encrypt the vault under the new key
            print("P.A.N.D.A : Password updated successfully.")
        else:
            print("P.A.N.D.A : Error, invalid input.")
    except FileNotFoundError:
        _password_not_set()
        password()


def _kv_panel(rows, title):
    """A borderless key/value table inside a titled cyan panel."""
    from rich.panel import Panel
    from rich.table import Table

    t = Table(box=None, show_header=False)
    t.add_column(style="muted", justify="right")
    t.add_column()
    for key, value in rows:
        t.add_row(key, value)
    ui.console.print(Panel(t, title=title, border_style="cyan", expand=False))


def _print_scan_summary(s):
    """Render what a TDR scan wrote to the case store."""
    reports = ("{} — LLM-polished ({} polished, {} fell back)".format(
                   s["reports"], s["polished"], s["polish_fallbacks"])
               if s["ai_polish"] else
               "{} — [muted]deterministic (AI extra not installed)[/muted]".format(s["reports"]))
    rows = [
        ("Source", s["source"]),
        ("Cases persisted", "[bold]{}[/bold]".format(s["cases"])),
        ("  kill chains", str(s["chains"])),
        ("  brute / spray", str(s["brute_spray"])),
        ("  account creations", str(s["account_creations"])),
        ("  correlations", str(s["correlations"])),
        ("Detections", str(s["detections"])),
        ("Reports", reports),
        ("Skipped (subsumed)", "{} brute/spray, {} account creation(s)".format(
            s["skipped_brute_spray"], s["skipped_account_creations"])),
    ]
    if s["skipped_duplicate"]:
        rows.append(("Skipped (already recorded)", str(s["skipped_duplicate"])))
    title = "[title]TDR scan complete[/title]" + (" [muted](fresh)[/muted]" if s["fresh"] else "")
    _kv_panel(rows, title)
    ui.console.print("[muted]Use [bold]CASES[/bold] to browse them.[/muted]")


def _print_anomaly_summary(s):
    """Render the result of an unsupervised anomaly scan."""
    if s["insufficient"]:
        rows = [
            ("Source", s["source"]),
            ("Insufficient data",
             "{} distinct source(s); need >= {} to model.".format(s["n_sources"], s["min_sources"])),
            ("", "[muted]Point at a larger capture (PANDA_SNAPSHOT) or run TDR LIVE.[/muted]"),
        ]
        _kv_panel(rows, "[title]TDR anomaly scan (advisory)[/title]")
        return
    rows = [
        ("Source", s["source"]),
        ("Sources modeled", str(s["n_sources"])),
        ("Anomaly candidates", "[bold]{}[/bold] (low-confidence cases)".format(s["persisted"])),
    ]
    for ip, score in s["candidates"]:
        rows.append(("", "[bold]{}[/bold]  [muted]score {}[/muted]".format(ip, score)))
    _kv_panel(rows, "[title]TDR anomaly scan (advisory)[/title]")
    if s["persisted"]:
        ui.console.print("[muted]Review them with [bold]CASES[/bold] and mark a verdict.[/muted]")
    else:
        ui.console.print("[muted]No outliers flagged — nothing stood out from the baseline.[/muted]")


def handle_tdr(query):
    """Run the TDR engine and persist findings.

    Offline snapshot by default; `tdr live` pulls from Splunk when the [live]
    extra is installed and configured, else degrades to the snapshot. `tdr fresh`
    clears previously stored cases first (rebuild, not append). `tdr anomaly`
    runs the unsupervised anomaly layer instead (advisory low-confidence cases).
    Set PANDA_SNAPSHOT to point a scan at a different capture (e.g. a larger
    real dataset).
    """
    live = router.matches("live", query)
    fresh = router.matches("fresh", query)
    note = "Pulling from Splunk…" if live else "Scanning telemetry…"

    def action():
        if router.matches("anomaly", query):
            with ui.console.status("[title]{}[/title]".format(note), spinner="dots"):
                s = bridge.scan_anomalies(snapshot_path=config.SNAPSHOT_PATH, live=live)
            _print_anomaly_summary(s)
        else:
            with ui.console.status("[title]{}[/title]".format(note), spinner="dots"):
                s = bridge.scan_and_persist(snapshot_path=config.SNAPSHOT_PATH, live=live, fresh=fresh)
            _print_scan_summary(s)

    try:
        _in_unlocked_vault(action)
    except FileNotFoundError:
        _password_not_set()
        password()


def handle_cases(query):
    """Browse the stored TDR cases inside an unlocked vault session."""
    try:
        _in_unlocked_vault(browse_cases)
    except FileNotFoundError:
        _password_not_set()
        password()


def fallback(query):
    print("P.A.N.D.A : Unknown command. Type HELP to see what I can do.")


# ---------------------------------------------------------------------------
# Register the security commands. (TDR will register its own here later.)
# ---------------------------------------------------------------------------

router.register("vault", ["vault"], handle_vault)
router.register("set", ["set"], lambda q: password())
router.register("change", ["change"], handle_change)
router.register("tdr", ["tdr"], handle_tdr)
router.register("cases", ["cases"], handle_cases)
router.register("help", ["help"], lambda q: help())


def main():
    banner()
    while True:
        try:
            query = takecommand()
        except (KeyboardInterrupt, EOFError):
            # Ctrl+C / Ctrl+D at the prompt: exit cleanly, no traceback.
            ui.console.print("\n[muted]Goodbye.[/muted]")
            break
        if router.matches("quit", query):
            break
        try:
            router.dispatch(query, fallback)
        except (KeyboardInterrupt, EOFError):
            # Ctrl+C / Ctrl+D mid-command: cancel it and return to the prompt.
            # (The vault re-locks in _in_unlocked_vault's finally regardless.)
            ui.console.print("\n[muted]Cancelled.[/muted]")
        except Exception:  # a bad command must not kill the whole session
            ui.err("Something went wrong with that command. Please try again.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass  # final safety net (e.g. Ctrl+C during startup)
