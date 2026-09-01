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
from panda import router, db, bridge
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


def _print_scan_summary(s):
    """Print what a TDR scan wrote to the case store."""
    print("-" * 60)
    print("P.A.N.D.A TDR : scan complete")
    print("-" * 60)
    if s["fresh"]:
        print(" (fresh scan — cleared previously stored cases)")
    print(f" Source               : {s['source']}")
    print(f" Cases persisted      : {s['cases']}")
    print(f"   kill chains        : {s['chains']}")
    print(f"   brute/spray        : {s['brute_spray']}")
    print(f"   account creations  : {s['account_creations']}")
    print(f"   correlations       : {s['correlations']}")
    print(f" Detections           : {s['detections']}")
    if s["ai_polish"]:
        print(f" Reports              : {s['reports']} — LLM-polished "
              f"({s['polished']} polished, {s['polish_fallbacks']} fell back)")
    else:
        print(f" Reports              : {s['reports']} — deterministic "
              f"(AI extra not installed)")
    print(f" Skipped (subsumed by a chain) : "
          f"{s['skipped_brute_spray']} brute/spray, "
          f"{s['skipped_account_creations']} account creation(s)")
    print("-" * 60)
    print("P.A.N.D.A : Use the CASES command to browse them.")


def _print_anomaly_summary(s):
    """Print the result of an unsupervised anomaly scan."""
    print("-" * 60)
    print("P.A.N.D.A TDR : anomaly scan (advisory)")
    print("-" * 60)
    print(f" Source               : {s['source']}")
    if s["insufficient"]:
        print(f" Insufficient data    : {s['n_sources']} distinct source(s); "
              f"need >= {s['min_sources']} to model.")
        print(" Point at a larger capture (PANDA_SNAPSHOT) or run TDR LIVE.")
    else:
        print(f" Sources modeled      : {s['n_sources']}")
        print(f" Anomaly candidates   : {s['persisted']} (low-confidence cases)")
        for ip, score in s["candidates"]:
            print(f"   - {ip}  (score {score})")
        print("-" * 60)
        print("P.A.N.D.A : Review them with CASES and mark a verdict.")


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
    if router.matches("anomaly", query):
        action = lambda: _print_anomaly_summary(bridge.scan_anomalies(
            snapshot_path=config.SNAPSHOT_PATH, live=live))
    else:
        action = lambda: _print_scan_summary(bridge.scan_and_persist(
            snapshot_path=config.SNAPSHOT_PATH, live=live, fresh=fresh))
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
        query = takecommand()
        if router.matches("quit", query):
            break
        try:
            router.dispatch(query, fallback)
        except Exception:  # a bad command must not kill the whole session
            print("P.A.N.D.A : Something went wrong with that command. Please try again.")


if __name__ == "__main__":
    main()
