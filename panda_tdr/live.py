"""Live source — pull the pipeline's inputs from Splunk (the `[live]` extra).

The online counterpart to snapshot.load_snapshot: it returns the SAME dict shape
(cowrie / failed / success / creation_rows), so the bridge consumes it
unchanged — only the source swaps from the fixture to a live Splunk pull.

Core stays offline: splunk-sdk and the SDK-dependent source modules are imported
ONLY inside load_live, never at module import. `live_available()` guards both
failure modes — the SDK not installed, and no Splunk credentials configured — so
the default run never needs Splunk and a live request degrades cleanly to the
snapshot rather than crashing.

Actually pulling needs Splunk reachable (SPLUNK_HOST/USER/PASSWORD) — i.e. the
lab up. Building and testing this module does not: the availability logic is
env-only, and the bridge's live path is exercised by injecting a fake loader.
"""

import os


def live_available():
    """True only if the [live] extra is usable: splunklib importable AND creds set.

    Checks credentials first (cheap) so a core install never imports splunklib.
    Covers both "extra not installed" and "installed but unconfigured", so a
    missing credential degrades to the snapshot instead of raising at pull time.
    """
    if not (os.getenv("SPLUNK_USER") and os.getenv("SPLUNK_PASSWORD")):
        return False
    try:
        import splunklib  # noqa: F401
    except ImportError:
        return False
    return True


def load_live(earliest=None, latest="now"):
    """Pull the four pipeline inputs from Splunk over one shared connection.

    Returns the same dict load_snapshot returns. splunk-sdk and the source
    modules are imported here (lazily) so importing this module never requires
    the SDK. One `service` is reused across all four pulls.
    """
    from panda_tdr.splunk_client import (
        DEFAULT_EARLIEST,
        get_account_creations_raw,
        get_service,
        get_successful_logons_raw,
    )
    from panda_tdr.cowrie_source import get_cowrie_records
    from panda_tdr.windows_records import structure_successful_logins
    from panda_tdr.windows_source import get_windows_records

    earliest = earliest or DEFAULT_EARLIEST
    service = get_service()  # one connection, reused across the pulls below
    return {
        "cowrie": get_cowrie_records(service=service, earliest=earliest, latest=latest),
        "failed": get_windows_records(service=service, earliest=earliest, latest=latest),
        "success": structure_successful_logins(
            get_successful_logons_raw(service=service, earliest=earliest, latest=latest)),
        "creation_rows": get_account_creations_raw(
            service=service, earliest=earliest, latest=latest),
    }
