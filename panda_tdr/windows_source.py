"""Windows Event Log source — the standalone entry point for the Windows crew.

Composes the two halves: pull raw failed-login events from Splunk
(splunk_client) and structure them into WindowsRecords (windows_records).
Kept in its own module so windows_records.py stays free of the Splunk SDK
dependency (its structuring logic is unit-testable with plain dicts, no network).

This is the Windows-side parallel to calling cowrie_detector.parse_lines: one
importable function that yields structured records, later wrapped as a CrewAI
@tool (Phase 1.4 Step 5).
"""

from panda_tdr.splunk_client import get_failed_logins_raw, DEFAULT_EARLIEST
from panda_tdr.windows_records import structure_failed_logins


def get_windows_records(service=None, earliest=DEFAULT_EARLIEST, latest="now"):
    """Pull failed-login (4625) events from Splunk and return WindowsRecords.

    `service` lets a caller reuse one Splunk connection; if omitted, the pull
    opens its own. Returns a list[WindowsRecord] with the correlation triple
    (timestamp, src_ip, username) — the same shape the Cowrie side produces.
    """
    rows = get_failed_logins_raw(service=service, earliest=earliest, latest=latest)
    return structure_failed_logins(rows)
