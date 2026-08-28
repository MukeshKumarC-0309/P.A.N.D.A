"""Cowrie event source — the LIVE (Splunk) entry point for the Cowrie crew.

Phase 2.1 Step 2. The Cowrie parallel to windows_source.get_windows_records:
pull raw cowrie events from Splunk (splunk_client) and structure them into
CowrieRecords (cowrie_records). Kept in its own module so cowrie_records.py
stays free of the Splunk SDK dependency and remains unit-testable with plain
dicts.

This is the pipeline's LIVE source. The file-based cowrie_detector.parse_lines
path stays as-is for the standalone CLI artifact (Repo Structure rule) — this
adds a Splunk-source path alongside it, it does not replace it.
"""

from panda_tdr.splunk_client import get_cowrie_events_raw, DEFAULT_EARLIEST
from panda_tdr.cowrie_records import structure_cowrie_events


def get_cowrie_records(service=None, earliest=DEFAULT_EARLIEST, latest="now"):
    """Pull cowrie events from Splunk and return CowrieRecords.

    `service` lets a caller reuse one Splunk connection across pulls (e.g. share
    it with get_windows_records so the whole pipeline is one connection); if
    omitted, the pull opens its own. Returns list[CowrieRecord] — the same shape
    the file-based parser yields, so the correlation layer is source-agnostic.
    """
    rows = get_cowrie_events_raw(service=service, earliest=earliest, latest=latest)
    return structure_cowrie_events(rows)
