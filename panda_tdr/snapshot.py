"""Offline source — load the exported Splunk snapshot into structured records.

The lab-off counterpart to a live Splunk pull: instead of querying Splunk, it
reads the fixture in test_data/ and runs the SAME structuring functions, so it
returns identical record types. The Windows detectors (brute/spray,
account-creation, multi-stage chain) consume the three Windows inputs; the
correlation layer additionally consumes the cowrie records. Stdlib only — no
network, no API key. (The cowrie structuring uses a local record type, not the
external cowrie_detector parser; see panda_tdr/cowrie_records.py.)
"""

import json
import pathlib

from panda_tdr.cowrie_records import structure_cowrie_events
from panda_tdr.windows_records import (
    structure_failed_logins,
    structure_successful_logins,
)

DEFAULT_SNAPSHOT = (
    pathlib.Path(__file__).resolve().parent.parent
    / "test_data" / "splunk_snapshot.json"
)


def load_snapshot(path=DEFAULT_SNAPSHOT):
    """Load the snapshot fixture and return the pipeline's inputs.

    Returns a dict:
      cowrie          list[CowrieRecord]   (honeypot events, for correlation)
      failed          list[WindowsRecord]  (4625 failed logons)
      success         list[WindowsRecord]  (4624 Type 3 successful logons)
      creation_rows   list[dict]           (raw 4720 rows)

    The account-creation side stays raw because detect_account_creations does
    the creator/built-in filtering itself — mirroring how a live pull would
    feed it raw Splunk rows, not pre-structured records.
    """
    data = json.loads(pathlib.Path(path).read_text(encoding="utf-8"))
    return {
        "cowrie": structure_cowrie_events(data["cowrie"]),
        "failed": structure_failed_logins(data["failed_logins"]),
        "success": structure_successful_logins(data["successful_logons"]),
        "creation_rows": data["account_creations"],
    }
