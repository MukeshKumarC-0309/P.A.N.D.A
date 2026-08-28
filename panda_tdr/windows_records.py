"""Structured records for the Windows Event Log crew.

Turns the raw dicts pulled from Splunk (splunk_client.py) into typed
WindowsRecords — the Windows-side parallel to cowrie_detector's CowrieRecord.
The join keys (src_ip, username, timestamp) are named to match CowrieRecord so
the correlation layer (Phase 1.5) can outer-join both sources on the same fields.
"""

from collections import OrderedDict
from dataclasses import dataclass
from datetime import datetime
from typing import Optional


@dataclass(frozen=True)
class WindowsRecord:
    """One structured Windows event.

    frozen=True mirrors CowrieRecord: immutable once built. timestamp stays a raw
    string (datetime conversion is Phase 1.5's job). src_ip / username are
    optional because a 4625 event can carry "-" for the source address and its
    Account_Name can resolve to no real user.
    """

    timestamp: str  # raw ISO string from Splunk _time
    event_id: str   # Windows Event ID, e.g. "4625"
    src_ip: Optional[str] = None   # from Source_Network_Address
    username: Optional[str] = None  # resolved from (multivalue) Account_Name
    host: Optional[str] = None      # the Windows host that logged the event
    logon_type: Optional[str] = None  # Splunk Logon_Type: "3"=network, "2"=interactive


def _clean(value):
    """Normalize a single Splunk value: '-' / '' / None all become None."""
    return value if value not in (None, "-", "") else None


def _real_username(account_name):
    """Collapse a (possibly multivalue) Account_Name to the real username.

    A 4625 event extracts two account names — the Subject account (often '-' or
    a machine account) and the Target account (the user who failed to log on).
    Splunk returns them as a list. Pick the first meaningful value; drop '-'.
    """
    candidates = account_name if isinstance(account_name, list) else [account_name]
    for name in candidates:
        cleaned = _clean(name)
        if cleaned is not None:
            return cleaned
    return None


def structure_failed_logins(rows):
    """Structure raw failed-login (4625) dicts into a list of WindowsRecords.

    `rows` is the output of splunk_client.get_failed_logins_raw() — each dict has
    _time, Account_Name, Source_Network_Address.
    """
    return [
        WindowsRecord(
            timestamp=row["_time"],
            event_id="4625",
            src_ip=_clean(row.get("Source_Network_Address")),
            username=_real_username(row.get("Account_Name")),
            host=_clean(row.get("host")),
            logon_type=_clean(row.get("Logon_Type")),
        )
        for row in rows
    ]


def structure_successful_logins(rows):
    """Structure raw successful network-logon (4624 Type 3) dicts into WindowsRecords.

    Mirrors structure_failed_logins but stamps event_id="4624". The multivalue
    Account_Name is [Subject, New Logon]; _real_username skips the '-' Subject and
    lands on the New Logon account (the identity that actually logged on) — the
    same helper the 4625 side uses, no special-casing needed.
    """
    return [
        WindowsRecord(
            timestamp=row["_time"],
            event_id="4624",
            src_ip=_clean(row.get("Source_Network_Address")),
            username=_real_username(row.get("Account_Name")),
            host=_clean(row.get("host")),
            logon_type=_clean(row.get("Logon_Type")),
        )
        for row in rows
    ]


def summarize_failed_logins(records):
    """Group failed-login WindowsRecords by (src_ip, username) into summaries.

    Deterministic and lossless: every record is counted (sum of attempt_count
    == len(records)), nothing is filtered. Each summary is one (source IP,
    targeted account) pair — the correlation keys — with the attempt count, the
    time span, and the host(s) attacked. It records everything and judges
    nothing; the signal-vs-noise verdict belongs to the correlation layer.
    """
    groups = OrderedDict()

    for r in records:
        key = (r.src_ip, r.username)
        g = groups.get(key)
        if g is None:
            g = {
                "src_ip": r.src_ip,
                "username": r.username,
                "attempt_count": 0,
                "hosts": set(),
                "_timestamps": [],
            }
            groups[key] = g

        g["attempt_count"] += 1
        g["_timestamps"].append(r.timestamp)
        if r.host:
            g["hosts"].add(r.host)

    summaries = []
    for g in groups.values():
        stamps = sorted(g.pop("_timestamps"))
        first, last = stamps[0], stamps[-1]
        span = (datetime.fromisoformat(last) - datetime.fromisoformat(first)).total_seconds()
        g["first_seen"] = first
        g["last_seen"] = last
        g["span_seconds"] = round(span, 3)
        g["hosts"] = sorted(g["hosts"])
        summaries.append(g)

    return summaries
