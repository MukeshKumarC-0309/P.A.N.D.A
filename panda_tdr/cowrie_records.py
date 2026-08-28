"""Structure raw Cowrie rows into CowrieRecords.

Vendored from the TDR repo with ONE change: the external cowrie_detector
package (a Cowrie-log file parser) is not a dependency here, so its
`CowrieRecord` type is replaced by the local lightweight record below. The
structuring logic — keying timestamp on Splunk `_time` (not the multivalue
`timestamp` field), cleaning `-`/`''`/`none` to None — is kept verbatim, so the
offline snapshot path produces records identical to the live path and the two
never silently diverge.

The correlation layer only reads a handful of attributes (src_ip, username,
timestamp, eventid, message) and duck-types on them, so a faithful local record
is all it needs. Kept free of any parser/SDK so the mapping stays unit-testable
with plain dicts — no file, no network.
"""

from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class CowrieRecord:
    """One structured Cowrie event.

    Mirrors the public shape of cowrie_detector.CowrieRecord (the live/file
    parser's output) field-for-field, so records built here are drop-in
    identical for downstream code. frozen=True: immutable once built.
    """

    # Required — present on every usable event.
    session: str
    eventid: str
    src_ip: str
    timestamp: str  # raw ISO string; datetime conversion is the correlation layer's job

    # Optional context.
    username: Optional[str] = None
    src_port: Optional[int] = None
    dst_ip: Optional[str] = None
    dst_port: Optional[int] = None
    password: Optional[str] = None
    sensor: Optional[str] = None
    message: Optional[str] = None


# The required set, keyed on the Splunk column names (its `timestamp` maps to
# Splunk `_time`, guaranteed present, so it isn't listed here). A row missing any
# of these can't be placed in a session or correlated, so it's dropped rather
# than admitted half-empty — false-negative-averse, like the live path.
_REQUIRED = ("session", "eventid", "src_ip")


def _clean(value):
    """Normalize one Splunk value.

    '-', '', 'none' and None all collapse to None (Splunk renders a null field
    variously as '-' or the literal string 'none'). A multivalue list collapses
    to its first meaningful entry — defensive: we key on the single-valued _time,
    not the polluted `timestamp`, but a surprise multivalue username/message
    shouldn't crash the mapping.
    """
    if isinstance(value, list):
        for v in value:
            cleaned = _clean(v)
            if cleaned is not None:
                return cleaned
        return None
    return value if value not in (None, "-", "", "none") else None


def _int_or_none(value):
    """Coerce a Splunk numeric column (returned as a string, e.g. '54800') to int.

    Keeps src_port as Optional[int], matching the record contract. Tolerates
    missing/junk as None rather than raising.
    """
    value = _clean(value)
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def structure_cowrie_events(rows):
    """Map raw Cowrie dicts (from the snapshot) into CowrieRecords.

    Each dict carries _time plus the tabled cowrie fields. Rows missing a
    required field (session/eventid/src_ip) are skipped, never admitting a
    half-empty record. Returns list[CowrieRecord].

    dst_ip / dst_port / sensor are left at their defaults (None): pure context,
    unused downstream — same "map only what's needed" discipline as the live pull.
    """
    records = []
    for row in rows:
        if not all(_clean(row.get(field)) is not None for field in _REQUIRED):
            continue
        records.append(
            CowrieRecord(
                session=_clean(row["session"]),
                eventid=_clean(row["eventid"]),
                src_ip=_clean(row["src_ip"]),
                timestamp=row["_time"],  # _time, not the raw multivalue `timestamp`
                username=_clean(row.get("username")),
                src_port=_int_or_none(row.get("src_port")),
                password=_clean(row.get("password")),
                message=_clean(row.get("message")),
            )
        )
    return records
