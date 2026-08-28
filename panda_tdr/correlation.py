"""Correlation layer — combines Cowrie and Windows records into alerts.

Phase 1.5 Step 1: the feature-engineering merge only. Takes per-event records
from both sources and outer-joins them on src_ip (IP-primary), producing one
dataframe with seen_in_cowrie / seen_in_windows provenance flags. No time-window
matching (Step 2), no username fallback (Step 3), no scoring here — just the
substrate the later steps operate on.

Records are passed in (dependency-injected), not fetched, so this stays pure and
testable with fabricated records — no Cowrie file, no Splunk connection needed.
"""

import pandas as pd

_COWRIE_COLUMNS = ["src_ip", "cowrie_username", "cowrie_timestamp", "cowrie_eventid"]
_WINDOWS_COLUMNS = [
    "src_ip",
    "windows_username",
    "windows_timestamp",
    "windows_event_id",
    "windows_host",
    "windows_logon_type",
]


def build_correlation_frame(cowrie_records, windows_records):
    """Outer-join Cowrie + Windows records on src_ip into one dataframe.

    Non-key columns are source-prefixed (cowrie_* / windows_*) so nothing
    collides on merge. seen_in_cowrie / seen_in_windows come from the merge
    indicator: an src_ip present in both sources yields paired rows (the match
    candidates Step 2 will time-filter); an src_ip in only one source is kept
    with NaN on the other side's columns (an outer, not inner, join — single-
    source events are never silently dropped). Timestamps stay raw strings;
    datetime conversion belongs to Step 2 when the time windows are applied.
    """
    cowrie_df = pd.DataFrame(
        [
            {
                "src_ip": r.src_ip,
                "cowrie_username": r.username,
                "cowrie_timestamp": r.timestamp,
                "cowrie_eventid": r.eventid,
            }
            for r in cowrie_records
        ],
        columns=_COWRIE_COLUMNS,
    )
    windows_df = pd.DataFrame(
        [
            {
                "src_ip": r.src_ip,
                "windows_username": r.username,
                "windows_timestamp": r.timestamp,
                "windows_event_id": r.event_id,
                "windows_host": r.host,
                "windows_logon_type": r.logon_type,
            }
            for r in windows_records
        ],
        columns=_WINDOWS_COLUMNS,
    )

    merged = cowrie_df.merge(windows_df, on="src_ip", how="outer", indicator=True)

    # Map the merge indicator to explicit provenance flags, then drop it.
    merged["seen_in_cowrie"] = merged["_merge"].isin(["both", "left_only"])
    merged["seen_in_windows"] = merged["_merge"].isin(["both", "right_only"])
    merged = merged.drop(columns="_merge")

    return merged


# 5-minute window for IP-based matching (locked correlation spec).
IP_WINDOW_SECONDS = 5 * 60


def match_ip_primary(merged, window_seconds=IP_WINDOW_SECONDS):
    """Filter the merged frame to IP-primary matches within the time window.

    A match is a row seen in BOTH sources (same src_ip) whose Cowrie and Windows
    timestamps are within `window_seconds` of each other. Adds a
    time_delta_seconds column (absolute gap) and returns only the matching rows.

    Timestamps are parsed to UTC-aware datetimes first: Cowrie stamps are 'Z'
    (UTC) and Windows stamps carry an offset (e.g. +05:30), so without utc=True
    the delta would be wrong by that offset. Single-source rows have a NaT on one
    side, so their delta is NaT and they're excluded — this step is only about
    the IP-primary path (username fallback is Step 3).
    """
    both = merged[merged["seen_in_cowrie"] & merged["seen_in_windows"]].copy()

    cowrie_ts = pd.to_datetime(both["cowrie_timestamp"], utc=True, format="ISO8601")
    windows_ts = pd.to_datetime(both["windows_timestamp"], utc=True, format="ISO8601")
    both["time_delta_seconds"] = (cowrie_ts - windows_ts).abs().dt.total_seconds()

    matches = both[both["time_delta_seconds"] <= window_seconds]
    return matches.reset_index(drop=True)


# 3-minute window for username-fallback matching (locked correlation spec).
USERNAME_WINDOW_SECONDS = 3 * 60


def _normalize_username(username):
    """Normalize a username for cross-source matching.

    Lowercase and strip a DOMAIN\\ prefix, so format differences don't block a
    match (Administrator == administrator == CORP\\Administrator). The trailing
    '$' on machine accounts is deliberately KEPT — it's an identity marker, not a
    format artifact, and excluding machine accounts is the deny-list's job
    (Step 4). Semantic equivalence like root<->Administrator is NOT done here: the
    fallback fires when IPs differ, so there's no IP to corroborate it — that's a
    Step 6 confidence signal, not a match key.
    """
    if username is None:
        return None
    u = username.strip().lower()
    if "\\" in u:
        u = u.rsplit("\\", 1)[-1]  # drop DOMAIN\ prefix, keep the account name
    return u or None


_UF_COWRIE_COLS = [
    "norm_username", "cowrie_username", "cowrie_src_ip",
    "cowrie_timestamp", "cowrie_eventid",
]
_UF_WINDOWS_COLS = [
    "norm_username", "windows_username", "windows_src_ip",
    "windows_timestamp", "windows_event_id", "windows_host", "windows_logon_type",
]


def match_username_fallback(cowrie_records, windows_records, window_seconds=USERNAME_WINDOW_SECONDS):
    """Match on normalized username within the window, across DIFFERENT IPs.

    The fallback for when IP-primary (Step 2) can't connect the two sides — e.g.
    an attacker reusing a username from a rotated IP. Merges on the normalized
    username (inner: only where usernames match), computes the UTC time delta,
    and keeps pairs within `window_seconds` whose src_ips DIFFER. Same-IP username
    matches are excluded because a same-IP pair within 3 min is already inside the
    5-min IP-primary window (Step 2) — so the two match sets stay disjoint and
    union cleanly in Step 7. Records with no username can't match and drop out.
    """
    cowrie_df = pd.DataFrame(
        [
            {
                "norm_username": _normalize_username(r.username),
                "cowrie_username": r.username,
                "cowrie_src_ip": r.src_ip,
                "cowrie_timestamp": r.timestamp,
                "cowrie_eventid": r.eventid,
            }
            for r in cowrie_records
        ],
        columns=_UF_COWRIE_COLS,
    )
    windows_df = pd.DataFrame(
        [
            {
                "norm_username": _normalize_username(r.username),
                "windows_username": r.username,
                "windows_src_ip": r.src_ip,
                "windows_timestamp": r.timestamp,
                "windows_event_id": r.event_id,
                "windows_host": r.host,
                "windows_logon_type": r.logon_type,
            }
            for r in windows_records
        ],
        columns=_UF_WINDOWS_COLS,
    )

    # A null normalized username can't match anything; drop before the merge.
    cowrie_df = cowrie_df[cowrie_df["norm_username"].notna()]
    windows_df = windows_df[windows_df["norm_username"].notna()]

    merged = cowrie_df.merge(windows_df, on="norm_username", how="inner")

    cowrie_ts = pd.to_datetime(merged["cowrie_timestamp"], utc=True, format="ISO8601")
    windows_ts = pd.to_datetime(merged["windows_timestamp"], utc=True, format="ISO8601")
    merged["time_delta_seconds"] = (cowrie_ts - windows_ts).abs().dt.total_seconds()

    matches = merged[
        (merged["time_delta_seconds"] <= window_seconds)
        & (merged["cowrie_src_ip"] != merged["windows_src_ip"])
    ]
    return matches.reset_index(drop=True)


# Generic / shared account names. A cross-IP username-fallback match on any of
# these is noise, not signal — everyone tries "administrator", so the same name
# from two IPs is almost certainly two different actors, not one. Lowercase to
# match the normalized username. Tunable.
DENY_LIST = frozenset({
    "administrator", "admin", "root", "guest", "user", "test",
    "sysadmin", "operator", "support", "oracle", "ubuntu", "pi",
    "-", "",
})


def _is_denied(norm_username):
    """True if a normalized username should be excluded from the fallback path."""
    if norm_username is None:
        return True
    if norm_username.endswith("$"):  # machine accounts (kept through normalization)
        return True
    return norm_username in DENY_LIST


def apply_deny_list(matches):
    """Drop username-fallback matches whose normalized username is generic/shared.

    Applies ONLY to username-fallback output (Step 3) — the path where a shared
    name can't distinguish one actor from many. IP-primary matches (Step 2) are
    never passed through this; there the IP carries the match and a generic
    username is harmless corroboration.
    """
    if matches.empty:
        return matches
    keep = ~matches["norm_username"].map(_is_denied)
    return matches[keep].reset_index(drop=True)


# HIGH tier = IP match within 0-3 min; MEDIUM = 3-5 min (locked spec).
HIGH_TIER_MAX_SECONDS = 180


def _cowrie_commands_by_ip(cowrie_records):
    """Map src_ip -> list of commands run, from Cowrie command.input events."""
    commands = {}
    for r in cowrie_records:
        if r.eventid == "cowrie.command.input":
            commands.setdefault(r.src_ip, []).append((r.message or "").removeprefix("CMD: "))
    return commands


def assemble_agent_inputs(ip_matches, cowrie_records):
    """Aggregate IP-primary matches into per-src_ip correlation-agent inputs.

    match_ip_primary emits one row per matched event-PAIR (the cross-product);
    the correlation agent judges one correlated IDENTITY. So we group by src_ip
    into one input per correlated IP, carrying the join facts plus the two extra
    signals from Step 5: logon_type (from the Windows side) and the commands the
    attacker ran (from the Cowrie side, gathered by src_ip). Returns a list of
    dicts — the input structure the agent reasons over.
    """
    if ip_matches.empty:
        return []

    commands_by_ip = _cowrie_commands_by_ip(cowrie_records)

    inputs = []
    for src_ip, grp in ip_matches.groupby("src_ip"):
        min_delta = float(grp["time_delta_seconds"].min())
        tightest = grp.loc[grp["time_delta_seconds"].idxmin()]  # for the timeline
        inputs.append({
            "match_type": "ip",  # IP-primary (same src_ip both sides); Reporter renders accordingly
            "src_ip": src_ip,
            "cowrie_usernames": sorted(set(grp["cowrie_username"].dropna())),
            "windows_usernames": sorted(set(grp["windows_username"].dropna())),
            "min_time_delta_seconds": min_delta,
            "tier": "high" if min_delta <= HIGH_TIER_MAX_SECONDS else "medium",
            "logon_types": sorted(set(grp["windows_logon_type"].dropna())),
            "commands": commands_by_ip.get(src_ip, []),
            # enrichment for the Reporter card (Phase 1.6):
            "windows_hosts": sorted(set(grp["windows_host"].dropna())),
            "windows_attempt_count": int(grp["windows_timestamp"].nunique()),
            "cowrie_time": tightest["cowrie_timestamp"],
            "windows_time": tightest["windows_timestamp"],
        })
    return inputs


def assemble_username_fallback_inputs(uf_matches, cowrie_records):
    """Aggregate username-fallback matches into per-account agent inputs.

    Mirrors assemble_agent_inputs, but for the fallback path: the correlated
    identity is the reused ACCOUNT (same normalized username seen from DIFFERENT
    IPs on the two sources), so we group by norm_username, and the tier is always
    LOW. Emits the username-fallback schema (match_type="username", distinct
    cowrie_src_ip / windows_src_ip) that the Reporter renders. Pass the
    deny-listed matches (apply_deny_list first).
    """
    if uf_matches.empty:
        return []

    commands_by_ip = _cowrie_commands_by_ip(cowrie_records)

    inputs = []
    for norm_user, grp in uf_matches.groupby("norm_username"):
        min_delta = float(grp["time_delta_seconds"].min())
        tightest = grp.loc[grp["time_delta_seconds"].idxmin()]  # representative pair
        cowrie_ips = sorted(set(grp["cowrie_src_ip"].dropna()))
        commands = [c for ip in cowrie_ips for c in commands_by_ip.get(ip, [])]
        inputs.append({
            "match_type": "username",
            "norm_username": norm_user,
            "cowrie_src_ip": tightest["cowrie_src_ip"],
            "windows_src_ip": tightest["windows_src_ip"],
            "cowrie_usernames": sorted(set(grp["cowrie_username"].dropna())),
            "windows_usernames": sorted(set(grp["windows_username"].dropna())),
            "min_time_delta_seconds": min_delta,
            "tier": "low",  # username-fallback is always the LOW-confidence path
            "logon_types": sorted(set(grp["windows_logon_type"].dropna())),
            "commands": commands,
            "windows_hosts": sorted(set(grp["windows_host"].dropna())),
            "windows_attempt_count": int(grp["windows_timestamp"].nunique()),
            "cowrie_time": tightest["cowrie_timestamp"],
            "windows_time": tightest["windows_timestamp"],
        })
    return inputs
