"""Unit tests for the correlation layer — the project's core cross-source join.

Uses fabricated records: a lightweight stand-in for Cowrie records (the
correlation code duck-types on attributes, so no cowrie_detector dependency is
needed) and the real WindowsRecord. Exercises the IP-primary join, the
username-fallback, the deny-list, and the per-identity input assembly.
"""
from types import SimpleNamespace

from panda_tdr.windows_records import WindowsRecord
from panda_tdr import correlation as corr


def cow(src_ip, username, ts, eventid="cowrie.login.failed", message=None):
    return SimpleNamespace(
        src_ip=src_ip, username=username, timestamp=ts, eventid=eventid, message=message
    )


def win(src_ip, username, ts, event_id="4625", host="HOST1", ltype="3"):
    return WindowsRecord(
        timestamp=ts, event_id=event_id, src_ip=src_ip, username=username, host=host, logon_type=ltype
    )


# --- build_correlation_frame (outer join, provenance flags) -----------------

def test_frame_flags_shared_and_single_source_ips():
    cowrie = [cow("10.0.0.1", "admin", "2026-01-01T00:00:00Z")]
    windows = [win("10.0.0.1", "admin", "2026-01-01T00:00:10+00:00"),
               win("10.0.0.9", "x", "2026-01-01T00:00:00+00:00")]
    frame = corr.build_correlation_frame(cowrie, windows)
    both = frame[frame.src_ip == "10.0.0.1"].iloc[0]
    assert bool(both.seen_in_cowrie) and bool(both.seen_in_windows)
    win_only = frame[frame.src_ip == "10.0.0.9"].iloc[0]
    assert bool(win_only.seen_in_windows) and not bool(win_only.seen_in_cowrie)


# --- match_ip_primary (5-minute window) -------------------------------------

def test_ip_primary_matches_within_window():
    cowrie = [cow("10.0.0.1", "admin", "2026-01-01T00:00:00Z")]
    windows = [win("10.0.0.1", "admin", "2026-01-01T00:01:00+00:00")]  # 60s
    m = corr.match_ip_primary(corr.build_correlation_frame(cowrie, windows))
    assert len(m) == 1
    assert abs(m.iloc[0].time_delta_seconds - 60) < 0.001


def test_ip_primary_excludes_outside_window():
    cowrie = [cow("10.0.0.1", "admin", "2026-01-01T00:00:00Z")]
    windows = [win("10.0.0.1", "admin", "2026-01-01T00:10:00+00:00")]  # 600s > 300
    assert corr.match_ip_primary(corr.build_correlation_frame(cowrie, windows)).empty


# --- match_username_fallback (3-minute window, DIFFERENT IPs) ----------------

def test_username_fallback_matches_across_different_ips():
    cowrie = [cow("10.0.0.1", "bob", "2026-01-01T00:00:00Z")]
    windows = [win("10.0.0.2", "bob", "2026-01-01T00:00:30+00:00")]  # diff IP, 30s
    m = corr.match_username_fallback(cowrie, windows)
    assert len(m) == 1 and m.iloc[0].norm_username == "bob"


def test_username_fallback_excludes_same_ip():
    cowrie = [cow("10.0.0.1", "bob", "2026-01-01T00:00:00Z")]
    windows = [win("10.0.0.1", "bob", "2026-01-01T00:00:30+00:00")]  # SAME IP
    assert corr.match_username_fallback(cowrie, windows).empty


def test_username_normalization_ignores_case_and_domain_prefix():
    cowrie = [cow("10.0.0.1", "Administrator", "2026-01-01T00:00:00Z")]
    windows = [win("10.0.0.2", "CORP\\administrator", "2026-01-01T00:00:30+00:00")]
    m = corr.match_username_fallback(cowrie, windows)
    assert len(m) == 1 and m.iloc[0].norm_username == "administrator"


# --- deny-list (generic/shared usernames) -----------------------------------

def test_deny_list_drops_generic_username():
    cowrie = [cow("10.0.0.1", "admin", "2026-01-01T00:00:00Z")]
    windows = [win("10.0.0.2", "admin", "2026-01-01T00:00:30+00:00")]
    m = corr.match_username_fallback(cowrie, windows)
    assert len(m) == 1                       # matched before deny
    assert corr.apply_deny_list(m).empty     # 'admin' is generic -> dropped


def test_deny_list_keeps_specific_username():
    cowrie = [cow("10.0.0.1", "alice_hr", "2026-01-01T00:00:00Z")]
    windows = [win("10.0.0.2", "alice_hr", "2026-01-01T00:00:30+00:00")]
    m = corr.match_username_fallback(cowrie, windows)
    assert len(corr.apply_deny_list(m)) == 1


# --- assemble_agent_inputs (per-IP identity, tier, commands) ----------------

def test_assemble_ip_inputs_sets_tier_and_gathers_commands():
    cowrie = [
        cow("10.0.0.1", "admin", "2026-01-01T00:00:00Z"),
        cow("10.0.0.1", None, "2026-01-01T00:00:05Z",
            eventid="cowrie.command.input", message="CMD: whoami"),
    ]
    windows = [win("10.0.0.1", "admin", "2026-01-01T00:00:10+00:00")]  # tightest 5s -> HIGH
    m = corr.match_ip_primary(corr.build_correlation_frame(cowrie, windows))
    inputs = corr.assemble_agent_inputs(m, cowrie)
    assert len(inputs) == 1
    assert inputs[0]["src_ip"] == "10.0.0.1"
    assert inputs[0]["tier"] == "high"          # <= 180s
    assert "whoami" in inputs[0]["commands"]


def test_username_fallback_inputs_are_low_tier():
    cowrie = [cow("10.0.0.1", "alice_hr", "2026-01-01T00:00:00Z")]
    windows = [win("10.0.0.2", "alice_hr", "2026-01-01T00:00:30+00:00")]
    m = corr.apply_deny_list(corr.match_username_fallback(cowrie, windows))
    inputs = corr.assemble_username_fallback_inputs(m, cowrie)
    assert len(inputs) == 1 and inputs[0]["tier"] == "low"
