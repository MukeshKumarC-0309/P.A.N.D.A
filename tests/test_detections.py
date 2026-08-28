"""Unit tests for the standalone detection logic (Phase 2.2).

These exercise the pure functions with FABRICATED records — no Splunk, no
network, no LLM, no API keys. That's possible because the detection/correlation
layers were built dependency-injected (records passed in, not fetched), which is
exactly what makes them testable in isolation here.
"""
from panda_tdr.windows_records import WindowsRecord
from panda_tdr.detections import (
    AccountCreationDetection,
    Detection,
    SourceRollup,
    BRUTE_MIN_ATTEMPTS_PER_ACCOUNT,
    CHAIN_MIN_FAILURES,
    HIGH_VOLUME_ATTEMPTS,
    SPRAY_MIN_ACCOUNTS,
    assess_severity,
    detect_account_creations,
    detect_failed_login_attacks,
    detect_multistage_chains,
    roll_up_by_source,
)

# seconds -> ISO timestamp helper (all within one minute, offset-aware UTC)
T = "2026-01-01T00:00:{:02d}.000+00:00".format


def w(ip, user, ts, event_id="4625", host="HOST1", ltype="3"):
    return WindowsRecord(
        timestamp=ts, event_id=event_id, src_ip=ip, username=user, host=host, logon_type=ltype
    )


# --- per-source rollup ------------------------------------------------------

def test_rollup_skips_records_without_src_ip():
    # a failed logon with no source address can't be attributed to an attacker
    rolls = roll_up_by_source([w(None, "a", T(0)), w("10.0.0.1", "a", T(1))])
    assert [r.src_ip for r in rolls] == ["10.0.0.1"]


def test_rollup_tracks_worst_account():
    recs = [w("10.0.0.1", "admin", T(0)), w("10.0.0.1", "admin", T(1)), w("10.0.0.1", "bob", T(2))]
    r = roll_up_by_source(recs)[0]
    assert r.attempts == 3
    assert r.distinct_accounts == 2
    assert r.max_single_account == 2
    assert r.worst_account == "admin"


# --- brute-force vs spray vs nothing ----------------------------------------

def test_brute_force_fires_on_repeated_single_account():
    recs = [w("10.0.0.1", "admin", T(i)) for i in range(BRUTE_MIN_ATTEMPTS_PER_ACCOUNT)]
    dets = detect_failed_login_attacks(recs)
    assert len(dets) == 1
    assert dets[0].detection_type == "brute_force"
    assert dets[0].rollup.worst_account == "admin"


def test_password_spray_fires_on_many_accounts_few_attempts():
    recs = [w("10.0.0.2", f"user{i}", T(i)) for i in range(SPRAY_MIN_ACCOUNTS)]
    dets = detect_failed_login_attacks(recs)
    assert len(dets) == 1
    assert dets[0].detection_type == "password_spray"


def test_below_threshold_does_not_fire():
    recs = [w("10.0.0.3", "admin", T(0)), w("10.0.0.3", "admin", T(1))]
    assert detect_failed_login_attacks(recs) == []


def test_loopback_is_suppressed_but_real_ip_is_not():
    loop = [w("::1", "admin", T(i)) for i in range(10)]
    assert detect_failed_login_attacks(loop) == []  # local noise, not an attack
    real = [w("10.0.0.4", "admin", T(i)) for i in range(10)]
    assert len(detect_failed_login_attacks(real)) == 1  # same volume, real IP -> fires


# --- severity (own deterministic rule, not the correlation tree) ------------

def _roll(attempts):
    return SourceRollup(
        src_ip="10.0.0.9", attempts=attempts, distinct_accounts=1,
        max_single_account=attempts, worst_account="admin", accounts=("admin",),
        hosts=("HOST1",), first_seen=T(0), last_seen=T(0), span_seconds=0.0,
    )


def test_severity_high_on_sustained_volume():
    d = Detection("brute_force", "10.0.0.9", "reason", _roll(HIGH_VOLUME_ATTEMPTS))
    assert assess_severity(d) == "high"


def test_severity_medium_below_volume_threshold():
    d = Detection("brute_force", "10.0.0.9", "reason", _roll(HIGH_VOLUME_ATTEMPTS - 1))
    assert assess_severity(d) == "medium"


# --- account creation (4720) filter -----------------------------------------

def _c(creator, new, ts=T(0), host="HOST1"):
    return {"Account_Name": [creator, new], "host": host, "_time": ts}


def test_system_creator_is_suppressed():
    # machine/SYSTEM account creating an account = OS setup, not an attack
    assert detect_account_creations([_c("MACHINE$", "acct")]) == []


def test_builtin_new_account_is_suppressed():
    assert detect_account_creations([_c("realadmin", "defaultuser0")]) == []


def test_real_session_account_creation_is_detected_high():
    dets = detect_account_creations([_c("bmleg", "backdoor")])
    assert len(dets) == 1
    assert dets[0].new_account == "backdoor"
    assert dets[0].creator == "bmleg"
    assert dets[0].severity == "high"


# --- multi-stage kill chain -------------------------------------------------

def test_chain_links_failed_success_persistence():
    failed = [w("10.0.0.3", "eviluser", T(i)) for i in range(CHAIN_MIN_FAILURES)]
    success = [w("10.0.0.3", "eviluser", T(30), event_id="4624", host="HOST1")]
    creations = [AccountCreationDetection("bk", "x", "HOST1", T(45))]
    chains = detect_multistage_chains(failed, success, creations)
    assert len(chains) == 1
    c = chains[0]
    assert c.account == "eviluser"
    assert c.failure_count == CHAIN_MIN_FAILURES
    assert c.stage_count == 3
    assert c.created_accounts == ("bk",)


def test_no_chain_when_too_few_preceding_failures():
    failed = [w("10.0.0.3", "eviluser", T(i)) for i in range(CHAIN_MIN_FAILURES - 1)]
    success = [w("10.0.0.3", "eviluser", T(30), event_id="4624", host="HOST1")]
    assert detect_multistage_chains(failed, success, []) == []


def test_creation_before_breach_is_not_attached():
    failed = [w("10.0.0.3", "eviluser", T(i)) for i in range(CHAIN_MIN_FAILURES)]
    success = [w("10.0.0.3", "eviluser", T(30), event_id="4624", host="HOST1")]
    creations = [AccountCreationDetection("bk", "x", "HOST1", T(5))]  # BEFORE the success
    chains = detect_multistage_chains(failed, success, creations)
    assert len(chains) == 1
    assert chains[0].stage_count == 2  # failed->success only; creation not linked
    assert chains[0].created_accounts == ()
