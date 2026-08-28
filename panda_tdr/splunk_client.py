"""Splunk client for PANDA TDR's Windows Event Log crew.

Pulls search results out of Splunk via its REST API (the Splunk Python SDK).
This is the Windows-side equivalent of the Cowrie parser: a standalone,
testable data source that later gets wrapped as a CrewAI @tool (Phase 1.4
Step 5). It returns structured data (list[dict]); it never prints.

Connection config comes from environment variables (loaded from .env), never
hardcoded — matching how GEMINI_API_KEY is handled:

    SPLUNK_HOST       Splunk host reachable from where PANDA runs (default localhost)
    SPLUNK_PORT       management port (default 8089)
    SPLUNK_USER       Splunk username
    SPLUNK_PASSWORD   Splunk password
    SPLUNK_VERIFY     "true" to verify the TLS cert; default "false" because the
                      management port serves a self-signed cert on a localhost
                      port-forward (verify=False is fine there, NOT over an
                      untrusted network).
"""

import os
import random
import time

import splunklib.client as client
import splunklib.results as results
from splunklib.binding import AuthenticationError

# Wide default window: the lab data is 1+ week old, so a short window returns
# empty even though the data exists (see the time-range gotcha in the design notes).
DEFAULT_EARLIEST = "-90d"


# Splunk login is intermittently flaky (observed AuthenticationError on some
# connects), and RAPID retries make it WORSE (rate-limit / lockout). Capped
# exponential backoff spaces attempts out so a transient failure clears instead
# of compounding. Retry only transient errors — a real ValueError/config bug
# should still surface immediately.
_RETRYABLE = (AuthenticationError, ConnectionError, TimeoutError)
_MAX_ATTEMPTS = 5
_BASE_DELAY = 1.0   # seconds
_MAX_DELAY = 30.0   # cap


def _connect_once():
    """One Splunk connect attempt using env-var config."""
    verify = os.getenv("SPLUNK_VERIFY", "false").lower() == "true"
    return client.connect(
        host=os.getenv("SPLUNK_HOST", "localhost"),
        port=int(os.getenv("SPLUNK_PORT", "8089")),
        username=os.getenv("SPLUNK_USER"),
        password=os.getenv("SPLUNK_PASSWORD"),
        scheme="https",
        verify=verify,
    )


def get_service(max_attempts=_MAX_ATTEMPTS, base_delay=_BASE_DELAY, max_delay=_MAX_DELAY):
    """Connect to Splunk with capped exponential backoff on transient failures.

    Splunk login is intermittently flaky and rapid retries trigger lockout, so we
    space attempts: the delay doubles each retry (base, 2*base, 4*base, ...)
    capped at max_delay, plus jitter to avoid synchronized retries. Retries only
    AuthenticationError / connection / timeout errors; after max_attempts it
    re-raises the last one (a persistent failure should still be loud).
    """
    last_err = None
    for attempt in range(max_attempts):
        try:
            return _connect_once()
        except _RETRYABLE as err:
            last_err = err
            if attempt == max_attempts - 1:
                break  # out of attempts — re-raise below
            delay = min(base_delay * (2 ** attempt), max_delay)
            delay += random.uniform(0, delay * 0.25)  # jitter
            time.sleep(delay)
    raise last_err


def run_search(spl, earliest=DEFAULT_EARLIEST, latest="now", service=None):
    """Run an SPL search and return its results as a list of dicts.

    `spl` is a raw SPL string. A transforming/generating search starting with
    '|' is passed through; anything else gets the required leading 'search '.
    `service` lets a caller reuse one connection across searches; if omitted a
    fresh one is opened.
    """
    service = service or get_service()

    stripped = spl.lstrip()
    if not stripped.startswith("|") and not stripped.lower().startswith("search"):
        spl = "search " + spl

    stream = service.jobs.oneshot(
        spl,
        earliest_time=earliest,
        latest_time=latest,
        output_mode="json",
        count=0,  # no result cap
    )
    # JSONResultsReader yields result dicts interleaved with Message objects
    # (diagnostics); keep only the actual result rows.
    return [dict(row) for row in results.JSONResultsReader(stream) if isinstance(row, dict)]


# --------------------------------------------------------------------------
# The two Phase 0 searches. The SPL below is RECONSTRUCTED (assumed), not the
# real saved-search text — verify against the actual searches on first live
# run and correct if the field names differ. Field-name assumptions depend on
# the Splunk Add-on for Windows: Logon_ID, Account_Name, Source_Network_Address.
# --------------------------------------------------------------------------

# ASSUMED SPL — confirm against the real saved search.
FAILED_LOGIN_SPL = (
    "index=main EventCode=4625 "
    "| stats count by Account_Name, Source_Network_Address"
)

# Per-EVENT failed logins (not aggregated). This is the correlation-ready source:
# every 4625 event with its timestamp + IP + username, mirroring Cowrie's
# per-event records so the correlation layer can outer-join on the same triple.
# No filtering here — noise (Account_Name "-", machine $ accounts, localhost IPs)
# is left in on purpose; excluding generic accounts is the deny-list's job in
# Phase 1.5, not this pull's (false-negative-averse: don't drop at the source).
FAILED_LOGIN_RAW_SPL = (
    "index=main EventCode=4625 "
    "| table _time, Account_Name, Source_Network_Address, host, Logon_Type"
)

# REAL Phase 0 saved search (validated) — pure TIME-PROXIMITY correlation with
# NO grouping field: transaction maxspan=10m maxevents=2. Phase 0 found that
# grouping on Account_Name OR Logon_ID both broke the join (unreliable /
# multivalue fields — the exact failure reproduced during Phase 1.4), so the
# working version abandoned field-based grouping entirely and pairs events
# purely by time proximity. earliest=0 = all time (the wrapper matches this).
# NOTE: field is EventCode (capital). The saved search as written used lowercase
# `eventcode`, which returns 0 via the SDK (Splunk field names are case-sensitive;
# this index parses it as EventCode). Structure is otherwise the real Phase 0
# search, untouched.
LOGON_PROCESS_SPL = (
    "index=main (EventCode=4624 OR EventCode=4688) earliest=0 "
    "| transaction maxspan=10m maxevents=2 "
    "| table _time, EventCode, duration"
)


def get_failed_logins_raw(service=None, earliest=DEFAULT_EARLIEST, latest="now"):
    """Pull per-event failed logins (4625) as a list of dicts.

    Each row is one 4625 event with _time, Account_Name, Source_Network_Address
    — the correlation triple (timestamp + username + IP). Unfiltered by design.
    """
    return run_search(FAILED_LOGIN_RAW_SPL, earliest=earliest, latest=latest, service=service)


def get_failed_login_counts(service=None, earliest=DEFAULT_EARLIEST, latest="now"):
    """Pull the failed-login-count aggregation (4625) as a list of dicts."""
    return run_search(FAILED_LOGIN_SPL, earliest=earliest, latest=latest, service=service)


def get_logon_process_transactions(service=None, earliest=DEFAULT_EARLIEST, latest="now"):
    """Pull the logon->process-creation transactions (4624/4688) as a list of dicts.

    Pure time-proximity correlation (no grouping field) — see LOGON_PROCESS_SPL.
    Defaults to the wide bounded window (-90d), not the search's inline earliest=0:
    both return identical rows on the (fixed, historical) lab data, but all-time
    scans the whole index and is much slower. The API earliest_time kwarg bounds
    the dispatch even though the SPL still carries earliest=0.
    """
    return run_search(LOGON_PROCESS_SPL, earliest=earliest, latest=latest, service=service)


# --------------------------------------------------------------------------
# Cowrie source (Phase 2.1). Cowrie events are ALREADY in Splunk (index=main
# sourcetype=_json, eventid=cowrie.*) — verified live in Step 1. Pulling them
# here makes the whole pipeline ONE live Splunk pull, retiring the fragile manual
# test_data/cowrie.json export.
# --------------------------------------------------------------------------

# The explicit | table is REQUIRED, not stylistic (Step 1 finding): a bare
# `search ... | head` via the SDK returns only indexed/default fields (_time,
# eventid, host, _raw) — the JSON-extracted fields (session, src_ip, username,
# ...) come back ONLY when named. Same reason FAILED_LOGIN_RAW_SPL tables its
# fields. NOT tabled: the raw `timestamp` field — Splunk returns it as a
# multivalue polluted with a literal 'none' (['..Z','none']); the structuring
# layer keys on the clean single-valued _time instead.
COWRIE_RAW_SPL = (
    "index=main sourcetype=_json eventid=cowrie.* "
    "| table _time, eventid, session, src_ip, src_port, username, password, message"
)


def get_cowrie_events_raw(service=None, earliest=DEFAULT_EARLIEST, latest="now"):
    """Pull cowrie events (all eventids) as a list of dicts.

    Each row is one cowrie event with _time + the tabled fields. Unfiltered by
    eventid on purpose: login.failed/success carry username; command.input
    carries the command in `message`; session.* carry neither but stay
    IP-correlatable. The signal-vs-noise call is the correlation layer's job,
    not this pull's — same false-negative-averse stance as the Windows pull.
    """
    return run_search(COWRIE_RAW_SPL, earliest=earliest, latest=latest, service=service)


# Account-creation (4720) for the standalone account-creation detection (2.2).
# Verified live in discovery: 4720 is classic WinEventLog (NOT _json), and the
# ONLY extracted account field is Account_Name — a 2-element MULTIVALUE
# [creator, new_account]. The guessed TargetUserName/SubjectUserName fields do
# not extract, so Account_Name is all we table. host = the machine the account
# was created on.
ACCOUNT_CREATED_RAW_SPL = (
    "index=main EventCode=4720 "
    "| table _time, host, Account_Name"
)


def get_account_creations_raw(service=None, earliest=DEFAULT_EARLIEST, latest="now"):
    """Pull account-creation (4720) events as a list of dicts.

    Each row has _time, host, and the multivalue Account_Name [creator,
    new_account]. Unfiltered here (system/OS-created accounts are left in);
    suppressing setup noise is the detector's job, not this pull's — same
    record-everything-judge-nothing stance as the other raw pulls.
    """
    return run_search(ACCOUNT_CREATED_RAW_SPL, earliest=earliest, latest=latest, service=service)


# Successful NETWORK logons (4624 Type 3) for the multi-stage chain (2.2). Only
# Type 3 matters: it's the only success that carries a remote Source_Network_
# Address (verified live — a real net-use success extracts src_ip cleanly, the
# gap the Phase 0 4624 investigation hit only because no Type 3 existed). Same
# multivalue Account_Name [Subject, New Logon] shape as 4625; the structuring
# layer takes the New Logon account (the one that logged on).
SUCCESS_LOGON_RAW_SPL = (
    "index=main EventCode=4624 Logon_Type=3 "
    "| table _time, Account_Name, Source_Network_Address, host, Logon_Type"
)


def get_successful_logons_raw(service=None, earliest=DEFAULT_EARLIEST, latest="now"):
    """Pull successful network logons (4624 Type 3) as a list of dicts.

    Each row is one successful remote logon with _time, Account_Name (multivalue),
    Source_Network_Address (the attacker IP), host, Logon_Type. This is the
    'success' stage of the failed->success->persistence chain.
    """
    return run_search(SUCCESS_LOGON_RAW_SPL, earliest=earliest, latest=latest, service=service)
