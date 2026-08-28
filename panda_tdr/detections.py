"""Standalone detections over a single source (Phase 2.2).

Until now the whole system had ONE alert source: the cross-source correlation
join. That misses any attack confined to a single surface. This module adds
detections that stand on their own — patterns a single source (here: Windows
4625 failed logons) exhibits by itself, independent of any correlation.

Design (settled in the 2.2 kickoff):
  * Each detection carries its OWN deterministic severity rule (Piece 3), NOT
    the correlation severity tree — that tree was trained on correlation
    features (confidence_tier, logon_type, command_danger) and has nothing to
    say about attempt counts. Forcing standalone detections through it would be
    dishonest. Detections reuse the alert card + Reporter, not the tree.
  * First detection: brute-force vs password-spray on 4625, two shapes of the
    same failed-login data (deep-on-few-accounts vs broad-and-shallow).

This module is the "detections layer"; more detectors (4720 account-creation,
multi-stage chains) will join it later.
"""

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Optional


@dataclass(frozen=True)
class SourceRollup:
    """Per-source view of failed-login activity — the input to the classifier.

    The three numbers that separate brute-force from spray:
      attempts             total failed logons from this src_ip
      distinct_accounts    how many different accounts were targeted (breadth)
      max_single_account   most attempts against any one account (depth)

    frozen=True mirrors WindowsRecord/CowrieRecord: immutable once built.
    """

    src_ip: str
    attempts: int
    distinct_accounts: int
    max_single_account: int
    worst_account: str       # the account that took the most attempts (brute target)
    accounts: tuple          # every account name targeted, sorted
    hosts: tuple             # host(s) the attempts landed on
    first_seen: str
    last_seen: str
    span_seconds: float


def roll_up_by_source(windows_records):
    """Group failed-login (4625) records by src_ip into SourceRollups.

    Records with no src_ip are skipped: brute/spray is a per-SOURCE pattern, so
    a failed logon with no attributable source address (localhost/system noise)
    isn't what this detection is about — a deliberate scoping choice, not silent
    data loss. Deterministic and lossless for everything it DOES claim: every
    attributed record is counted (sum of attempts == number of src_ip'd records).
    """
    per_ip = {}
    for r in windows_records:
        if not r.src_ip:
            continue
        g = per_ip.setdefault(r.src_ip, {"accounts": {}, "hosts": set(), "stamps": []})
        # count attempts per account (username may be None on some 4625s — keep
        # it as a distinct "unknown" bucket rather than dropping the attempt)
        g["accounts"][r.username] = g["accounts"].get(r.username, 0) + 1
        g["stamps"].append(r.timestamp)
        if r.host:
            g["hosts"].add(r.host)

    rollups = []
    for src_ip, g in per_ip.items():
        stamps = sorted(g["stamps"])
        span = (datetime.fromisoformat(stamps[-1]) - datetime.fromisoformat(stamps[0])).total_seconds()
        worst = max(g["accounts"], key=g["accounts"].get)  # account with the most attempts
        rollups.append(
            SourceRollup(
                src_ip=src_ip,
                attempts=sum(g["accounts"].values()),
                distinct_accounts=len(g["accounts"]),
                max_single_account=max(g["accounts"].values()),
                worst_account=str(worst) if worst is not None else "unknown",
                accounts=tuple(sorted(str(a) for a in g["accounts"])),
                hosts=tuple(sorted(g["hosts"])),
                first_seen=stamps[0],
                last_seen=stamps[-1],
                span_seconds=round(span, 3),
            )
        )
    return rollups


# --------------------------------------------------------------------------
# Piece 2 — the classifier. Turns a per-source rollup into a verdict:
# brute-force (deep on one account), password-spray (broad + shallow), or none.
# --------------------------------------------------------------------------

# Loopback is excluded (2.2 design call): brute/spray is a REMOTE-attacker
# pattern; ::1 / 127.0.0.1 are local, so failed logons there are testing/system
# noise, not an attack. Can't exclude private ranges — the real lab attacker
# (10.0.2.3) is itself RFC1918.
_LOOPBACK = frozenset({"::1", "127.0.0.1"})

# Thresholds are deliberate, tunable policy — not learned. Documented so an
# analyst can retune them. Chosen false-negative-averse (catch more, tolerate
# some noise), matching the project's governing principle.
BRUTE_MIN_ATTEMPTS_PER_ACCOUNT = 5   # >=5 tries at ONE account = sustained guessing
SPRAY_MIN_ACCOUNTS = 5               # >=5 accounts from one source = breadth
SPRAY_MAX_ATTEMPTS_PER_ACCOUNT = 3   # ...but shallow on each (lockout-evasive)

# KNOWN REFINEMENT (documented, not built — 2.2 design call): these thresholds
# count over the WHOLE pull window, not a rolling burst. Real brute-force is
# "N attempts in T minutes"; the live rollup for 10.0.2.3 spans ~17 days,
# merging separate sessions. The count threshold still classifies the lab data
# correctly, so burst-bucketing is deferred until multi-burst data needs it.


@dataclass(frozen=True)
class Detection:
    """One standalone-detection finding. severity is assigned separately (Piece 3),
    so the classifier stays purely about WHAT the pattern is, not how bad it is."""

    detection_type: str   # "brute_force" | "password_spray"
    src_ip: str
    reason: str           # plain-language why-this-tripped, analyst-readable
    rollup: SourceRollup  # the evidence behind the verdict


def classify(rollup) -> Optional[Detection]:
    """Classify one SourceRollup as brute-force, password-spray, or nothing.

    Brute-force takes precedence over spray: a source hammering one account hard
    AND spreading is reported as brute-force (the concentrated guessing is the
    stronger, more specific signal). Returns None for loopback sources and for
    activity below both thresholds.
    """
    if rollup.src_ip in _LOOPBACK:
        return None

    if rollup.max_single_account >= BRUTE_MIN_ATTEMPTS_PER_ACCOUNT:
        return Detection(
            detection_type="brute_force",
            src_ip=rollup.src_ip,
            reason=(f"{rollup.max_single_account} failed logons against a single account "
                    f"('{rollup.worst_account}') from {rollup.src_ip} — sustained "
                    f"credential guessing against one target."),
            rollup=rollup,
        )

    if (rollup.distinct_accounts >= SPRAY_MIN_ACCOUNTS
            and rollup.max_single_account <= SPRAY_MAX_ATTEMPTS_PER_ACCOUNT):
        return Detection(
            detection_type="password_spray",
            src_ip=rollup.src_ip,
            reason=(f"{rollup.distinct_accounts} accounts targeted from {rollup.src_ip} "
                    f"with <= {rollup.max_single_account} attempt(s) each — broad, shallow "
                    f"guessing consistent with lockout-evasive password spraying."),
            rollup=rollup,
        )

    return None


def detect_failed_login_attacks(windows_records):
    """End-to-end: roll up 4625 records by source and classify each.

    Returns list[Detection] — only the sources that tripped a rule. This is the
    detections layer's public entry point for the brute/spray detector.
    """
    return [d for d in (classify(ru) for ru in roll_up_by_source(windows_records)) if d]


# --------------------------------------------------------------------------
# Piece 3 — severity. Standalone detections carry their OWN deterministic rule
# (the 2.2 design call), NOT the correlation severity tree — that tree's
# features (confidence_tier, command_danger) don't apply to a single-source
# failed-login pattern. Severity here is a function of attack VOLUME.
# --------------------------------------------------------------------------

# >= this many failed attempts from one source = sustained/determined -> HIGH.
# Tunable policy, documented, like the detection thresholds above.
HIGH_VOLUME_ATTEMPTS = 20


def assess_severity(detection) -> str:
    """Deterministic severity for a brute/spray detection.

    Base MEDIUM: these are failed logons — suspicious and review-worthy, but no
    confirmed compromise. Escalate to HIGH on sustained volume (an active,
    determined attack). Never LOW: clearing the detection threshold at all
    already means it warrants review — consistent with the project's stance
    that a real attack signal is never "no action".
    """
    if detection.rollup.attempts >= HIGH_VOLUME_ATTEMPTS:
        return "high"
    return "medium"


# --------------------------------------------------------------------------
# Detection #2 — account creation (Event 4720). Unlike brute/spray, there's no
# threshold: the mere creation of an account by a real (non-system) session is
# the signal — a classic persistence move — so it's HIGH by default. The work
# is separating that from benign OS/setup creations (the 2.2 design call, the
# account-creation analogue of the loopback exclusion).
# --------------------------------------------------------------------------

# New-account names Windows itself creates during setup/servicing — benign,
# suppressed even if something odd made their creator look non-system.
_BUILTIN_ACCOUNTS = frozenset({"defaultuser0", "wdagutilityaccount", "defaultaccount"})


@dataclass(frozen=True)
class AccountCreationDetection:
    """One 4720 finding that survived the system/built-in filter. severity is a
    field (fixed HIGH) rather than computed — account creation by a real session
    is persistence; there's no volume knob to turn like brute/spray."""

    new_account: str
    creator: str
    host: str
    timestamp: str
    severity: str = "high"


def _account_pair(account_name):
    """Split 4720's multivalue Account_Name into (creator, new_account).

    Verified in discovery: Account_Name is [Subject (creator), New Account]. On
    a single value we can only know the new account. Empties are dropped first.
    """
    vals = account_name if isinstance(account_name, list) else [account_name]
    vals = [v for v in vals if v not in (None, "-", "", "none")]
    if len(vals) >= 2:
        return vals[0], vals[1]
    if len(vals) == 1:
        return None, vals[0]
    return None, None


def _is_system_creator(creator):
    """True if the account was created by SYSTEM / a machine account ($-suffixed)
    — OS-driven setup, not a human or attacker. The suppression key."""
    return creator is None or creator.endswith("$") or creator.upper() == "SYSTEM"


def detect_account_creations(rows):
    """Turn raw 4720 rows into AccountCreationDetections, suppressing OS noise.

    `rows` is splunk_client.get_account_creations_raw() output. A row is
    suppressed when the creator is SYSTEM/a machine account (setup, not an
    attack) or the new account is a known Windows built-in. Everything that
    survives is a real session creating an account — HIGH by default.
    """
    dets = []
    for row in rows:
        creator, new_account = _account_pair(row.get("Account_Name"))
        if new_account is None:
            continue
        if _is_system_creator(creator) or new_account.lower() in _BUILTIN_ACCOUNTS:
            continue
        dets.append(
            AccountCreationDetection(
                new_account=new_account,
                creator=creator,
                host=row.get("host") or "unknown",
                timestamp=row.get("_time"),
            )
        )
    return dets


# --------------------------------------------------------------------------
# Detection #3 — multi-stage kill chain (failed -> success -> persistence).
# The first detection that confirms an ACTUAL successful compromise, not just
# attempts — so it's the top of the severity scale. It stitches three event
# types the earlier detectors saw in isolation into one narrative.
# --------------------------------------------------------------------------

# A success preceded by at least this many failures (same IP + account) reads as
# a cracked brute-force rather than a fat-fingered password. Tunable policy.
CHAIN_MIN_FAILURES = 3
# An account created on the breached host within this window AFTER the success
# is treated as the persistence stage. 4720 carries no src_ip, so host+timing is
# the honest join. Tunable; wide (1h) is false-negative-averse.
PERSIST_WINDOW_SECONDS = 3600


def _to_dt(ts):
    """Parse a Splunk timestamp (offset-aware, e.g. +00:00 / +05:30, or Z)."""
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


@dataclass(frozen=True)
class MultiStageChain:
    """A stitched failed->success(->persistence) kill chain for one (src_ip,
    account). severity is fixed HIGH — a confirmed successful breach is the
    strongest signal the system produces."""

    src_ip: str
    account: str
    host: str
    failure_count: int
    first_failure: str
    success_time: str
    created_accounts: tuple      # accounts created on the host post-breach (stage 3)
    creators: tuple             # who created them
    creation_time: Optional[str]
    severity: str = "high"

    @property
    def stage_count(self):
        return 3 if self.created_accounts else 2


def detect_multistage_chains(failed_records, success_records, creations):
    """Stitch failed (4625) -> success (4624 Type 3) -> creation (4720) into chains.

    For each successful network logon, require >= CHAIN_MIN_FAILURES preceding
    failures from the SAME src_ip AND account (a cracked brute-force). If a
    non-system account creation then appears on the same host within
    PERSIST_WINDOW_SECONDS after the success, it's attached as the persistence
    stage (making the chain 3-stage instead of 2). Returns list[MultiStageChain].
    """
    chains = []
    for succ in success_records:
        if not succ.src_ip or not succ.username:
            continue
        st = _to_dt(succ.timestamp)

        fails = [
            f for f in failed_records
            if f.src_ip == succ.src_ip and f.username == succ.username
            and _to_dt(f.timestamp) <= st
        ]
        if len(fails) < CHAIN_MIN_FAILURES:
            continue  # no brute-force precursor -> not a chain

        posts = [
            c for c in creations
            if c.host == succ.host
            and st < _to_dt(c.timestamp) <= st + timedelta(seconds=PERSIST_WINDOW_SECONDS)
        ]

        earliest_fail = min(fails, key=lambda f: _to_dt(f.timestamp))
        earliest_post = min(posts, key=lambda c: _to_dt(c.timestamp), default=None)
        chains.append(
            MultiStageChain(
                src_ip=succ.src_ip,
                account=succ.username,
                host=succ.host or "unknown",
                failure_count=len(fails),
                first_failure=earliest_fail.timestamp,
                success_time=succ.timestamp,
                created_accounts=tuple(c.new_account for c in posts),
                creators=tuple(sorted({c.creator for c in posts})),
                creation_time=earliest_post.timestamp if earliest_post else None,
            )
        )
    return chains
