"""Bridge: run the TDR detection engine and persist its findings as cases.

This is the seam between the deterministic TDR engine (panda_tdr/, stdlib
only) and the encrypted case store (panda/cases.py). It loads the offline
snapshot, runs the Windows detectors and the multi-stage kill-chain stitcher,
then writes each finding into the vault as a case (+ detections, + reports).

Persisting requires an UNLOCKED vault, so the caller (the `tdr` command)
unlocks, calls scan_and_persist(), then re-locks.

De-duplication principle: dedup WITHIN a subsystem (the same events producing
duplicate cases), never ACROSS sensors/claims (different evidence). So the
Windows detectors dedup against the chain — a brute/spray whose (src_ip,
account) is part of a chain, or an account creation a chain already attached as
its persistence stage, is skipped (a brute-force that never succeeded, or a
4720 with no preceding breach, is NOT subsumed and stays standalone). But the
cross-source correlation is a DIFFERENT claim from a different sensor (the SSH
honeypot interaction + cross-source timing), so it is never deduped against the
Windows-only chain; its shared source_ip is the intended link an analyst
follows when browsing, not a duplicate.

Known limitation (Step 1): scan_and_persist APPENDS. Re-running `tdr` writes
the findings again; idempotency is a later cut. With the fixed snapshot this
is a demo artifact, not a real risk.
"""

from panda import cases
from panda_tdr import correlation, live as live_source, polish
from panda_tdr.snapshot import load_snapshot
from panda_tdr.alerting import build_alert
from panda_tdr.detections import (
    assess_severity,
    detect_account_creations,
    detect_failed_login_attacks,
    detect_multistage_chains,
)
from panda_tdr.incident_polish import render_advanced_report
from panda_tdr.incident_report import render_incident_report
from panda_tdr.polish_guard import guarded_polish
from panda_tdr.reporter import render_alert
from panda_tdr.severity_model import train_severity_tree

# Detection.detection_type -> the rule vocabulary used in the case store.
_STANDALONE_RULE = {"brute_force": "brute-force", "password_spray": "password-spray"}


def _persist_chain(chain, summary, section_polisher):
    """A confirmed kill chain -> one case, a detection per stage, two reports.

    The technical report is the advanced incident report, optionally prose-
    polished (section_polisher, the [ai] extra) with a per-section fact guard;
    the plain report is always deterministic (never LLM-touched).
    """
    has_persist = bool(chain.created_accounts)
    persist_note = (
        f" and created {', '.join(chain.created_accounts)} on the host"
        if has_persist else ""
    )
    case_id = cases.record_case(
        title=f"Multi-stage credential compromise on {chain.host}",
        severity=chain.severity, confidence="high", source_ip=chain.src_ip,
        summary=(f"{chain.failure_count} failed logons from {chain.src_ip} preceded a "
                 f"successful logon as '{chain.account}' on {chain.host}{persist_note}."),
    )

    # Stage 1 — brute-force precursor.
    cases.record_detection(
        case_id, rule="brute-force", source="windows",
        severity=chain.severity, confidence="high",
        source_ip=chain.src_ip, username=chain.account,
        evidence=(f"{chain.failure_count} failed logons (Event 4625) against "
                  f"'{chain.account}' before the successful logon."),
    )
    # Stage 2 — the breach (successful network logon).
    cases.record_detection(
        case_id, rule="successful-logon", source="windows",
        severity=chain.severity, confidence="high",
        source_ip=chain.src_ip, username=chain.account,
        evidence=(f"Successful network logon (Event 4624, Type 3) as '{chain.account}' "
                  f"from {chain.src_ip} — credentials confirmed compromised."),
    )
    n_detections = 2
    # Stage 3 — persistence (only if an account was created post-breach).
    if has_persist:
        cases.record_detection(
            case_id, rule="account-creation", source="windows",
            severity=chain.severity, confidence="high",
            source_ip=chain.src_ip, username=", ".join(chain.created_accounts),
            evidence=(f"Account(s) {', '.join(chain.created_accounts)} created on "
                      f"{chain.host} after the breach — linked by host+timing, not "
                      f"proof the same session created it (Event 4720 carries no IP)."),
        )
        n_detections = 3

    advanced, n_polished, n_reverted = render_advanced_report(chain, section_polisher)
    summary["polished"] += n_polished
    summary["polish_fallbacks"] += n_reverted
    cases.record_report(case_id, "technical", advanced)
    cases.record_report(case_id, "plain", render_incident_report(chain, mode="normal"))

    summary["chains"] += 1
    summary["cases"] += 1
    summary["detections"] += n_detections
    summary["reports"] += 2


def _persist_standalone(det, summary):
    """A standalone brute-force / password-spray -> one case + one detection."""
    rule = _STANDALONE_RULE[det.detection_type]
    severity = assess_severity(det)
    label = "Brute-force" if det.detection_type == "brute_force" else "Password spray"
    case_id = cases.record_case(
        title=f"{label} from {det.src_ip}",
        severity=severity, confidence="high", source_ip=det.src_ip,
        summary=det.reason,
    )
    cases.record_detection(
        case_id, rule=rule, source="windows",
        severity=severity, confidence="high",
        source_ip=det.src_ip, username=det.rollup.worst_account,
        evidence=det.reason,
    )
    summary["brute_spray"] += 1
    summary["cases"] += 1
    summary["detections"] += 1


def _persist_account_creation(ac, summary):
    """A standalone account creation (no preceding breach) -> case + detection.

    source_ip is None: Event 4720 carries no source address, so there is no IP
    to attribute honestly. confidence is 'medium' — the account survived the
    system/built-in filter, but a legitimate admin creating an account trips
    the same rule, so this is the weakest of the standalone signals.
    """
    summary_line = f"'{ac.creator}' created account '{ac.new_account}' on {ac.host}."
    case_id = cases.record_case(
        title=f"Account creation: {ac.new_account} on {ac.host}",
        severity=ac.severity, confidence="medium", source_ip=None,
        summary=summary_line,
    )
    cases.record_detection(
        case_id, rule="account-creation", source="windows",
        severity=ac.severity, confidence="medium",
        source_ip=None, username=ac.new_account,
        evidence=(f"Event 4720 at {ac.timestamp}: {summary_line} No preceding breach "
                  f"in this data — flagged as a standalone persistence-style event."),
    )
    summary["account_creations"] += 1
    summary["cases"] += 1
    summary["detections"] += 1


def _persist_correlation(inp, clf, summary, card_polisher):
    """A cross-source correlated identity -> one case + one detection + one report.

    Not deduped against the Windows chain: correlation is a distinct claim (same
    actor seen on the SSH honeypot AND Windows), so it stands as its own case,
    linked to the chain only by a shared source_ip an analyst can follow.

    The technical report is the deterministic analyst card, optionally polished:
    when card_polisher is set (the [ai] extra), guarded_polish reworks the
    wording but ships the deterministic card if the polish drifts or the call
    fails — so the stored report is never less truthful than the card.
    """
    alert = build_alert(inp, clf)          # {severity, narrative, recommended_action}
    card = render_alert(inp, clf)          # the deterministic analyst card
    body = card
    if card_polisher is not None:
        body, reason = guarded_polish(card, alert["severity"], card_polisher)
        summary["polish_fallbacks" if reason else "polished"] += 1
    is_fallback = inp.get("match_type") == "username"
    delta = inp["min_time_delta_seconds"]

    if is_fallback:
        title = f"Cross-source correlation: account '{inp['norm_username']}' across IPs"
        source_ip = None                   # two different IPs; the account is the shared key
        username = inp["norm_username"]
        evidence = (f"Account '{inp['norm_username']}' on the Cowrie honeypot from "
                    f"{inp['cowrie_src_ip']} and Windows failed logons from a different IP "
                    f"{inp['windows_src_ip']}, {delta:.1f}s apart (tier {inp['tier']}, "
                    f"username-fallback).")
    else:
        title = f"Cross-source correlation: {inp['src_ip']} (SSH honeypot + Windows)"
        source_ip = inp["src_ip"]
        users = sorted(set(inp["cowrie_usernames"]) | set(inp["windows_usernames"]))
        username = ", ".join(users) or None
        commands = ", ".join(dict.fromkeys(inp["commands"])) or "none"
        evidence = (f"Same IP {inp['src_ip']} on the Cowrie honeypot and Windows failed logons "
                    f"within {delta:.1f}s (tier {inp['tier']}). Honeypot commands: {commands}.")

    case_id = cases.record_case(
        title=title, severity=alert["severity"], confidence=inp["tier"],
        source_ip=source_ip, summary=alert["narrative"],
    )
    cases.record_detection(
        case_id, rule="correlation", source="cowrie+windows",
        severity=alert["severity"], confidence=inp["tier"],
        source_ip=source_ip, username=username, evidence=evidence,
    )
    cases.record_report(case_id, "technical", body)

    summary["correlations"] += 1
    summary["cases"] += 1
    summary["detections"] += 1
    summary["reports"] += 1


def scan_and_persist(snapshot_path=None, card_polisher=None, section_polisher=None,
                     live=False):
    """Run the detectors + correlation over the telemetry and persist as cases.

    Returns a summary dict of what was written (and what was skipped as subsumed
    by a chain), so the caller can print a run report. Requires an unlocked
    vault.

    Source: the offline snapshot by default. live=True pulls from Splunk (the
    [live] extra) when it is usable — splunk-sdk installed AND credentials set;
    otherwise it degrades to the snapshot with the reason recorded in
    summary["source"], never crashing. So an unconfigured `tdr live` still runs.

    card_polisher / section_polisher optionally rework report prose (the [ai]
    extra): the correlation alert card, and the advanced incident report's prose
    sections. Left None, each defaults to the lazy provider, itself None unless
    crewai is installed AND a Gemini key is set — so the default run is fully
    deterministic and offline. Tests inject fakes directly. `polished` /
    `polish_fallbacks` in the summary aggregate both paths (card + sections).
    """
    if card_polisher is None:
        card_polisher = polish.make_card_polisher()
    if section_polisher is None:
        section_polisher = polish.make_section_polisher()

    if live and live_source.live_available():
        snap, source = live_source.load_live(), "live (Splunk)"
    elif live:
        snap = load_snapshot() if snapshot_path is None else load_snapshot(snapshot_path)
        source = "snapshot (live unavailable — no splunk-sdk / credentials)"
    else:
        snap = load_snapshot() if snapshot_path is None else load_snapshot(snapshot_path)
        source = "snapshot"
    cowrie, failed, success = snap["cowrie"], snap["failed"], snap["success"]

    account_dets = detect_account_creations(snap["creation_rows"])
    brute_dets = detect_failed_login_attacks(failed)
    chains = detect_multistage_chains(failed, success, account_dets)

    # Cross-source correlation (cowrie honeypot <-> Windows failed logons).
    frame = correlation.build_correlation_frame(cowrie, failed)
    ip_inputs = correlation.assemble_agent_inputs(
        correlation.match_ip_primary(frame), cowrie)
    uf_inputs = correlation.assemble_username_fallback_inputs(
        correlation.apply_deny_list(
            correlation.match_username_fallback(cowrie, failed)), cowrie)
    clf = train_severity_tree()

    # What the chains already cover, so standalone findings don't double-count.
    covered_pairs = {(c.src_ip, c.account) for c in chains}
    covered_creations = {(name, c.host) for c in chains for name in c.created_accounts}

    summary = {
        "chains": 0, "brute_spray": 0, "account_creations": 0, "correlations": 0,
        "skipped_brute_spray": 0, "skipped_account_creations": 0,
        "cases": 0, "detections": 0, "reports": 0,
        "ai_polish": (card_polisher is not None) or (section_polisher is not None),
        "polished": 0, "polish_fallbacks": 0, "source": source,
    }

    for chain in chains:
        _persist_chain(chain, summary, section_polisher)

    for inp in ip_inputs + uf_inputs:
        _persist_correlation(inp, clf, summary, card_polisher)

    for det in brute_dets:
        if (det.src_ip, det.rollup.worst_account) in covered_pairs:
            summary["skipped_brute_spray"] += 1
            continue
        _persist_standalone(det, summary)

    for ac in account_dets:
        if (ac.new_account, ac.host) in covered_creations:
            summary["skipped_account_creations"] += 1
            continue
        _persist_account_creation(ac, summary)

    return summary
