"""Reporter — render a correlation result into a human-readable alert card.

Phase 1.6 Step 2. Deterministic renderer: it turns the correlation-layer output
(an assembled agent input + the severity tree) into the locked alert-card format.

The WHY section is grounded in `used_features(clf)`, so it can ONLY cite the
features the tree actually branched on — it never claims logon_type mattered if
the tree didn't split on it. The CrewAI Reporter agent (Step 3) polishes prose on
top of this; the factual honesty is locked here. No recall/F1 caveats appear in
the alert (docs only).
"""

from panda_tdr.alerting import score, command_danger, _logon_class, _RECOMMENDED_ACTION
from panda_tdr.detections import assess_severity, HIGH_VOLUME_ATTEMPTS, _to_dt
from panda_tdr.severity_model import used_features


def _uniq(seq):
    """De-duplicate while preserving order (so 'exit, exit, exit' -> 'exit')."""
    seen, out = set(), []
    for x in seq or []:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


def _fmt_list(items, empty="unknown"):
    return ", ".join(items) if items else empty


def _is_fallback(inp):
    """True for a username-fallback match (same account, DIFFERENT IPs)."""
    return inp.get("match_type") == "username"


def _rule_phrase(severity, danger):
    if danger == "dangerous":
        return "dangerous command -> HIGH, independent of confidence tier"
    if severity == "medium":
        return "no dangerous commands + high-confidence correlation -> MEDIUM"
    return "no dangerous commands + lower-confidence correlation -> LOW"


def _vector(inp):
    logon = _logon_class(inp.get("logon_types"))
    lt = "Type 3" if logon == "network" else "Type 2"
    return f"SSH credential probe (honeypot) + network auth attempts (Windows, {lt})"


def _headline(inp, severity, action):
    if _is_fallback(inp):
        who = (
            f"account '{inp.get('norm_username', '?')}' from {inp.get('cowrie_src_ip')} "
            f"and {inp.get('windows_src_ip')}"
        )
    else:
        who = f"{inp['src_ip']} on SSH honeypot and Windows"
    return [
        f"[{severity.upper()}] Cross-source correlation: {who}",
        f"-> Recommended action: {action}",
    ]


def _what_happened(inp):
    cmds = _uniq(inp["commands"])
    if _is_fallback(inp):
        body = (
            f"Account '{inp.get('norm_username', '?')}' was seen on the Cowrie SSH honeypot from "
            f"{inp.get('cowrie_src_ip')} (commands: {_fmt_list(cmds, 'no commands')}) and, within "
            f"{inp['min_time_delta_seconds']:.1f}s, in {inp.get('windows_attempt_count', 0)} failed "
            f"Windows logon(s) from a DIFFERENT IP {inp.get('windows_src_ip')} against host "
            f"{_fmt_list(inp.get('windows_hosts'), 'a Windows host')}. The same account from two "
            f"different IPs may indicate one actor rotating source addresses."
        )
    else:
        body = (
            f"Source {inp['src_ip']} authenticated to the Cowrie SSH honeypot as "
            f"'{_fmt_list(inp['cowrie_usernames'])}' and ran: {_fmt_list(cmds, 'no commands')}. "
            f"Within {inp['min_time_delta_seconds']:.1f}s, the same IP produced "
            f"{inp.get('windows_attempt_count', 0)} failed network logon(s) against Windows host "
            f"{_fmt_list(inp.get('windows_hosts'), 'a Windows host')}, targeting "
            f"{_fmt_list(inp['windows_usernames'])}. The near-simultaneous appearance on two "
            f"independent sensors indicates a single actor probing both surfaces."
        )
    return ["WHAT HAPPENED", body]


def _why(inp, severity, danger, used):
    cmds = _fmt_list(_uniq(inp["commands"]), "none")
    lines = [f"WHY {severity.upper()}"]
    if danger == "dangerous":
        lines.append(
            f"A dangerous command was observed ({cmds}), which is scored "
            f"{severity.upper()} regardless of correlation confidence."
        )
        if inp["tier"] == "low":
            lines.append(
                "Note: the cross-source link is LOW confidence (username match across different IPs), "
                "so we are NOT certain this is a single actor -- but the command itself is severe. We "
                "flag the command, not a confirmed intrusion."
            )
    elif severity == "medium":
        lines += [
            "Two factors set the severity:",
            f" - Correlation confidence is HIGH -- matched within {inp['min_time_delta_seconds']:.1f}s, "
            "inside the 3-minute window, so this is very likely one actor.",
            f" - Impact is low -- only benign commands were run ({cmds}); no dangerous actions observed.",
            'A confirmed cross-source actor with no destructive behaviour is "watch closely", not active-breach.',
        ]
    else:
        lines.append(
            f"Correlation is {inp['tier']}-confidence and only benign commands were observed "
            f"({cmds}), so this is low severity."
        )
    lines.append(f"   Rule applied: {_rule_phrase(severity, danger)}")
    if "logon_type" not in used:
        lines.append(
            f"   Logon type was {_logon_class(inp.get('logon_types'))}; recorded, "
            "but it did not influence this score."
        )
    return lines


def _evidence(inp):
    if _is_fallback(inp):
        corr_line = (
            f" - Correlation : username-fallback (account '{inp.get('norm_username', '?')}' from "
            f"different IPs {inp.get('cowrie_src_ip')} -> {inp.get('windows_src_ip')}), "
            f"{inp['min_time_delta_seconds']:.1f}s apart -> {inp['tier'].upper()} tier"
        )
    else:
        corr_line = (
            f" - Correlation : IP-primary (same source IP), {inp['min_time_delta_seconds']:.1f}s apart "
            f"-> {inp['tier'].upper()} tier"
        )
    return [
        "EVIDENCE",
        f" - Vector      : {_vector(inp)}",
        corr_line,
        f" - Timeline    : Cowrie {inp.get('cowrie_time')}  |  Windows {inp.get('windows_time')}",
        f" - Honeypot    : user {_fmt_list(inp['cowrie_usernames'])}; commands: "
        f"{_fmt_list(_uniq(inp['commands']), 'none')}",
        f" - Windows     : {inp.get('windows_attempt_count', 0)} failed logons; targets "
        f"{_fmt_list(inp['windows_usernames'])}; host {_fmt_list(inp.get('windows_hosts'), 'unknown')}; "
        f"Logon {_fmt_list(['Type ' + t for t in inp.get('logon_types', [])], 'unknown')}",
    ]


def _windows_ip(inp):
    """The IP on the Windows side (differs from Cowrie's in a fallback match)."""
    return inp.get("windows_src_ip") if _is_fallback(inp) else inp["src_ip"]


def _all_ips(inp):
    if _is_fallback(inp):
        return [ip for ip in (inp.get("cowrie_src_ip"), inp.get("windows_src_ip")) if ip]
    return [inp["src_ip"]]


def _what_to_check_next(inp, danger):
    wip = _windows_ip(inp)
    ips = _fmt_list(_all_ips(inp), "the source(s)")
    checks = ["WHAT TO CHECK NEXT"]
    checks.append(
        f" - Did any logon from {wip} SUCCEED on {_fmt_list(inp.get('windows_hosts'), 'the target')} "
        "(Event 4624)? A success escalates this."
    )
    checks.append(
        f" - Review targeted accounts ({_fmt_list(inp['windows_usernames'])}) for lockouts or later activity."
    )
    if danger == "dangerous":
        checks.append(
            f" - Investigate the dangerous command run from {ips} -- confirm impact and any persistence."
        )
    checks.append(f" - Consider blocking / rate-limiting {ips} given confirmed activity.")
    return checks


def _recommended(inp, severity, action, danger):
    if severity == "high":
        why = "a dangerous command was observed" if danger == "dangerous" else "high-severity pattern"
        tail = f"Escalate now -- {why}."
    elif severity == "medium":
        tail = "No immediate escalation (no destructive commands), but this is a confirmed single-actor correlation -- track for follow-on activity."
    else:
        tail = "Low priority; log and move on unless it recurs."
    return ["RECOMMENDED ACTION", f"{action}. {tail}"]


def render_alert(agent_input, clf):
    """Render one correlated-identity input into the human-readable alert card."""
    severity, action = score(agent_input, clf)
    danger = command_danger(agent_input.get("commands"))
    used = used_features(clf)

    sections = [
        _headline(agent_input, severity, action),
        _what_happened(agent_input),
        _why(agent_input, severity, danger, used),
        _evidence(agent_input),
        _what_to_check_next(agent_input, danger),
        _recommended(agent_input, severity, action, danger),
    ]
    return "\n\n".join("\n".join(block) for block in sections)


# --------------------------------------------------------------------------
# Standalone-detection card (Phase 2.2, Piece 4). Same 6-section format as the
# correlation card above, but single-source-accurate: NO cross-source /
# correlation-tier language (a brute/spray detection has no Cowrie side). Facts
# are locked here (deterministic); the SAME Reporter crew polishes wording only.
# --------------------------------------------------------------------------

_DETECTION_LABEL = {
    "brute_force": "Brute-force attack",
    "password_spray": "Password-spray attack",
}


def render_detection_alert(detection):
    """Render a standalone single-source detection into the locked alert card.

    Mirrors render_alert's format and honesty discipline. Its scope note is the
    analogue of the correlation card's logon_type note: it states plainly what
    this detection does NOT know — whether any attempt actually succeeded — so
    the card never overclaims a confirmed compromise from failed-logon data.
    """
    ru = detection.rollup
    severity = assess_severity(detection)
    action = _RECOMMENDED_ACTION[severity]
    label = _DETECTION_LABEL.get(detection.detection_type, detection.detection_type)
    host = _fmt_list(list(ru.hosts), "a Windows host")
    accounts = _fmt_list(list(ru.accounts))

    headline = [
        f"[{severity.upper()}] {label}: {ru.src_ip} against {host}",
        f"-> Recommended action: {action}",
    ]

    if detection.detection_type == "brute_force":
        what = (
            f"Source {ru.src_ip} made {ru.attempts} failed logon attempts against Windows host "
            f"{host}, with {ru.max_single_account} concentrated on a single account "
            f"('{ru.worst_account}'). Sustained repeated guessing against one account is the "
            f"signature of a brute-force credential attack."
        )
    else:
        what = (
            f"Source {ru.src_ip} made {ru.attempts} failed logon attempts spread across "
            f"{ru.distinct_accounts} accounts ({accounts}) on Windows host {host}, no more than "
            f"{ru.max_single_account} against any one. Broad, shallow guessing across many accounts "
            f"is the signature of a lockout-evasive password-spray attack."
        )
    what_happened = ["WHAT HAPPENED", what]

    why = [f"WHY {severity.upper()}"]
    if severity == "high":
        why.append(
            f"Volume is sustained: {ru.attempts} failed attempts (>= {HIGH_VOLUME_ATTEMPTS}) "
            f"indicates a determined, active attack."
        )
        rule = f"{ru.attempts} attempts >= {HIGH_VOLUME_ATTEMPTS} -> HIGH (volume-based)"
    else:
        why.append(
            f"The pattern is a clear {label.lower()}, but volume ({ru.attempts} attempts) is below "
            f"the {HIGH_VOLUME_ATTEMPTS}-attempt HIGH threshold -- suspicious and review-worthy."
        )
        rule = f"{ru.attempts} attempts < {HIGH_VOLUME_ATTEMPTS} -> MEDIUM (volume-based)"
    why.append(f"   Rule applied: {rule}")
    why.append(
        "   Scope note: this detection sees only FAILED Windows logons -- it cannot confirm "
        "whether any attempt succeeded (that needs an Event 4624 check)."
    )

    evidence = [
        "EVIDENCE",
        " - Vector      : repeated Windows authentication failures (Event 4625)",
        f" - Source      : {ru.src_ip}",
        f" - Volume      : {ru.attempts} failed attempts across {ru.distinct_accounts} account(s): {accounts}",
        f" - Focus       : {ru.max_single_account} attempts against '{ru.worst_account}'",
        f" - Host        : {host}",
        f" - Time span   : {ru.first_seen} -> {ru.last_seen} ({ru.span_seconds:.0f}s)",
    ]

    checks = [
        "WHAT TO CHECK NEXT",
        f" - Did any logon from {ru.src_ip} SUCCEED on {host} (Event 4624)? A success turns this "
        "from attempted to actual compromise.",
        f" - Review the targeted account(s) ({accounts}) for lockouts or later activity.",
        f" - Consider blocking / rate-limiting {ru.src_ip}.",
    ]

    if severity == "high":
        tail = f"Escalate now -- sustained active {label.lower()} against {host}."
    else:
        tail = f"Monitor {ru.src_ip} and confirm no successful logon followed."
    recommended = ["RECOMMENDED ACTION", f"{action}. {tail}"]

    sections = [headline, what_happened, why, evidence, checks, recommended]
    return "\n\n".join("\n".join(block) for block in sections)


def render_chain_alert(chain):
    """Render a multi-stage kill-chain (failed->success->persistence) into the card.

    This is the only alert that reports a CONFIRMED successful compromise, so the
    prose says so plainly. Its honest scope note draws the line the join can't
    cross: the persistence stage is linked by host + timing (4720 has no source
    IP), so a created account is flagged as concurrent persistence on the breached
    host — not proof the cracked session itself created it.
    """
    sev = chain.severity
    action = _RECOMMENDED_ACTION[sev]
    dwell = (_to_dt(chain.success_time) - _to_dt(chain.first_failure)).total_seconds()
    has_persist = bool(chain.created_accounts)
    created = _fmt_list(list(chain.created_accounts))
    creators = _fmt_list(list(chain.creators))

    headline = [
        f"[{sev.upper()}] Multi-stage intrusion: {chain.src_ip} cracked '{chain.account}' "
        f"on {chain.host}",
        f"-> Recommended action: {action}",
    ]

    stages = (
        f"(1) {chain.failure_count} failed logons against '{chain.account}' (brute-force), then "
        f"(2) a SUCCESSFUL network logon as '{chain.account}' — the account was cracked after "
        f"~{dwell:.0f}s of guessing"
    )
    if has_persist:
        persist_delay = (_to_dt(chain.creation_time) - _to_dt(chain.success_time)).total_seconds()
        stages += (f", and (3) ~{persist_delay:.0f}s later a new account ({created}) was created "
                   f"on {chain.host} — persistence")
    what_happened = [
        "WHAT HAPPENED",
        (f"A {chain.stage_count}-stage attack chain from {chain.src_ip}: {stages}. This is a "
         f"CONFIRMED successful compromise, not an attempt."),
    ]

    why = [
        f"WHY {sev.upper()}",
        (f"A brute-force that SUCCEEDED ({chain.failure_count} failures then a valid logon from the "
         f"same IP and account) means the attacker now holds working credentials for "
         f"'{chain.account}'."),
    ]
    if has_persist:
        why.append(
            f"A new account ({created}) was then created on the breached host — the attacker "
            f"establishing persistence. This is the most severe pattern the system detects."
        )
    why.append(
        f"   Rule applied: {chain.failure_count} failures (>= {'3'}) -> success (same IP + account) "
        + ("-> account creation on host " if has_persist else "")
        + "= confirmed intrusion chain -> HIGH"
    )
    if has_persist:
        why.append(
            f"   Scope note: the persistence stage is linked by host + timing (Event 4720 carries "
            f"no source IP). The created account ({created}) was made by '{creators}'; we flag it as "
            f"concurrent persistence on the breached host, not proof the cracked session created it."
        )

    evidence = [
        "EVIDENCE",
        " - Vector      : network credential attack (NTLM) escalating on a single host",
        f" - Stage 1     : {chain.failure_count} failed logons (4625) from {chain.src_ip} vs "
        f"'{chain.account}', from {chain.first_failure}",
        f" - Stage 2     : successful network logon (4624 Type 3) as '{chain.account}' from "
        f"{chain.src_ip} at {chain.success_time}",
    ]
    if has_persist:
        evidence.append(
            f" - Stage 3     : account '{created}' created on {chain.host} at {chain.creation_time} "
            f"by '{creators}'"
        )
    evidence.append(f" - Dwell       : ~{dwell:.0f}s from first attempt to breach")

    checks = [
        "WHAT TO CHECK NEXT",
        f" - ISOLATE {chain.host} — this is a confirmed compromise, not an attempt.",
        f" - Disable '{chain.account}' (cracked)"
        + (f" and '{created}' (attacker-created)." if has_persist else "."),
        f" - Hunt what the '{chain.account}' session did (process creation 4688, lateral movement).",
        f" - Block {chain.src_ip} and force a password reset for '{chain.account}'.",
    ]

    recommended = [
        "RECOMMENDED ACTION",
        (f"{action}. Confirmed intrusion — initiate incident response: isolate {chain.host}, disable "
         f"the cracked"
         + (" and created accounts" if has_persist else " account")
         + f", and investigate the {chain.src_ip} session."),
    ]

    sections = [headline, what_happened, why, evidence, checks, recommended]
    return "\n\n".join("\n".join(block) for block in sections)


def render_account_creation_alert(det):
    """Render a 4720 account-creation detection into the locked alert card.

    Same format + honesty discipline. Its scope note draws the honest line 4720
    can't cross on its own: the event confirms an account was CREATED, not that
    it was malicious — a legitimate admin action is indistinguishable at this
    layer. HIGH flags it for verification; it does not assert intent.
    """
    sev = det.severity
    action = _RECOMMENDED_ACTION[sev]

    headline = [
        f"[{sev.upper()}] Account creation: '{det.new_account}' on {det.host}",
        f"-> Recommended action: {action}",
    ]

    what_happened = [
        "WHAT HAPPENED",
        (f"A new local account '{det.new_account}' was created on Windows host {det.host} by "
         f"'{det.creator}'. Creating an account outside normal provisioning is a classic "
         f"persistence technique — a durable foothold that survives reboots and password resets."),
    ]

    why = [
        f"WHY {sev.upper()}",
        (f"The account was created by '{det.creator}', a real (non-system) account — not OS setup. "
         f"Account creation is a persistence action, scored HIGH by default."),
        "   Rule applied: new account created by a non-system account -> HIGH",
        ("   Scope note: Event 4720 confirms the creation, not intent — an authorized admin action "
         "looks identical. HIGH flags this for verification; it does not assert malice."),
    ]

    evidence = [
        "EVIDENCE",
        " - Vector      : Windows account management (Event 4720)",
        f" - New account : {det.new_account}",
        f" - Created by  : {det.creator}",
        f" - Host        : {det.host}",
        f" - Time        : {det.timestamp}",
    ]

    checks = [
        "WHAT TO CHECK NEXT",
        f" - Was this creation authorized? Confirm with the owner of the '{det.creator}' account.",
        f" - Was '{det.new_account}' added to a privileged group (Event 4732 — e.g. Administrators)?",
        f" - Review any activity by '{det.new_account}' since it was created.",
        f" - If unauthorized: disable '{det.new_account}' and investigate the '{det.creator}' session.",
    ]

    recommended = [
        "RECOMMENDED ACTION",
        (f"{action}. Verify authorization; if unauthorized, disable '{det.new_account}' and "
         f"investigate the session that created it."),
    ]

    sections = [headline, what_happened, why, evidence, checks, recommended]
    return "\n\n".join("\n".join(block) for block in sections)
