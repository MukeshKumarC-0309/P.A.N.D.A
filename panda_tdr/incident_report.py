"""Deterministic incident-report generator (Phase 2.6).

Turns a MultiStageChain (a confirmed failed->success->persistence intrusion) into
a formal SOC-style incident report in Markdown. Every fact traces to the chain
data; MITRE techniques are mapped from which stages actually fired; honest limits
are stated plainly. This is the facts-locked layer — the LLM (Phase 2.6 Piece 4)
polishes the prose, it does not invent facts.

Scoped to ONE incident (the chain passed in). It deliberately does not weave in
unrelated activity (e.g. an earlier cross-source correlation on a different
account/date) — conflating separate events would be dishonest.
"""

from collections import OrderedDict
from datetime import timezone

from panda_tdr.detections import CHAIN_MIN_FAILURES, PERSIST_WINDOW_SECONDS, _to_dt

# Sections whose value is narrative prose safe for LLM polish. Everything else
# (tables, timeline, IOCs, MITRE IDs) stays deterministic and untouched.
PROSE_SECTIONS = ("executive_summary", "impact")

# The layman ("Normal" mode) report is deterministic end-to-end — no LLM. Plain
# wording is written here rather than LLM-translated, so simplification can never
# overstate a hedge (e.g. turn "suspected" into "hacked") or drop a caveat. Bonus:
# Normal mode then runs with no internet at all.


def _fmt_ts(ts):
    """Render a Splunk timestamp as an unambiguous UTC string."""
    return _to_dt(ts).astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _fmt_list(items):
    return ", ".join(f"`{i}`" for i in items) if items else "none"


def _mitre_rows(chain):
    """Map the stages that fired to MITRE ATT&CK techniques (deterministic)."""
    rows = [
        ("Initial Access / Credential Access", "T1110 — Brute Force",
         f"{chain.failure_count} failed logons against `{chain.account}`"),
        ("Lateral Movement / Initial Access", "T1021.002 — Remote Services: SMB/Windows Admin Shares",
         "network (Type 3) logon over SMB/IPC$"),
        ("Defense Evasion / Persistence", "T1078.003 — Valid Accounts: Local Accounts",
         f"successful logon using cracked credentials for `{chain.account}`"),
    ]
    if chain.created_accounts:
        rows.append(
            ("Persistence", "T1136.001 — Create Account: Local Account",
             f"created {_fmt_list(chain.created_accounts)} on the host"))
    return rows


def report_sections(chain):
    """Build the report as an ordered {section_key: markdown} map.

    Each value includes its own heading. Keeping sections addressable lets a
    caller polish only the prose ones (PROSE_SECTIONS) and leave the structured
    sections — tables, timeline, IOCs, MITRE IDs — deterministic and untouched.
    """
    has_persist = bool(chain.created_accounts)
    dwell = (_to_dt(chain.success_time) - _to_dt(chain.first_failure)).total_seconds()
    s = OrderedDict()

    s["title"] = f"# Incident Report — Credential Compromise on {chain.host}"

    s["metadata"] = (
        f"**Report ID:** INC-{_to_dt(chain.success_time).strftime('%Y%m%d')}-{chain.src_ip.replace('.', '-')}  \n"
        f"**Severity:** {chain.severity.upper()}  \n"
        f"**Status:** Confirmed intrusion  \n"
        f"**Affected host:** {chain.host}  \n"
        f"**Prepared by:** PANDA TDR (automated multi-stage detection)"
    )

    persist_clause = (
        f" and established persistence by creating {_fmt_list(chain.created_accounts)}"
        if has_persist else ""
    )
    s["executive_summary"] = (
        "## 1. Executive Summary\n\n"
        f"On {_fmt_ts(chain.success_time)}, source `{chain.src_ip}` achieved a **confirmed "
        f"compromise** of the local account `{chain.account}` on `{chain.host}`. The attacker "
        f"brute-forced the account with {chain.failure_count} failed attempts, succeeded after "
        f"~{dwell:.0f} seconds{persist_clause}. This is a confirmed successful breach, not an "
        f"attempted one, and warrants immediate incident response."
    )

    s["classification"] = (
        "## 2. Incident Classification\n\n"
        f"| Field | Value |\n| --- | --- |\n"
        f"| Severity | {chain.severity.upper()} |\n"
        f"| Type | Brute-force → successful compromise"
        + (" → persistence |" if has_persist else " |") + "\n"
        f"| Confidence | High (failed → success confirmed on same IP + account) |\n"
        f"| Source | `{chain.src_ip}` |\n"
        f"| Compromised account | `{chain.account}` |\n"
        + (f"| Attacker-created account(s) | {_fmt_list(chain.created_accounts)} |\n" if has_persist else "")
        + f"| Host | `{chain.host}` |\n"
        f"| Detection time | {_fmt_ts(chain.success_time)} |"
    )

    tl = [
        f"- **{_fmt_ts(chain.first_failure)}** — Stage 1: brute-force begins — "
        f"{chain.failure_count} failed network logons (Event 4625) from `{chain.src_ip}` "
        f"against `{chain.account}`.",
        f"- **{_fmt_ts(chain.success_time)}** — Stage 2: **breach** — successful network logon "
        f"(Event 4624, Type 3) as `{chain.account}` from `{chain.src_ip}` (~{dwell:.0f}s after the "
        f"first attempt).",
    ]
    if has_persist:
        tl.append(
            f"- **{_fmt_ts(chain.creation_time)}** — Stage 3: persistence — account "
            f"{_fmt_list(chain.created_accounts)} created on `{chain.host}` "
            f"(created by {_fmt_list(chain.creators)})."
        )
    s["timeline"] = "## 3. Timeline of Events\n\n" + "\n".join(tl)

    mitre = ["| Tactic | Technique | Observed |", "| --- | --- | --- |"]
    mitre += [f"| {t} | {tech} | {obs} |" for t, tech, obs in _mitre_rows(chain)]
    s["mitre"] = "## 4. MITRE ATT&CK Mapping\n\n" + "\n".join(mitre)

    iocs = [
        f"- **Source IP:** `{chain.src_ip}`",
        f"- **Compromised account:** `{chain.account}`",
        f"- **Affected host:** `{chain.host}`",
        "- **Authentication:** NTLM network logon (Logon Type 3)",
    ]
    if has_persist:
        iocs.insert(2, f"- **Attacker-created account(s):** {_fmt_list(chain.created_accounts)}")
    s["iocs"] = "## 5. Indicators of Compromise\n\n" + "\n".join(iocs)

    impact = [
        f"- **Confirmed:** the credentials for `{chain.account}` are compromised — the attacker "
        f"authenticated successfully from `{chain.src_ip}`.",
    ]
    if has_persist:
        impact.append(
            f"- **Confirmed:** persistence established — {_fmt_list(chain.created_accounts)} now "
            f"persist on `{chain.host}` and would survive a password reset of `{chain.account}`."
        )
    impact += [
        f"- **Blast radius:** any resource `{chain.account}`"
        + (" or the created account(s)" if has_persist else "")
        + f" can reach from `{chain.host}`.",
        "- **Not yet established (honest limit):** there is no evidence in this data of lateral "
        "movement or data exfiltration — but absence of evidence is not evidence of absence; "
        "those would require process (4688) and network telemetry not covered here.",
    ]
    s["impact"] = "## 6. Impact Assessment\n\n" + "\n".join(impact)

    disable = (f"`{chain.account}`"
               + (f" and {_fmt_list(chain.created_accounts)}" if has_persist else ""))
    s["response"] = (
        "## 7. Response & Recommendations\n\n"
        f"**Contain**\n"
        f"- Isolate `{chain.host}` from the network.\n"
        f"- Block `{chain.src_ip}` at the perimeter.\n\n"
        f"**Eradicate**\n"
        f"- Disable/remove {disable}.\n"
        + ("- Remove any privileged-group membership granted to these accounts.\n" if has_persist else "")
        + f"\n**Recover**\n"
        f"- Reset credentials for `{chain.account}` and any account sharing that password.\n"
        f"- Verify no additional persistence remains (scheduled tasks, services, extra accounts).\n"
        f"- Restore `{chain.host}` to monitoring and watch for re-compromise from `{chain.src_ip}`."
    )

    s["notes"] = (
        "## 8. Detection & Evidence Notes\n\n"
        f"- **How it was detected:** the multi-stage chain detector stitched failed logons (4625), "
        f"a successful network logon (4624 Type 3), and account creation (4720) into one chain — "
        f"triggering because ≥ {CHAIN_MIN_FAILURES} failures preceded a success from the same IP and "
        f"account.\n"
        + (f"- **Honest limit — persistence link:** the account creation is linked to the breach by "
           f"**host and timing** (within {PERSIST_WINDOW_SECONDS // 60} min on the same host); Event 4720 "
           f"carries no source IP, so this is flagged as concurrent persistence on the breached host, "
           f"not proof the cracked session itself created the account.\n" if has_persist else "")
        + "- **Honest limit — model:** severity here is a deterministic policy rule, not a statistically "
        "validated model; reported detection metrics elsewhere are by-construction and are a methodology "
        "demonstration, not generalization evidence.\n"
        "- **Environment:** single-host lab telemetry via Splunk (Cowrie honeypot + Windows Security log)."
    )

    return s


def layman_sections(chain):
    """Plain-language ("Normal" mode) version of the report for a non-technical
    reader. Same facts, no jargon (no MITRE, Event IDs, or IOC tables) and no LLM
    — the plain wording is written here so simplification can't distort the
    confirmed-vs-suspected framing. A multi-stage chain is always a CONFIRMED
    break-in, and the plain text says exactly that, no more.
    """
    has_persist = bool(chain.created_accounts)
    made = _fmt_list(chain.created_accounts)
    s = OrderedDict()

    s["title"] = f"# Security Alert (Plain-Language) — {chain.host}"

    s["banner"] = (
        "**How serious:** URGENT — this is a confirmed break-in, not just a failed attempt.  \n"
        f"**Affected computer:** {chain.host}  \n"
        f"**Account involved:** {chain.account}"
    )

    persist_bit = (
        f" After getting in, they created a new hidden account ({made}) so they can come back "
        f"later — even if you change the original password."
        if has_persist else ""
    )
    s["what_happened"] = (
        "## What happened\n\n"
        f"Someone using another computer (`{chain.src_ip}`) repeatedly tried to guess the password "
        f"for the `{chain.account}` account on `{chain.host}`, and eventually succeeded — they got "
        f"in.{persist_bit} This is a real break-in that already worked, so it needs attention right away."
    )

    means = [
        f"- The password for `{chain.account}` is no longer safe — the attacker knows it.",
    ]
    if has_persist:
        means.append(
            f"- They set up a hidden way back in (the {made} account), so simply changing one "
            "password is not enough to lock them out."
        )
    means.append(
        "- We do not have proof yet that they copied files or reached other computers — but we also "
        "cannot rule it out, so treat this computer as compromised until it has been checked."
    )
    s["what_it_means"] = "## What this means for you\n\n" + "\n".join(means)

    todo = [
        f"1. **Disconnect `{chain.host}` from the internet and network now** (unplug the cable / turn "
        "off Wi-Fi). This stops the attacker from doing more.",
        "2. **Contact your IT support or a security professional** — tell them a computer was broken "
        "into and show them this alert.",
    ]
    if has_persist:
        todo.append(
            f"3. **Have IT remove BOTH the `{chain.account}` and {made} accounts** — do not just "
            "change the password, because the hidden account would still let the attacker back in."
        )
    else:
        todo.append(
            f"3. **Have IT reset the password for `{chain.account}`** and check who has been using it."
        )
    todo.append(
        f"{len(todo) + 1}. **Ask IT to check this computer** for anything else that was changed or added."
    )
    s["what_to_do"] = "## What to do now\n\n" + "\n".join(todo)

    return s


def render_incident_report(chain, sections=None, mode="advanced"):
    """Assemble the full Markdown report.

    mode="advanced" -> the full technical report (report_sections).
    mode="normal"   -> the plain-language report (layman_sections), no jargon.
    Pass `sections` explicitly (e.g. after polishing prose) to render from it and
    bypass mode selection.
    """
    if sections is None:
        sections = layman_sections(chain) if mode == "normal" else report_sections(chain)
    return "\n\n".join(sections.values())
