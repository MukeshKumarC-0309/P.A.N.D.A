"""Section-level fact guard for the advanced incident report (the `[ai]` extra).

The incident-report analogue of polish_guard.py. Where polish_guard checks a
whole alert card, this polishes ONLY the prose sections of an incident report
(executive_summary, impact) and reverts any section that lost a hard fact in the
rewrite. Structured sections (tables, timeline, IOCs, MITRE IDs) are never sent
to the LLM, so exact facts and technique IDs can't drift. Stdlib only; the LLM
call is injected (a section polisher from panda_tdr.polish), so this module has
no crewai dependency and the plain-language report is never touched.

render_advanced_report degrades in both directions the LLM can fail: a polish
that RAISES (API down / no key) reverts that section, and a polish that DRIFTS
(drops a hard fact) reverts it too — so the report is never less truthful than
the deterministic one, and a hiccup never crashes the scan.
"""

from panda_tdr.incident_report import (
    PROSE_SECTIONS,
    render_incident_report,
    report_sections,
)


def required_facts(chain):
    """Hard facts that MUST survive a polish verbatim (else revert the section)."""
    facts = [chain.src_ip, chain.account, str(chain.failure_count), *chain.created_accounts]
    return [f for f in facts if f]


def guard(section_key, deterministic, polished, facts):
    """Keep the polish only if every hard fact in the deterministic section is
    still present; otherwise revert (drift protection)."""
    needed = [f for f in facts if f in deterministic]
    # Impact must also keep its honest-limit keywords, not just the hard facts.
    if section_key == "impact":
        needed += [w for w in ("lateral movement", "exfiltration") if w in deterministic]
    missing = [f for f in needed if f not in polished]
    return deterministic if missing else polished


def render_advanced_report(chain, section_polisher=None):
    """Render the advanced incident report, optionally polishing its prose.

    Returns (markdown, polished_count, reverted_count). With no section_polisher
    (the [ai] extra off) it is the pure deterministic report and both counts are
    zero. With one, each PROSE_SECTION is polished then fact-guarded; a section
    that drifts or whose polish raises reverts to deterministic.
    """
    if section_polisher is None:
        return render_incident_report(chain, mode="advanced"), 0, 0

    sections = report_sections(chain)
    facts = required_facts(chain)
    polished_count = reverted_count = 0
    for key in PROSE_SECTIONS:
        deterministic = sections[key]
        try:
            polished = section_polisher(deterministic)
        except Exception:  # noqa: BLE001 - any polish failure degrades, never crashes
            sections[key] = deterministic
            reverted_count += 1
            continue
        kept = guard(key, deterministic, polished, facts)
        sections[key] = kept
        if kept is polished:
            polished_count += 1
        else:
            reverted_count += 1
    return render_incident_report(chain, sections=sections), polished_count, reverted_count
