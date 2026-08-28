"""Integrity guard for LLM-polished alert cards.

The deterministic alert card is the source of truth; the LLM Reporter is only
allowed to reword it. This backstops that contract: it inspects a polished card
against the deterministic one and reports a reason to REJECT it (fall back to the
deterministic card) when the polish drifted in a way that could mislead an analyst.

It catches the concrete, dangerous failure modes actually observed:
  * LaTeX / math notation leaking into prose (e.g. `$\\ge$`, `\\rightarrow`)
  * the authoritative severity word being dropped
  * a source IP being dropped, or a NEW IP being invented that isn't in the card

What it deliberately does NOT claim: to catch every qualitative embellishment.
Verifying free text is fundamentally limited, so the guarantee is scoped and
honest — fabricated DATA and formatting drift can't reach an alert, and when the
guard trips the deterministic card (always correct) ships instead.
"""

import re

# LaTeX/math markers an LLM sometimes emits instead of plain text.
_LATEX_RE = re.compile(r"\$|\\(?:ge|le|geq|leq|neq|approx|times|rightarrow|leftarrow|to)\b")
# Dotted-quad IPv4 — distinctive enough that comparing sets is low-false-positive.
_IP_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")


def polish_rejection_reason(card, polished, severity):
    """Return a short reason to reject the polish, or None if it is clean.

    `card` is the deterministic source of truth; `polished` is the LLM output;
    `severity` is the authoritative severity that must survive.
    """
    if _LATEX_RE.search(polished):
        return "LaTeX/math notation in output"
    if severity.lower() not in polished.lower():
        return f"authoritative severity '{severity}' missing"
    card_ips = set(_IP_RE.findall(card))
    out_ips = set(_IP_RE.findall(polished))
    dropped = card_ips - out_ips
    if dropped:
        return f"dropped source IP(s): {sorted(dropped)}"
    fabricated = out_ips - card_ips
    if fabricated:
        return f"fabricated IP(s): {sorted(fabricated)}"
    return None


def guarded_polish(card, severity, polish_fn):
    """Polish a card safely: the deterministic card is the guaranteed output.

    Returns (text, fallback_reason). `text` is the polished card when it is safe,
    otherwise the deterministic `card`; `fallback_reason` is None on acceptance,
    or a short string explaining why the card was shipped instead. Falls back in
    BOTH directions the LLM layer can go wrong:
      * the polish call RAISES (dependency down / rate-limited / no key) -> card,
      * the polish DRIFTS (fails polish_rejection_reason) -> card.
    So one API hiccup can never crash the run, and a bad rewrite can never ship.
    """
    try:
        polished = polish_fn(card)
    except Exception as err:  # noqa: BLE001 - any failure must degrade, not crash
        return card, f"polish failed ({type(err).__name__})"
    reason = polish_rejection_reason(card, polished, severity)
    if reason:
        return card, f"polish rejected ({reason})"
    return polished, None
