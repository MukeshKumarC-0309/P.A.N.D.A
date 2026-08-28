"""Lazy provider for the optional LLM report polish (the `[ai]` extra).

Core stays offline: crewai and Gemini are imported ONLY inside the returned
polish function, never at module import. When the extra isn't usable — crewai
not installed, or no GEMINI_API_KEY — the factory returns None and the caller
keeps the deterministic report. So the same code path runs with or without the
extra; the LLM is pure opt-in presentation, never the source of truth.

Two polish shapes share this scaffolding:
  * "card"    — whole alert card (correlation reports); paired with guarded_polish.
  * "section" — one prose section of an incident report (3b), fact-guarded.
Both are built by make_polisher(kind); the convenience wrappers name the two.
"""

import os

# kind -> (task attribute on reporter_crew, the Task's input key).
_KINDS = {
    "card": ("polish_alert_task", "card"),
    "section": ("polish_section_task", "section"),
}


def ai_available():
    """True only if the [ai] extra is usable: crewai importable AND a key set.

    Checks the key first (cheap) so a core install never imports crewai. Covers
    both failure modes — extra not installed, and installed-but-unconfigured —
    so a missing key degrades to deterministic instead of raising later.
    """
    if not os.getenv("GEMINI_API_KEY"):
        return False
    try:
        import crewai  # noqa: F401
    except ImportError:
        return False
    return True


def make_polisher(kind="card"):
    """Return a polish_fn(text)->str built from the [ai] crew, or None.

    None means "run deterministically" — the extra isn't installed or isn't
    configured. When a function is returned, the actual LLM call happens lazily
    on each invocation; if that call raises at run time (API down / rate limit),
    guarded_polish (card) or the section fact guard (section) still degrades to
    the deterministic text — this factory only guards availability, not runtime.
    """
    if kind not in _KINDS:
        raise ValueError("Unknown polisher kind: {!r}".format(kind))
    if not ai_available():
        return None

    task_attr, input_key = _KINDS[kind]

    def polish_fn(text):
        from crewai import Crew
        from panda_tdr.crews import reporter_crew

        task = getattr(reporter_crew, task_attr)
        crew = Crew(agents=[reporter_crew.reporter_agent], tasks=[task], verbose=False)
        return str(crew.kickoff(inputs={input_key: text}))

    return polish_fn


def make_card_polisher():
    """Whole-card polisher (correlation alert cards). None if the extra is off."""
    return make_polisher("card")


def make_section_polisher():
    """Prose-section polisher (incident-report sections, 3b). None if off."""
    return make_polisher("section")
