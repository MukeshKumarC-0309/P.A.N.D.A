"""Reporter Crew — the CrewAI agent/task that polishes a deterministic alert
card into natural analyst prose (Phase 1.6 Step 3).

DESIGN: the LLM only ever sees the already-correct card (rendered deterministically
by reporter.render_alert) as text — never the raw data, the tree, or the model.
Its ONLY job is to improve wording. It must not change the severity, the
recommended action, the reasoning, or any caveat (especially "logon type did not
affect this score" and any "not certain this is one actor" notes). The structured
severity/recommended_action of record stay deterministic (re-stamped at run time,
Step 4) — this prose is presentation, not the source of truth.
"""

from crewai import Agent, Task

from panda_tdr.llm import gemini_llm

reporter_agent = Agent(
    role="SOC Alert Report Writer",
    goal=(
        "Rewrite a factually-correct, machine-generated security alert into clear, "
        "natural prose a SOC analyst can act on quickly — improving ONLY the wording. "
        "Never change the severity, the recommended action, the reasoning, or any "
        "caveat. Preserve every technical fact exactly as given."
    ),
    backstory=(
        "You are an experienced SOC report writer. You make alerts read cleanly and "
        "professionally, but you treat the technical content as sacrosanct: you never "
        "alter the severity, the recommended action, the rule that produced the score, "
        "or the honesty caveats. If the alert states that the logon type did not affect "
        "the score, you keep that exactly; if it states the cross-source link is "
        "low-confidence and it's 'not certain this is one actor', you keep that too. You "
        "never add facts, sources, or conclusions that are not already in the alert."
    ),
    llm=gemini_llm,
    allow_delegation=False,
    max_iter=2,
    verbose=True,
)

polish_alert_task = Task(
    description=(
        "Below is a factually-correct security alert card. Rewrite it as polished, "
        "natural, scannable analyst prose while preserving EVERY fact exactly:\n"
        " - Do NOT change the severity or the recommended action.\n"
        " - Do NOT change the reasoning or the rule that set the severity.\n"
        " - Preserve ALL caveats verbatim in meaning — especially any note that the "
        "logon type did not affect the score, and any 'we are not certain this is a "
        "single actor' wording.\n"
        " - Do NOT add any information, source, or conclusion not present in the card.\n"
        "Keep it action-oriented and easy to scan.\n\n"
        "ALERT CARD:\n{card}"
    ),
    expected_output=(
        "A polished, readable version of the alert with identical severity, recommended "
        "action, reasoning, and caveats — only the wording is improved. No facts added, "
        "none removed, none altered."
    ),
    agent=reporter_agent,
)

# Polishes ONE prose section of an incident report (Phase 2.6). Only the narrative
# sections are ever passed here — tables, timeline, IOCs, and MITRE IDs stay
# deterministic and are never sent to the LLM. A run-time fact guard reverts the
# section to deterministic if any hard fact went missing in the rewrite.
polish_section_task = Task(
    description=(
        "Below is one section of a security incident report. Rewrite ONLY its prose for "
        "clarity and flow, under strict constraints:\n"
        " - Keep the Markdown heading line exactly as given.\n"
        " - Preserve EVERY fact verbatim: IP addresses, account names, host names, counts, "
        "timestamps, and Event IDs must appear unchanged.\n"
        " - Preserve every caveat and honest-limit statement in meaning — especially any "
        "note that something is NOT confirmed or NOT yet established. Never upgrade a "
        "hedge into a certainty.\n"
        " - Do NOT add any fact, cause, or recommendation not already present. Do NOT use "
        "LaTeX or math notation; plain text and Markdown only.\n"
        "Return only the rewritten section.\n\n"
        "SECTION:\n{section}"
    ),
    expected_output=(
        "The same section with improved prose, the heading unchanged, every fact and caveat "
        "preserved, nothing added or removed."
    ),
    agent=reporter_agent,
)
