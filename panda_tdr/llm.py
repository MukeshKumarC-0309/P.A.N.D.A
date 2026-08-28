"""Shared LLM configuration for PANDA TDR's crews.

Single source of truth for the model both crews (and later the correlation /
reporter agents) use, so the Gemini config isn't duplicated and can't drift.

Gemini via LiteLLM's provider/model naming. The API key is read from the
GEMINI_API_KEY environment variable (never hardcoded) — required at run time,
not at construction time.

gemini-2.5-flash-lite is deprecated for new API keys (404), so we use the
current lite alias. Note: -latest aliases shift over time; pin a versioned
lite model (e.g. gemini-3.5-flash-lite) if you need reproducible runs.
"""

import os

from crewai import LLM

gemini_llm = LLM(
    model="gemini/gemini-flash-lite-latest",
    api_key=os.getenv("GEMINI_API_KEY"),
)
