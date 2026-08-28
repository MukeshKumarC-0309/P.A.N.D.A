"""Output contract for a correlated pair: {severity, narrative, recommended_action}.

severity comes from the deterministic Step-6 decision tree. The narrative is a
DETERMINISTIC template (not LLM) grounded in `used_features(clf)` — so it can
only cite features the tree actually branched on, and it states plainly when
logon_type did not affect the decision. This makes the honesty requirement a
guarantee rather than a hope; the LLM Reporter (Phase 1.6) adds prose polish on
top of an already-truthful narrative.
"""

from panda_tdr.severity_model import _encode_row, used_features

# Commands that make a pair severe regardless of correlation confidence.
_DANGEROUS_MARKERS = (
    "net user", "/add", "net localgroup", "reg add", "-enc", "-encodedcommand",
    "certutil", "vssadmin", "bcdedit", "schtasks", "mimikatz",
)

_RECOMMENDED_ACTION = {
    "high": "escalate immediately",
    "medium": "log for review",
    "low": "likely benign, no action",
}

# Human-friendly names for the decision features (for the narrative).
_FRIENDLY = {
    "command_danger": "whether a dangerous command was run",
    "confidence_tier": "the correlation confidence tier",
    "logon_type": "the logon type",
}


def command_danger(commands):
    """Classify a pair's commands as 'dangerous' or 'not'."""
    joined = " ".join(commands or []).lower()
    return "dangerous" if any(m in joined for m in _DANGEROUS_MARKERS) else "not"


def _logon_class(logon_types):
    return "network" if "3" in (logon_types or []) else "interactive"


def _narrative(agent_input, severity, danger, logon, used):
    delta = agent_input["min_time_delta_seconds"]
    tier = agent_input["tier"]
    cmds = agent_input.get("commands") or []
    cmd_str = ", ".join(cmds) if cmds else "none"

    if agent_input.get("match_type") == "username":
        lead = (
            f"Account '{agent_input.get('norm_username', '?')}' appears on the Cowrie SSH "
            f"honeypot ({agent_input.get('cowrie_src_ip')}) and in Windows failed logons from a "
            f"DIFFERENT IP ({agent_input.get('windows_src_ip')}) {delta:.1f}s apart — a "
            f"{tier}-confidence username-fallback correlation."
        )
    else:
        lead = (
            f"Source {agent_input['src_ip']} appears in both the Cowrie SSH honeypot and the "
            f"Windows failed-logon telemetry {delta:.1f}s apart — a {tier}-confidence "
            f"cross-source correlation."
        )
    parts = [lead]
    if danger == "dangerous":
        parts.append(
            f"It ran a dangerous command ({cmd_str}), which drives the "
            f"{severity.upper()} severity regardless of correlation confidence."
        )
    elif severity == "medium":
        parts.append(
            f"The commands observed were benign ({cmd_str}); severity is "
            f"{severity.upper()} on the strength of the high-confidence match alone."
        )
    else:
        parts.append(
            f"The commands observed were benign ({cmd_str}) and correlation "
            f"confidence is {tier}, so severity is {severity.upper()}."
        )
    # Honesty about which inputs actually decided this — never overclaim.
    reasons = " and ".join(_FRIENDLY.get(f, f) for f in used)
    if "logon_type" not in used:
        parts.append(
            f"Severity was determined by {reasons}; the logon type ({logon}) was "
            f"recorded but did not affect this decision."
        )
    else:
        parts.append(f"Severity was determined by {reasons}.")
    return " ".join(parts)


def score(agent_input, clf):
    """Predict (severity, recommended_action) for an input. Schema-agnostic —
    uses only tier/logon_types/commands, so it works for both IP-primary and
    username-fallback inputs (no src_ip needed)."""
    tier = agent_input["tier"]
    logon = _logon_class(agent_input.get("logon_types"))
    danger = command_danger(agent_input.get("commands"))
    severity = clf.predict([_encode_row(tier, logon, danger)])[0]
    return severity, _RECOMMENDED_ACTION[severity]


def build_alert(agent_input, clf):
    """Turn one assembled correlated-identity input into the output contract."""
    severity, action = score(agent_input, clf)
    danger = command_danger(agent_input.get("commands"))
    logon = _logon_class(agent_input.get("logon_types"))
    narrative = _narrative(agent_input, severity, danger, logon, used_features(clf))

    return {
        "severity": severity,
        "narrative": narrative,
        "recommended_action": action,
    }
