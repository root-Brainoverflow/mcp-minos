"""Detection-method → confidence floor (docs/severity-verdict-model.md §6).

Confidence is a DISPLAY-ONLY estimate of detector precision P(true | fired); it is
deliberately NOT an input to severity (§5) or the verdict (§8). Scanners may carry
a finer per-finding confidence; this module supplies the per-method floor used as
a fallback and documents the directness-of-observation ordering (more direct
observation ⇒ lower false-positive ⇒ higher confidence).
"""

from __future__ import annotations

# Method → floor confidence.
METHOD_CONFIDENCE: dict[str, float] = {
    "honeypot": 0.95,       # honeypot/canary trap fired
    "syscall": 0.85,        # observed system call
    "network": 0.80,        # observed network connection
    "mcp_protocol": 0.80,   # captured MCP JSON-RPC message
    "fuzzing": 0.70,        # fuzz-response analysis
    "tool_metadata": 0.65,  # tool description / annotation text match
    "static": 0.55,         # static source analysis
}

# Event type → detection method (the directness tier the event belongs to).
EVENT_METHOD: dict[str, str] = {
    "honeypot_access": "honeypot",
    "canary_detected": "honeypot",
    "process_exec": "syscall",
    "file_open": "syscall",
    "file_read": "syscall",
    "file_write": "syscall",
    "server_crash": "syscall",
    "mcp_response": "mcp_protocol",
    "sequence_timeout": "mcp_protocol",
    "test_result": "fuzzing",
}

_DEFAULT_METHOD = "static"


def method_for_event_type(event_type: str) -> str:
    """Map an event ``type`` to its detection-method tier."""
    if event_type in EVENT_METHOD:
        return EVENT_METHOD[event_type]
    if any(tok in event_type for tok in ("network", "connect", "dns", "socket")):
        return "network"
    return _DEFAULT_METHOD


def confidence_for_method(method: str) -> float:
    """Floor confidence for a detection method (defaults to the static tier)."""
    return METHOD_CONFIDENCE.get(method, METHOD_CONFIDENCE[_DEFAULT_METHOD])
