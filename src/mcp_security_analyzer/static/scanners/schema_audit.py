"""Input-schema auditor (R5).

Scores how permissive each tool's ``inputSchema`` is. A loose schema is not a
vulnerability by itself — it is a measure of attack surface — so findings here
are LOW/MEDIUM and meant primarily as a corroborating signal for the dynamic
phase (e.g. raising confidence when a fuzzing scanner also finds something on
the same tool).

Operates on ``ToolInfo.input_schema`` (JSON Schema). Tools without a schema are
skipped — source extraction usually cannot recover the schema, so this scanner
is most useful on the runtime ``tools/list`` response where schemas are real.
"""

from __future__ import annotations

from mcp_security_analyzer.common.static_finding import StaticFinding
from mcp_security_analyzer.dynamic.models import RiskType, Severity, ToolInfo

_SCANNER = "schema_audit"

# Property names that imply a filesystem / network target — for these a missing
# format constraint is more concerning (path traversal / SSRF surface).
_SENSITIVE_NAME_HINTS = ("path", "file", "dir", "url", "uri", "host", "cmd", "command", "query")

_SCORE_THRESHOLD = 0.6


def scan_schemas(tools: list[ToolInfo]) -> list[StaticFinding]:
    """Return permissiveness findings for tools that expose an input schema."""
    findings: list[StaticFinding] = []
    for tool in tools:
        schema = tool.input_schema
        if not isinstance(schema, dict):
            continue
        score, reasons = _permissiveness(schema)
        if score >= _SCORE_THRESHOLD:
            severity = Severity.MEDIUM if score >= 0.8 else Severity.LOW
            findings.append(StaticFinding(
                risk_type=RiskType.R5,
                severity=severity,
                # Capped low — this is attack-surface context, not a confirmed
                # vulnerability. The dynamic phase corroborates.
                confidence=min(0.45, round(score / 2, 3)),
                kind="static.schema_permissive",
                title="Permissive input schema",
                description=(
                    f"Tool '{tool.name}' accepts loosely-constrained input "
                    f"(permissiveness {score:.2f}): {'; '.join(reasons)}. This "
                    "widens the input attack surface; pair with the dynamic "
                    "fuzzing results before concluding."
                ),
                scanner=_SCANNER,
                location=f"tool:{tool.name}",
                tool_name=tool.name,
                tags=("permissive-schema",),
            ))
    return findings


def _permissiveness(schema: dict) -> tuple[float, list[str]]:
    """Return a 0..1 permissiveness score and the reasons contributing to it."""
    # A tool with no schema body at all is maximally permissive.
    if not schema or schema == {"type": "object"}:
        return 1.0, ["no constraints declared"]

    score = 0.0
    reasons: list[str] = []

    if schema.get("additionalProperties") is True:
        score += 0.3
        reasons.append("additionalProperties: true")

    props = schema.get("properties")
    if not isinstance(props, dict) or not props:
        # An object type with no declared properties accepts anything.
        if schema.get("type") in (None, "object"):
            score += 0.4
            reasons.append("object with no declared properties")
        return min(score, 1.0), reasons or ["weak typing"]

    loose_strings = 0
    sensitive_unconstrained = 0
    untyped = 0
    for pname, pdef in props.items():
        if not isinstance(pdef, dict):
            continue
        ptype = pdef.get("type")
        if ptype is None and "enum" not in pdef and "anyOf" not in pdef and "oneOf" not in pdef:
            untyped += 1
        if ptype == "string":
            constrained = any(k in pdef for k in ("pattern", "maxLength", "enum", "format"))
            if not constrained:
                loose_strings += 1
                if any(h in str(pname).lower() for h in _SENSITIVE_NAME_HINTS):
                    sensitive_unconstrained += 1

    if loose_strings:
        score += min(0.3, 0.1 * loose_strings)
        reasons.append(f"{loose_strings} unconstrained string field(s)")
    if sensitive_unconstrained:
        score += min(0.3, 0.15 * sensitive_unconstrained)
        reasons.append(
            f"{sensitive_unconstrained} sensitive field(s) "
            "(path/url/cmd) without a format constraint"
        )
    if untyped:
        score += min(0.2, 0.1 * untyped)
        reasons.append(f"{untyped} field(s) with no type")

    return min(score, 1.0), reasons
