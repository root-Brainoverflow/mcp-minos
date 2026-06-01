"""Source vs. runtime metadata divergence scanner (R4).

When both inputs are available, the static layer holds two views of the same
tool list:

- *Source-extracted* — what the server's source code says each tool's name
  and description are.
- *Runtime-captured* — what the server actually returns to the client when
  asked ``tools/list`` during the dynamic phase.

In a benign server these match. Divergence has three usual causes:

1. **Conditional registration** — a tool exists in source but is gated by
   env/config and isn't registered at runtime (or vice versa). Common,
   usually benign.
2. **External-source description** — code says ``description=load_help("x")``
   and the actual text is composed at startup from a file/DB. Common, benign.
3. **Active sandbox evasion** — the server detects analysis and serves a
   clean description, while a real client receives a different (malicious)
   one. Rare but the only adversarial scenario.

The scanner can't tell (1)/(2) from (3) on its own. It surfaces divergence
as a *low-confidence R4 signal* whose specific shape (tool missing on one
side, descriptions differ in length, descriptions differ in content) tells
the reviewer what kind of divergence is at play. Confirmation is left to
the dynamic phase or manual inspection.
"""

from __future__ import annotations

from mcp_security_analyzer.common.static_finding import StaticFinding
from mcp_security_analyzer.dynamic.models import RiskType, Severity, ToolInfo

_SCANNER = "metadata_divergence"

# Tolerances. Below these the difference is reported at the lowest confidence
# (most of these will be benign whitespace / phrasing tweaks).
_LENGTH_RATIO_FLAG = 1.5     # one side ≥ 1.5× the other
_LENGTH_RATIO_STRONG = 3.0   # one side ≥ 3× the other (much stronger signal)


def scan_metadata_divergence(
    source_tools: list[ToolInfo],
    runtime_tools: list[ToolInfo],
) -> list[StaticFinding]:
    """Compare the two tool lists by name and emit R4 findings for mismatches.

    Returns ``[]`` whenever either list is empty (one channel of evidence is
    not enough to claim divergence).
    """
    if not source_tools or not runtime_tools:
        return []

    src_by_name = {t.name: t for t in source_tools if t.name}
    rt_by_name = {t.name: t for t in runtime_tools if t.name}

    findings: list[StaticFinding] = []
    findings.extend(_missing_on_runtime(src_by_name, rt_by_name))
    findings.extend(_missing_on_source(src_by_name, rt_by_name))
    findings.extend(_description_differs(src_by_name, rt_by_name))
    return findings


# ─────────────────────────────────────────────────────────────────────────────
# Specific divergence kinds
# ─────────────────────────────────────────────────────────────────────────────


def _missing_on_runtime(
    src: dict[str, ToolInfo],
    rt: dict[str, ToolInfo],
) -> list[StaticFinding]:
    """Tool defined in source but absent in runtime tools/list.

    Usually a conditional registration (env / license / mode gate). Reported
    at INFO so a reviewer can confirm the absence is intentional.
    """
    out: list[StaticFinding] = []
    missing = sorted(set(src) - set(rt))
    for name in missing:
        out.append(StaticFinding(
            risk_type=RiskType.R4,
            severity=Severity.INFO,
            confidence=0.2,
            title=f"Tool '{name}' defined in source but not exposed at runtime",
            description=(
                f"Source extraction found tool '{name}' but the runtime "
                "tools/list response does not include it. Common causes are "
                "conditional registration (env / config) and platform gating; "
                "sandbox-evasion variants are rare. Verify the gating "
                "condition matches expected behaviour."
            ),
            scanner=_SCANNER,
            location=f"tool:{name}",
            tool_name=name,
            tags=("metadata-divergence", "missing-at-runtime"),
        ))
    return out


def _missing_on_source(
    src: dict[str, ToolInfo],
    rt: dict[str, ToolInfo],
) -> list[StaticFinding]:
    """Tool exposed at runtime but absent in source extraction.

    More suspicious than the reverse — the server is offering a tool the
    static layer never saw declared. Could be a heuristic miss (extractor
    couldn't recognise the declaration shape) or a runtime-synthesised tool.
    """
    out: list[StaticFinding] = []
    missing = sorted(set(rt) - set(src))
    for name in missing:
        out.append(StaticFinding(
            risk_type=RiskType.R4,
            severity=Severity.LOW,
            confidence=0.35,
            title=f"Tool '{name}' exposed at runtime but not found in source",
            description=(
                f"The runtime tools/list response advertises tool '{name}' "
                "but the source extractor did not see a declaration for it. "
                "Most often this is an extractor-coverage gap (custom "
                "registration pattern), but it can also indicate a "
                "runtime-synthesised tool whose definition lives outside the "
                "package — worth a quick source review."
            ),
            scanner=_SCANNER,
            location=f"tool:{name}",
            tool_name=name,
            tags=("metadata-divergence", "missing-in-source"),
        ))
    return out


def _description_differs(
    src: dict[str, ToolInfo],
    rt: dict[str, ToolInfo],
) -> list[StaticFinding]:
    """For tools present on both sides, compare their descriptions."""
    out: list[StaticFinding] = []
    for name in sorted(set(src) & set(rt)):
        s_desc = (src[name].description or "").strip()
        r_desc = (rt[name].description or "").strip()
        if not s_desc or not r_desc:
            continue
        if s_desc == r_desc:
            continue

        kind, severity, confidence, summary = _classify_diff(s_desc, r_desc)
        out.append(StaticFinding(
            risk_type=RiskType.R4,
            severity=severity,
            confidence=confidence,
            title=f"Tool '{name}' description differs between source and runtime",
            description=(
                f"{summary} "
                "A benign cause is a description built from external data "
                "(config, locale, env). The adversarial case is sandbox "
                "evasion — the server returns a clean description here while "
                "real users see a different one. Cross-check the runtime "
                "description with the dynamic-phase R3 scanner output for "
                "this tool."
            ),
            scanner=_SCANNER,
            location=f"tool:{name}",
            evidence=_evidence_pair(s_desc, r_desc),
            tool_name=name,
            tags=("metadata-divergence", "description-differs", kind),
        ))
    return out


def _classify_diff(s_desc: str, r_desc: str) -> tuple[str, Severity, float, str]:
    """Return (tag, severity, confidence, summary sentence) for a desc diff."""
    s_len = len(s_desc)
    r_len = len(r_desc)
    longer = max(s_len, r_len)
    shorter = max(min(s_len, r_len), 1)
    ratio = longer / shorter

    if ratio >= _LENGTH_RATIO_STRONG:
        return (
            "length-strong",
            Severity.MEDIUM,
            0.45,
            f"Lengths differ sharply (source={s_len}, runtime={r_len}; "
            f"ratio≈{ratio:.1f}×).",
        )
    if ratio >= _LENGTH_RATIO_FLAG:
        return (
            "length-moderate",
            Severity.LOW,
            0.3,
            f"Lengths differ noticeably (source={s_len}, runtime={r_len}; "
            f"ratio≈{ratio:.1f}×).",
        )
    return (
        "content",
        Severity.LOW,
        0.25,
        f"Content differs (source={s_len} chars, runtime={r_len} chars).",
    )


def _evidence_pair(s_desc: str, r_desc: str, limit: int = 160) -> str:
    s = s_desc.replace("\n", " ")[:limit]
    r = r_desc.replace("\n", " ")[:limit]
    return f"source: \"{s}\" | runtime: \"{r}\""
