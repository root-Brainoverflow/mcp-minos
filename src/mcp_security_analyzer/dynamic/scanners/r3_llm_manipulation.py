"""R3: LLM Behavior Manipulation scanner.

R3 is scoped to server-supplied content only. The scanner analyzes metadata,
tool responses, and observed resource bodies for patterns that can poison or
steer a consuming agent. It intentionally does not infer vulnerability from
injecting prompt-like strings into ordinary tool arguments.
"""

from __future__ import annotations

from typing import Any

import structlog

from mcp_security_analyzer.dynamic.models import (
    AnalysisContext,
    Finding,
    RiskType,
    Severity,
)
from mcp_security_analyzer.dynamic.payloads.injection_patterns import (
    scan_response,
)
from mcp_security_analyzer.dynamic.payloads.resource_poisoning import (
    looks_like_poisoned_resource,
    scan_resource_response,
)
from mcp_security_analyzer.dynamic.payloads.tool_poisoning import (
    scan_tool_list,
)
from mcp_security_analyzer.dynamic.scanners.base import BaseScanner

log = structlog.get_logger()

class R3LlmManipulationScanner(BaseScanner):
    """Analyses tool definitions and responses for LLM manipulation attempts."""

    @property
    def name(self) -> str:
        return "r3_llm_manipulation"

    @property
    def risk_type(self) -> RiskType:
        return RiskType.R3

    async def analyze(self, ctx: AnalysisContext) -> list[Finding]:
        findings: list[Finding] = []
        # Description-text pattern scanning moved to the shared
        # ``static/scanners/descriptions.py``. It runs on the same runtime
        # tools/list captured here, fed through the static findings runner —
        # one canonical scanner, not two. Tool-poisoning heuristics (name
        # collisions, hidden Unicode in identifiers, etc.) remain here
        # because they operate on more than description text.
        findings.extend(await self._scan_tool_poisoning(ctx))
        findings.extend(await self._scan_responses(ctx))
        findings.extend(await self._scan_resource_reads(ctx))
        return findings

    # -- tool_poisoning heuristics -------------------------------------------

    async def _scan_tool_poisoning(self, ctx: AnalysisContext) -> list[Finding]:
        """Run scan_tool_list() + looks_like_poisoned_description() over real tools."""
        findings: list[Finding] = []

        # Build a raw-dict list the scanner expects.
        raw_tools = [
            {
                "name": t.name,
                "description": t.description or "",
                "inputSchema": t.input_schema or {},
                "annotations": t.annotations,
            }
            for t in ctx.tools
        ]
        for hit in scan_tool_list(raw_tools):
            reason = hit.get("reason", "")
            tool_name = hit.get("tool", "")
            field = hit.get("field", "")
            value_preview = str(hit.get("value", ""))[:200]

            sev = _tool_poisoning_severity(reason)
            findings.append(Finding(
                risk_type=RiskType.R3,
                severity=sev,
                confidence=0.8,
                title=f"Tool poisoning indicator: {reason} in '{tool_name}.{field}'",
                description=(
                    f"Tool '{tool_name}' field '{field}' matches tool-poisoning pattern "
                    f"({reason}). Excerpt: \"{value_preview}\""
                ),
                tool_name=tool_name,
                reproduction=f"Inspect field '{field}' of tool '{tool_name}' in tools/list output",
            ))

        return findings

    # -- tool-return injection in mcp_response events ------------------------

    async def _scan_responses(self, ctx: AnalysisContext) -> list[Finding]:
        findings: list[Finding] = []
        reader = ctx.event_reader  # type: ignore[union-attr]

        async for evt in reader.events_by_type("mcp_response"):
            msg: dict[str, Any] = evt.data.get("message", {})
            result = msg.get("result", {})
            content_list = result.get("content", [])
            response_text = _extract_text(content_list)
            if not response_text:
                continue

            # Static pattern scan.
            for m in scan_response(response_text):
                req_method = evt.data.get("method")
                findings.append(Finding(
                    risk_type=RiskType.R3,
                    severity=_sev(m.severity),
                    confidence=0.8,
                    title=f"Tool-return injection: '{m.pattern_name}'",
                    description=(
                        f"A tool response contains pattern '{m.pattern_name}' "
                        f"that may hijack LLM behaviour.  Matched: \"{m.matched_text}\""
                    ),
                    related_events=[evt.event_id],
                    reproduction=f"Replay request {req_method} and inspect response",
                ))

        return findings

    # -- resource body scan --------------------------------------------------

    async def _scan_resource_reads(self, ctx: AnalysisContext) -> list[Finding]:
        """Check resources/read responses for indirect prompt injection."""
        findings: list[Finding] = []
        reader = ctx.event_reader  # type: ignore[union-attr]

        async for evt in reader.events_by_type("mcp_response"):
            msg: dict[str, Any] = evt.data.get("message", {})
            result = msg.get("result", {})
            # resources/read returns {"contents": [...]}
            contents = result.get("contents", [])
            if not contents:
                continue
            for item in contents:
                if not isinstance(item, dict):
                    continue
                body = item.get("text", "")
                uri = item.get("uri", "")
                mime = item.get("mimeType", "text/plain")
                if not body:
                    continue

                if looks_like_poisoned_resource(body):
                    findings.append(Finding(
                        risk_type=RiskType.R3,
                        severity=Severity.HIGH,
                        confidence=0.8,
                        title=f"Indirect prompt injection in resource '{uri}'",
                        description=(
                            f"Resource body at '{uri}' contains injection patterns "
                            f"that may manipulate the consuming LLM."
                        ),
                        related_events=[evt.event_id],
                        reproduction=f"Read resource '{uri}' and inspect body",
                    ))

                for hit in scan_resource_response(uri, mime, body):
                    findings.append(Finding(
                        risk_type=RiskType.R3,
                        severity=Severity.MEDIUM,
                        confidence=0.7,
                        title=f"Resource anomaly: {hit.get('reason')} at '{uri}'",
                        description=str(hit),
                        related_events=[evt.event_id],
                        reproduction=f"Inspect resource '{uri}'",
                    ))

        return findings

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_SEV_MAP = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}


def _sev(s: str) -> Severity:
    return _SEV_MAP.get(s, Severity.MEDIUM)


def _tool_poisoning_severity(reason: str) -> Severity:
    if reason in {"hidden-unicode-in-name", "hidden-unicode-in-text", "tool-name-collision"}:
        return Severity.CRITICAL
    return Severity.HIGH


def _extract_text(content_list: list[dict[str, Any]] | Any) -> str:
    if not isinstance(content_list, list):
        return str(content_list) if content_list else ""
    parts: list[str] = []
    for item in content_list:
        if isinstance(item, dict) and item.get("type") == "text":
            parts.append(item.get("text", ""))
        elif isinstance(item, str):
            parts.append(item)
    return "\n".join(parts)
