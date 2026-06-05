"""Finding produced by a static-analysis scanner.

Kept separate from the dynamic-side ``Finding`` (which carries runtime concepts
like related event ids and reproduction steps). Static findings instead carry a
source location. Both reuse the same ``RiskType`` / ``Severity`` vocabulary so
the unified report can merge them under one risk taxonomy.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from mcp_security_analyzer.dynamic.models import RiskType, Severity


@dataclass(frozen=True)
class StaticFinding:
    """A security signal found by inspecting source / manifest / tool metadata.

    ``confidence`` follows the dynamic side's convention: a 0..1 estimate of how
    likely this is a true positive. Static signals are mostly suspicions to be
    corroborated by the dynamic phase, so confidence is generally moderate.
    """

    risk_type: RiskType
    severity: Severity
    confidence: float
    title: str
    description: str
    scanner: str
    # Human-readable source location, e.g. "dist/index.js:176" or
    # "package.json (dependencies)". None when not tied to a specific spot.
    location: str | None = None
    # The matched snippet / evidence, trimmed. Optional.
    evidence: str | None = None
    # Tool name when the finding concerns a specific MCP tool.
    tool_name: str | None = None
    tags: tuple[str, ...] = field(default_factory=tuple)
    # Catalog key for the severity/verdict model (output.policy). The verdict
    # engine looks up (Impact, Evidence) from this kind; unknown/None fails
    # closed. NOTE: distinct from ``evidence`` above (a matched-snippet string).
    kind: str | None = None

    def to_dict(self) -> dict:
        return {
            "risk_type": self.risk_type.value,
            "severity": self.severity.value,
            "confidence": round(self.confidence, 3),
            "title": self.title,
            "description": self.description,
            "scanner": self.scanner,
            "location": self.location,
            "evidence": self.evidence,
            "tool_name": self.tool_name,
            "tags": list(self.tags),
            "kind": self.kind,
        }
