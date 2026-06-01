"""Static findings runner — composes static scanners into one report.

Source-tree scanners (manifest security, semgrep) run against the extracted
or local source tree carried by the environment snapshot.

Description scanner (2.4) and schema auditor (2.5) share the same input
selection: source-extracted tool definitions are preferred when available
(``tool_extractor`` recovers zod schemas as JSON Schema dicts), and the
runtime ``tools/list`` response captured by the dynamic phase is used as a
fallback. The source path lets ``minos static`` produce both R3 and R5
findings without standing up the sandbox.

The schema auditor runs only on tools whose ``input_schema`` is set. Source
extraction recovers schemas for zod-based servers but skips tools whose
schema we can't represent (pydantic, refinements, etc.); for those the
runtime ``tools/list`` fallback fills in.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import structlog

from mcp_security_analyzer.common.environment_snapshot import EnvironmentSnapshot
from mcp_security_analyzer.common.static_finding import StaticFinding
from mcp_security_analyzer.dynamic.models import ToolInfo
from mcp_security_analyzer.static.scanners.code_patterns import scan_code_patterns
from mcp_security_analyzer.static.scanners.descriptions import scan_descriptions
from mcp_security_analyzer.static.scanners.manifest_security import scan_manifest_security
from mcp_security_analyzer.static.scanners.metadata_divergence import scan_metadata_divergence
from mcp_security_analyzer.static.scanners.schema_audit import scan_schemas
from mcp_security_analyzer.static.tool_extractor import extract_tools_from_source

log = structlog.get_logger()


@dataclass(frozen=True)
class StaticReport:
    """Result of the static analysis phase."""

    findings: tuple[StaticFinding, ...]
    tools_analyzed: int
    # ``"source"``: tools came from source extraction.
    # ``"runtime"``: tools came from the dynamic phase's tools/list response.
    # ``"none"``: no tool list was available.
    tool_source: str
    scanners_run: tuple[str, ...]
    scanners_skipped: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict:
        return {
            "findings": [f.to_dict() for f in self.findings],
            "tools_analyzed": self.tools_analyzed,
            "tool_source": self.tool_source,
            "scanners_run": list(self.scanners_run),
            "scanners_skipped": list(self.scanners_skipped),
        }


def run_static_findings(
    snapshot: EnvironmentSnapshot,
    *,
    runtime_tools: list[ToolInfo] | None = None,
) -> StaticReport:
    """Run every applicable static scanner and collect their findings."""
    findings: list[StaticFinding] = []
    scanners_run: list[str] = []
    scanners_skipped: list[str] = []

    # ── Source-tree scanners ────────────────────────────────────────────────
    source_tools: list[ToolInfo] = []
    if snapshot.has_source_tree:
        root = snapshot.source_tree_path
        assert root is not None
        findings.extend(scan_manifest_security(root))
        scanners_run.append("manifest_security")

        findings.extend(scan_code_patterns(root))
        scanners_run.append("semgrep")

        source_tools = extract_tools_from_source(root)
    else:
        scanners_skipped.extend(["manifest_security", "semgrep"])

    # ── Pick the tool list: prefer source, fall back to runtime ─────────────
    if source_tools:
        tools = source_tools
        tool_source = "source"
    elif runtime_tools:
        tools = runtime_tools
        tool_source = "runtime"
    else:
        tools = []
        tool_source = "none"

    # ── Description scanner ─────────────────────────────────────────────────
    if tools:
        findings.extend(scan_descriptions(tools))
        scanners_run.append("descriptions")
    else:
        scanners_skipped.append("descriptions")

    # ── Schema auditor — runs on whatever tool list we have ─────────────────
    # ``scan_schemas`` already skips per-tool when ``input_schema`` is missing,
    # so source-extracted tools without a recoverable schema simply contribute
    # nothing without breaking the rest of the audit.
    if tools and any(t.input_schema for t in tools):
        findings.extend(scan_schemas(tools))
        scanners_run.append("schema_audit")
    else:
        scanners_skipped.append("schema_audit")

    # ── Source vs. runtime metadata divergence (rug pull / evasion) ─────────
    # Only meaningful when BOTH channels of evidence are present. Reports
    # tools missing on either side and description content / length mismatches
    # as low-confidence R4 signals.
    if source_tools and runtime_tools:
        findings.extend(scan_metadata_divergence(source_tools, runtime_tools))
        scanners_run.append("metadata_divergence")
    else:
        scanners_skipped.append("metadata_divergence")

    tools_analyzed = len(tools)

    log.info(
        "static.findings.done",
        findings=len(findings),
        tools=tools_analyzed,
        tool_source=tool_source,
        scanners_run=scanners_run,
    )

    return StaticReport(
        findings=tuple(findings),
        tools_analyzed=tools_analyzed,
        tool_source=tool_source,
        scanners_run=tuple(scanners_run),
        scanners_skipped=tuple(scanners_skipped),
    )
