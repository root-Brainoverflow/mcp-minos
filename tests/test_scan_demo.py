"""End-to-end demo: the real R1 + R5 scanners feed the new verdict engine.

This drives the *actual* scanner ``analyze()`` code over an event stream that
reproduces the vulnerable fixture's behaviour (no Docker), confirms the
findings are tagged with the new ``kind`` field, and shows ``verdict.evaluate``
turning them into a REJECT. A benign event stream yields PASS — proving the
model does not over-reject.

Run: ``.venv/bin/python -m pytest tests/test_scan_demo.py -v``
"""

from __future__ import annotations

import asyncio
from pathlib import Path

from mcp_security_analyzer.common.static_finding import StaticFinding
from mcp_security_analyzer.dynamic.correlation.event_store import EventStore
from mcp_security_analyzer.dynamic.models import (
    AnalysisContext,
    Event,
    Finding,
    RiskType,
    Severity,
    ToolInfo,
)
from mcp_security_analyzer.dynamic.output import verdict
from mcp_security_analyzer.dynamic.output.verdict import Decision
from mcp_security_analyzer.dynamic.scanners.r1_data_access import R1DataAccessScanner
from mcp_security_analyzer.dynamic.scanners.r5_input_validation import R5InputValidationScanner

READ_FILE = ToolInfo(
    name="read_file",
    description="Read a file",
    input_schema={"properties": {"path": {"type": "string"}}},
)


def _event(source: str, type_: str, **data: object) -> Event:
    return Event(session_id="ses-demo", source=source, type=type_, data=dict(data))


async def _run_real_scanners(tmp: Path, events: list[Event]) -> list:
    """Write events, then run the real R1 + R5 scanner analyze() over them."""
    store = EventStore(tmp / "demo-session")
    async with store.writer as w:
        for e in events:
            await w.write(e)
    ctx = AnalysisContext(
        session_id="ses-demo",
        event_reader=store.reader,
        tools=[READ_FILE],
        config={},
    )
    findings: list = []
    findings += await R1DataAccessScanner().analyze(ctx)
    findings += await R5InputValidationScanner().analyze(ctx)
    return findings


def test_vulnerable_fixture_scan_rejects(tmp_path: Path) -> None:
    # The vulnerable fixture's read_file opens any path with no validation:
    #  (1) it reads sensitive files            → R1 syscall finding
    #  (2) a path-traversal fuzz payload returns /etc/passwd content → R5 finding
    events = [
        _event("syscall", "file_open", path="/home/user/.ssh/id_rsa"),
        _event(
            "test", "test_result",
            sequence="fuzz_input_validation",
            category="path_traversal",
            tool="read_file",
            outcome="server_response",
            payload_repr="../../../../etc/passwd",
            response_preview=(
                "root:x:0:0:root:/root:/bin/bash\n"
                "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin"
            ),
        ),
    ]
    findings = asyncio.run(_run_real_scanners(tmp_path, events))

    # The real scanners tagged each finding with a catalog kind.
    kinds = {f.kind for f in findings}
    assert "r1.sensitive_read" in kinds, kinds
    assert "r5.path_traversal" in kinds, kinds

    # The verdict engine derives severity from kind and blocks the server.
    result = verdict.evaluate(findings)
    assert result.decision is Decision.REJECT
    reasons = {r.reason for r in result.reasons}
    assert verdict.REASON_DATA_ACCESS in reasons        # sensitive read (R1)
    assert verdict.REASON_MACHINE_TAKEOVER in reasons   # path traversal (R5)


def test_benign_fixture_scan_passes(tmp_path: Path) -> None:
    # Benign behaviour: an ordinary file access + a clean tool response carrying
    # no exploit indicators → no R1/R5 findings → PASS (no over-rejection).
    events = [
        _event("syscall", "file_open", path="/tmp/workdir/notes.txt"),
        _event(
            "test", "test_result",
            sequence="fuzz_input_validation",
            category="path_traversal",
            tool="read_file",
            outcome="server_response",
            payload_repr="../../../../etc/passwd",
            response_preview="Hello, world!",
        ),
    ]
    findings = asyncio.run(_run_real_scanners(tmp_path, events))
    assert findings == [], [f.title for f in findings]

    result = verdict.evaluate(findings)
    assert result.decision is Decision.PASS
    assert result.max_residual_severity is None


def _static(kind: str, risk: RiskType = RiskType.R2) -> StaticFinding:
    return StaticFinding(
        risk_type=risk, severity=Severity.INFO, confidence=0.1,
        title=f"static {kind}", description="-", scanner="test", kind=kind,
    )


def test_static_finding_unions_into_verdict() -> None:
    # a static-only known-malicious package blocks via duck-typed evaluation
    # (StaticFinding has no impact/evidence enum fields — resolved by kind)
    result = verdict.evaluate([_static("static.malicious_package")])
    assert result.decision is Decision.REJECT
    assert result.reasons[0].reason == verdict.REASON_KNOWN_MALWARE


def test_static_dynamic_union_blocks() -> None:
    # benign dynamic crash (warn) + static malicious package (block) → REJECT
    f_crash = Finding(
        risk_type=RiskType.R6, severity=Severity.INFO, confidence=0.1,
        title="crash", description="-", reproduction="-", kind="r6.server_crash",
    )
    result = verdict.evaluate([f_crash, _static("static.decode_exec_hook")])
    assert result.decision is Decision.REJECT
    assert result.warnings.get(verdict.WARN_AVAILABILITY) == 1  # the crash still warns


def test_static_potential_only_passes() -> None:
    result = verdict.evaluate([_static("static.tool_desc_suspicious", risk=RiskType.R3)])
    assert result.decision is Decision.PASS
    assert result.warnings.get(verdict.WARN_STATIC_SUSPICION) == 1


def test_server_crash_warns_or_errors_by_coverage() -> None:
    # The discriminator for a server crash is coverage, not the crash itself
    # (docs/severity-verdict-model.md §8.4). Same finding, two outcomes.
    crash = Finding(
        risk_type=RiskType.R6, severity=Severity.INFO, confidence=0.1,
        title="server crashed", description="-", reproduction="-", kind="r6.server_crash",
    )
    # recovered crash (scan completed) → AVAILABILITY warning, PASS — never REJECT
    recovered = verdict.evaluate([crash], coverage_ok=True)
    assert recovered.decision is Decision.PASS
    assert recovered.warnings.get(verdict.WARN_AVAILABILITY) == 1
    # unrecovered crash that truncated the scan → ERROR(검사 불가), not PASS
    truncated = verdict.evaluate([crash], coverage_ok=False)
    assert truncated.decision is Decision.ERROR
    assert truncated.error_code == "untestable"
