"""Semgrep wrapper (R1/R2/R4/R5/R6).

Invokes the Semgrep CLI as a subprocess against a source tree and converts its
JSON output into ``StaticFinding`` objects. Rules live in
``static/patterns/*.yaml``. When Semgrep is not installed the scanner returns
an empty list and logs a warning rather than failing the analysis.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import structlog

from mcp_security_analyzer.common.static_finding import StaticFinding
from mcp_security_analyzer.dynamic.models import RiskType, Severity

log = structlog.get_logger()

_SCANNER = "semgrep"
_PATTERNS_DIR = Path(__file__).parent.parent / "patterns"
_DEFAULT_TIMEOUT_SEC = 120

# Semgrep severity → our severity. Semgrep only has ERROR/WARNING/INFO; we lean
# on the rule's ``metadata.confidence`` to spread these across our finer scale.
_SEMGREP_SEVERITY = {
    "ERROR": Severity.HIGH,
    "WARNING": Severity.MEDIUM,
    "INFO": Severity.LOW,
}
_CONFIDENCE = {"low": 0.3, "medium": 0.55, "high": 0.75}
_RISK = {
    "R1": RiskType.R1, "R2": RiskType.R2, "R3": RiskType.R3,
    "R4": RiskType.R4, "R5": RiskType.R5, "R6": RiskType.R6,
}


def semgrep_available() -> bool:
    return shutil.which("semgrep") is not None


def scan_code_patterns(
    root: Path,
    *,
    timeout_sec: int = _DEFAULT_TIMEOUT_SEC,
) -> list[StaticFinding]:
    """Run Semgrep over *root* with the built-in rule set; return findings."""
    if not semgrep_available():
        log.warning(
            "static.semgrep.unavailable",
            hint="Install semgrep to enable code-pattern scanning; skipping.",
        )
        return []

    cmd = [
        "semgrep",
        "scan",
        "--config", str(_PATTERNS_DIR),
        "--json",
        "--quiet",
        "--no-git-ignore",
        "--timeout", str(timeout_sec),
        str(root),
    ]
    # Semgrep's built-in ignore list excludes dist/, build/, node_modules/, etc.
    # But published packages put their actual code in dist/, so scanning a
    # source tree with the default ignores would scan nothing. An empty
    # .semgrepignore in the scan root overrides the default and scans
    # everything. We add it only if absent and remove our own afterwards so a
    # local checkout is not left mutated.
    ignore_path = root / ".semgrepignore"
    added_ignore = False
    if not ignore_path.exists():
        try:
            ignore_path.write_text("", encoding="utf-8")
            added_ignore = True
        except OSError:
            pass
    try:
        proc = subprocess.run(  # noqa: S603
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_sec + 30,
        )
    except (subprocess.TimeoutExpired, OSError) as exc:
        log.warning("static.semgrep.run_failed", error=str(exc))
        return []
    finally:
        if added_ignore:
            ignore_path.unlink(missing_ok=True)

    if not proc.stdout.strip():
        if proc.returncode != 0:
            log.warning(
                "static.semgrep.nonzero_exit",
                rc=proc.returncode,
                stderr=proc.stderr[-400:],
            )
        return []

    try:
        data = json.loads(proc.stdout)
    except ValueError:
        log.warning("static.semgrep.bad_json")
        return []

    findings: list[StaticFinding] = []
    for res in data.get("results", []):
        finding = _result_to_finding(res, root)
        if finding is not None:
            findings.append(finding)

    log.info("static.semgrep.done", findings=len(findings))
    return findings


# Semgrep rule id (bare, last dotted segment) → severity/verdict catalog kind
# (output.policy). Rules with no good catalog match are omitted → kind=None →
# fail-closed to (LIMITED, POTENTIAL): a warn, never a block.
_RULE_KIND: dict[str, str] = {
    "mcp-r1-env-secret-access": "static.secret_read",
    "mcp-r1-env-secret-access-node": "static.secret_read",
    # mcp-r1-broad-file-read → fail-closed (no broad-fs-read kind)
    "mcp-r2-python-dynamic-eval": "static.eval",
    "mcp-r2-node-dynamic-eval": "static.eval",
    "mcp-r2-python-command-exec": "static.command_exec",
    "mcp-r2-node-command-exec": "static.command_exec",
    "mcp-r2-runtime-package-install": "static.runtime_install",
    "mcp-r4-sandbox-detection-python": "static.env_time_branch",
    "mcp-r4-sandbox-detection-node": "static.env_time_branch",
    "mcp-r4-time-conditional-python": "static.env_time_branch",
    "mcp-r4-time-conditional-node": "static.env_time_branch",
    "mcp-r5-python-command-injection-taint": "static.taint_flow",
    "mcp-r5-node-command-injection-taint": "static.taint_flow",
    "mcp-r5-python-path-traversal": "static.taint_flow",
    "mcp-r5-python-path-traversal-taint": "static.taint_flow",
    "mcp-r5-node-path-traversal": "static.taint_flow",
    "mcp-r5-node-path-traversal-taint": "static.taint_flow",
    "mcp-r5-node-shell-interpolation": "static.taint_flow",
    "mcp-r5-python-sql-fstring": "static.taint_flow",
    "mcp-r5-python-sql-injection-taint": "static.taint_flow",
    # mcp-r6-* (http-no-timeout, unbounded-read) → fail-closed (no R6 static kind)
}


def _result_to_finding(res: dict, root: Path) -> StaticFinding | None:
    extra = res.get("extra") or {}
    meta = extra.get("metadata") or {}

    risk = _RISK.get(str(meta.get("risk", "")).upper())
    if risk is None:
        # A rule without a recognised risk tag — skip rather than misclassify.
        return None

    # Map the specific rule id → catalog kind (None ⇒ fail-closed in policy).
    kind = _RULE_KIND.get(str(res.get("check_id", "")).split(".")[-1])

    severity = _SEMGREP_SEVERITY.get(extra.get("severity", "WARNING"), Severity.MEDIUM)
    confidence = _CONFIDENCE.get(str(meta.get("confidence", "low")).lower(), 0.3)

    path = res.get("path", "")
    try:
        rel = str(Path(path).relative_to(root))
    except ValueError:
        rel = Path(path).name
    line = (res.get("start") or {}).get("line")
    location = f"{rel}:{line}" if line else rel

    message = (extra.get("message") or "").strip()
    snippet = (extra.get("lines") or "").strip()

    return StaticFinding(
        risk_type=risk,
        severity=severity,
        confidence=confidence,
        title=res.get("check_id", "semgrep-finding").split(".")[-1],
        description=message,
        scanner=_SCANNER,
        location=location,
        evidence=snippet[:200] if snippet else None,
        tags=("semgrep", res.get("check_id", "")),
        kind=kind,
    )
