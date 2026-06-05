"""Severity LUT (§5) + binary risk verdict with a separate ERROR(검사 불가)
outcome (§8). Replaces the legacy continuous ``scorer.py``.

Implements docs/severity-verdict-model.md:

* severity is a *total function* of (Impact, Evidence) — no continuous scoring;
* the server verdict is REJECT iff any finding is a strong-evidence C/I
  compromise (incl. host takeover);
* an untestable scan (no meaningful coverage) returns ERROR instead of a risk
  verdict, so "no evidence of compromise" is never reported as "safe";
* everything else is PASS, carrying a warnings breakdown.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from mcp_security_analyzer.dynamic.models import Evidence, Finding, Impact, RiskType, Severity
from mcp_security_analyzer.dynamic.output import policy

# ---------------------------------------------------------------------------
# §5 — Severity = LUT(Impact, Evidence)
# ---------------------------------------------------------------------------

_STRONG: tuple[Evidence, ...] = (Evidence.REALIZED, Evidence.DETERMINISTIC)

_SEVERITY_LUT: dict[tuple[Impact, bool], Severity] = {
    (Impact.TAKEOVER, True): Severity.CRITICAL,
    (Impact.TAKEOVER, False): Severity.HIGH,
    (Impact.PARTIAL_CI, True): Severity.HIGH,
    (Impact.PARTIAL_CI, False): Severity.MEDIUM,
    (Impact.AVAILABILITY, True): Severity.HIGH,
    (Impact.AVAILABILITY, False): Severity.MEDIUM,
    (Impact.LIMITED, True): Severity.MEDIUM,
    (Impact.LIMITED, False): Severity.LOW,
}

_SEV_ORDER: dict[Severity, int] = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.INFO: 0,
}


def evidence_is_strong(evidence: Evidence) -> bool:
    """REALIZED / DETERMINISTIC are the strong-evidence classes (§4.1, §5)."""
    return evidence in _STRONG


def severity_of(impact: Impact, evidence: Evidence) -> Severity:
    """§5: severity = LUT(impact, evidence_is_strong). Total over all inputs."""
    return _SEVERITY_LUT[(impact, evidence_is_strong(evidence))]


# ---------------------------------------------------------------------------
# §8.1 — reject predicate
# ---------------------------------------------------------------------------

_REJECT_IMPACTS: tuple[Impact, ...] = (Impact.TAKEOVER, Impact.PARTIAL_CI)


def is_reject(impact: Impact, evidence: Evidence) -> bool:
    """§8.1: a strong-evidence C/I compromise (incl. host takeover) blocks.

        REJECT ⇔ impact ∈ {TAKEOVER, PARTIAL_CI} ∧ evidence ∈ {REALIZED, DETERMINISTIC}
    """
    return impact in _REJECT_IMPACTS and evidence_is_strong(evidence)


def resolve(finding: object) -> tuple[Impact, Evidence]:
    """A finding's (Impact, Evidence): explicit fields if set, else catalog by kind.

    Duck-typed so it works for both the dynamic ``Finding`` (which carries
    ``impact``/``evidence`` enum fields) and the static ``StaticFinding`` (whose
    ``evidence`` attribute is an unrelated matched-snippet string) — only genuine
    enum values are honoured; everything else resolves from the catalog by kind.
    """
    impact = getattr(finding, "impact", None)
    evidence = getattr(finding, "evidence", None)
    if not isinstance(impact, Impact):
        impact = None
    if not isinstance(evidence, Evidence):
        evidence = None
    if impact is None or evidence is None:
        cat_impact, cat_evidence = policy.lookup(getattr(finding, "kind", None))
        impact = impact or cat_impact
        evidence = evidence or cat_evidence
    return impact, evidence


def classify(finding: object) -> tuple[Impact, Evidence, Severity]:
    """Full classification of one finding: (impact, evidence, derived severity)."""
    impact, evidence = resolve(finding)
    return impact, evidence, severity_of(impact, evidence)


# ---------------------------------------------------------------------------
# §8 — verdict
# ---------------------------------------------------------------------------

class Decision(str, Enum):
    """Terminal outcome. REJECT/PASS are the binary *risk* verdict; ERROR means
    the scan could not establish a result (검사 불가) — an execution-validity
    state, not a risk tier."""

    REJECT = "REJECT"
    PASS = "PASS"
    ERROR = "ERROR"


# §8.5 reject-reason taxonomy (priority-ordered, mutually exclusive).
REASON_KNOWN_MALWARE = "known-malware"
REASON_MACHINE_TAKEOVER = "machine-takeover"
REASON_DATA_ACCESS = "data-access"
REASON_INTEGRITY = "integrity-manipulation"

# §8.5 warning categories (non-blocking findings).
WARN_AVAILABILITY = "availability/stability"
WARN_STATIC_SUSPICION = "static-only-suspicion"
WARN_LIMITED_LEAK = "limited-info-leak"


@dataclass
class RejectReason:
    finding_id: str | None
    kind: str | None
    reason: str


@dataclass
class VerdictResult:
    decision: Decision
    reasons: list[RejectReason] = field(default_factory=list)
    warnings: dict[str, int] = field(default_factory=dict)
    max_residual_severity: Severity | None = None
    coverage_ok: bool = True
    error_code: str | None = None       # "untestable" when decision is ERROR
    error_message: str | None = None

    def to_dict(self) -> dict:
        return {
            "decision": self.decision.value,
            "reasons": [
                {"reason": r.reason, "kind": r.kind, "finding_id": r.finding_id}
                for r in self.reasons
            ],
            "warnings": dict(self.warnings),
            "max_residual_severity": (
                self.max_residual_severity.value if self.max_residual_severity else None
            ),
            "coverage_ok": self.coverage_ok,
            "error_code": self.error_code,
            "error_message": self.error_message,
        }


def _reject_reason(finding: object, impact: Impact) -> str:
    # known-malware is reserved for the denylist/package hit only (§8.5);
    # other DETERMINISTIC takeovers (decode-exec hook, bidi unicode) are
    # machine-takeover.
    if getattr(finding, "kind", None) == "static.malicious_package":
        return REASON_KNOWN_MALWARE
    if impact is Impact.TAKEOVER:
        return REASON_MACHINE_TAKEOVER
    # PARTIAL_CI: confidentiality (R1 data access) vs integrity (everything else).
    return REASON_DATA_ACCESS if getattr(finding, "risk_type", None) is RiskType.R1 else REASON_INTEGRITY


def _warning_category(impact: Impact, evidence: Evidence) -> str:
    if evidence is Evidence.POTENTIAL:
        return WARN_STATIC_SUSPICION
    if impact is Impact.AVAILABILITY:
        return WARN_AVAILABILITY
    return WARN_LIMITED_LEAK  # LIMITED realized (e.g. verbose error leak)


def evaluate(
    findings: list[Finding],
    *,
    coverage_ok: bool = True,
    error_message: str | None = None,
) -> VerdictResult:
    """Compute the server verdict from a finding pool (static+dynamic union).

    Precedence is REJECT > ERROR > PASS (§8.4): a confirmed compromise stays a
    REJECT even on partial coverage; otherwise an untestable scan is ERROR; a
    fully-tested clean scan is PASS.

    ``coverage_ok`` is supplied by the caller (server booted, tools discovered,
    sequences ran). A ``r6.coverage_incomplete`` caveat finding also forces the
    coverage-void path.
    """
    has_caveat = any(getattr(f, "kind", None) == policy.COVERAGE_INCOMPLETE_KIND for f in findings)
    coverage = coverage_ok and not has_caveat

    reasons: list[RejectReason] = []
    warnings: dict[str, int] = {}
    residual: list[Severity] = []

    for f in findings:
        if getattr(f, "kind", None) == policy.COVERAGE_INCOMPLETE_KIND:
            continue  # coverage caveat is not a risk finding (§9 note)
        impact, evidence = resolve(f)
        if is_reject(impact, evidence):
            reasons.append(
                RejectReason(getattr(f, "finding_id", None), getattr(f, "kind", None), _reject_reason(f, impact))
            )
        else:
            cat = _warning_category(impact, evidence)
            warnings[cat] = warnings.get(cat, 0) + 1
            residual.append(severity_of(impact, evidence))

    if reasons:
        decision = Decision.REJECT
    elif not coverage:
        decision = Decision.ERROR
    else:
        decision = Decision.PASS

    max_res = max(residual, key=lambda s: _SEV_ORDER[s], default=None)

    return VerdictResult(
        decision=decision,
        reasons=reasons,
        warnings=warnings,
        max_residual_severity=max_res,
        coverage_ok=coverage,
        error_code="untestable" if decision is Decision.ERROR else None,
        error_message=error_message if decision is Decision.ERROR else None,
    )
