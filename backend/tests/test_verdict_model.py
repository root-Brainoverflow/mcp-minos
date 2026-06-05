"""Tests for the severity/verdict model (docs/severity-verdict-model.md).

Covers the §5 severity LUT, the §8.1 reject truth table, the full §9 catalog
(every kind derives the documented severity + verdict), the ERROR(검사 불가)
coverage path (§8.4), fail-closed handling of unknown kinds (§8.5), and the
prior-review regressions (canary REJECT via the symmetric rule; the inert
scanner-set severity being ignored).
"""

from __future__ import annotations

import pytest

from mcp_security_analyzer.dynamic.models import Evidence, Finding, Impact, RiskType, Severity
from mcp_security_analyzer.dynamic.output import policy, verdict
from mcp_security_analyzer.dynamic.output.verdict import (
    Decision,
    evidence_is_strong,
    is_reject,
    severity_of,
)

T, P, A, L = Impact.TAKEOVER, Impact.PARTIAL_CI, Impact.AVAILABILITY, Impact.LIMITED
R, D, PT = Evidence.REALIZED, Evidence.DETERMINISTIC, Evidence.POTENTIAL
CRIT, HIGH, MED, LOW = Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW

_RISK_BY_PREFIX = {
    "r1": RiskType.R1, "r2": RiskType.R2, "r3": RiskType.R3,
    "r4": RiskType.R4, "r5": RiskType.R5, "r6": RiskType.R6,
    "chain": RiskType.R3, "static": RiskType.R2,
}


def mk(kind: str, *, risk_type: RiskType | None = None) -> Finding:
    """A finding tagged only with ``kind``. severity/confidence are deliberately
    bogus to prove the verdict engine ignores scanner-set severity."""
    prefix = kind.split(".", 1)[0]
    return Finding(
        risk_type=risk_type or _RISK_BY_PREFIX.get(prefix, RiskType.R1),
        severity=Severity.INFO,   # ignored by the engine
        confidence=0.01,          # ignored by the engine
        title=f"test {kind}",
        description="-",
        reproduction="-",
        kind=kind,
    )


# ---------------------------------------------------------------------------
# §5 — severity LUT (all 8 cells)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "impact,evidence,expected",
    [
        (T, R, CRIT), (T, D, CRIT), (T, PT, HIGH),
        (P, R, HIGH), (P, D, HIGH), (P, PT, MED),
        (A, R, HIGH), (A, D, HIGH), (A, PT, MED),
        (L, R, MED), (L, D, MED), (L, PT, LOW),
    ],
)
def test_severity_lut(impact, evidence, expected):
    assert severity_of(impact, evidence) == expected


def test_severity_lut_is_total():
    # every (impact, evidence) pair is defined — no KeyError anywhere
    for impact in Impact:
        for evidence in Evidence:
            assert isinstance(severity_of(impact, evidence), Severity)


def test_evidence_strength():
    assert evidence_is_strong(R) and evidence_is_strong(D)
    assert not evidence_is_strong(PT)


# ---------------------------------------------------------------------------
# §8.1 — reject truth table (symmetric rule)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "impact,evidence,expected",
    [
        (T, R, True), (T, D, True), (T, PT, False),
        (P, R, True), (P, D, True), (P, PT, False),   # P×D True == the symmetric fix
        (A, R, False), (A, D, False), (A, PT, False),
        (L, R, False), (L, D, False), (L, PT, False),
    ],
)
def test_reject_truth_table(impact, evidence, expected):
    assert is_reject(impact, evidence) is expected


# ---------------------------------------------------------------------------
# §9 — full catalog: each kind derives the documented severity + verdict
# ---------------------------------------------------------------------------

# (kind, expected_severity, expected_reject) straight from docs §9.
EXPECTED: dict[str, tuple[Severity, bool]] = {
    # R1
    "r1.honeypot_access": (CRIT, True),
    "r1.canary_leak": (HIGH, True),
    "r1.cloud_metadata": (CRIT, True),
    "r1.sensitive_read": (HIGH, True),
    "r1.network_egress": (HIGH, True),
    # R2
    "r2.shell_exec": (CRIT, True),
    "r2.installer_exec": (CRIT, True),
    "r2.cmd_injection_exec": (CRIT, True),
    "r2.rce_indicator": (CRIT, True),
    # R3
    "r3.invisible_unicode_bidi": (CRIT, True),
    "r3.invisible_unicode_zw": (HIGH, False),
    "r3.response_injection": (HIGH, True),
    "r3.resource_indirect_injection": (HIGH, True),
    "r3.resource_anomaly": (MED, False),
    "r3.tool_desc_suspicious": (MED, False),
    "r3.tool_name_collision": (MED, False),
    # chain
    "chain.readonly_mismatch": (MED, False),
    "chain.guided_chain": (MED, False),
    # R4
    "r4.rug_pull": (HIGH, True),
    "r4.env_tool_divergence": (HIGH, True),
    "r4.capability_mismatch": (MED, False),
    # R5
    "r5.path_traversal": (CRIT, True),
    "r5.cmd_injection": (CRIT, True),
    "r5.ssrf": (CRIT, True),
    "r5.nosql_exfil": (CRIT, True),
    "r5.sql_error_leak": (MED, False),
    "r5.nosql_error_leak": (MED, False),
    "r5.type_confusion": (HIGH, False),       # AVAILABILITY strong → HIGH, no reject
    # R6 (never reject)
    "r6.server_crash": (HIGH, False),
    "r6.oom": (HIGH, False),
    "r6.stack_overflow": (HIGH, False),
    "r6.high_error_rate": (MED, False),
    "r6.sequence_timeout": (MED, False),
    "r6.error_info_leak": (MED, False),
    "r6.parser_failure": (MED, False),
    "r6.oom_handled": (MED, False),
    "r6.crash_handled": (MED, False),
    "r6.parser_handled": (MED, False),
    # static
    "static.eval": (HIGH, False),
    "static.command_exec": (HIGH, False),
    "static.runtime_install": (HIGH, False),
    "static.secret_read": (HIGH, False),
    "static.taint_flow": (HIGH, False),
    "static.env_time_branch": (MED, False),
    "static.tool_desc_suspicious": (MED, False),
    "static.malicious_package": (CRIT, True),
    "static.decode_exec_hook": (CRIT, True),
    "static.encoded_payload_inline": (HIGH, False),
    "static.install_hook": (LOW, False),
    "static.typosquat": (LOW, False),
    "static.schema_permissive": (LOW, False),
    "static.metadata_divergence": (LOW, False),
}


def test_catalog_matches_expected_keys():
    # catalog and the doc-derived expectation table must stay in lockstep
    assert set(policy.CATALOG) == set(EXPECTED)


@pytest.mark.parametrize("kind", sorted(EXPECTED))
def test_catalog_derivation(kind):
    expected_sev, expected_reject = EXPECTED[kind]
    impact, evidence = policy.lookup(kind)
    assert severity_of(impact, evidence) == expected_sev
    assert is_reject(impact, evidence) is expected_reject


# ---------------------------------------------------------------------------
# §8.5 — fail-closed for unknown kinds
# ---------------------------------------------------------------------------

def test_unknown_kind_fails_closed():
    assert policy.lookup("does.not.exist") == (L, PT)
    assert policy.lookup(None) == (L, PT)
    assert not policy.is_known("does.not.exist")


def test_unknown_kind_does_not_reject():
    res = verdict.evaluate([mk("totally.unknown")])
    assert res.decision is Decision.PASS
    assert res.warnings.get(verdict.WARN_STATIC_SUSPICION) == 1


# ---------------------------------------------------------------------------
# §8 — verdict aggregation
# ---------------------------------------------------------------------------

def test_reject_wins_and_reports_reason():
    res = verdict.evaluate([mk("r5.path_traversal"), mk("r6.server_crash")])
    assert res.decision is Decision.REJECT
    assert [r.reason for r in res.reasons] == [verdict.REASON_MACHINE_TAKEOVER]


def test_canary_rejects_via_symmetric_rule():
    # regression: canary is PARTIAL_CI + REALIZED → HIGH → REJECT (data-access)
    res = verdict.evaluate([mk("r1.canary_leak")])
    assert res.decision is Decision.REJECT
    assert res.reasons[0].reason == verdict.REASON_DATA_ACCESS


def test_known_malware_vs_takeover_reasons():
    res = verdict.evaluate([mk("static.malicious_package")])
    assert res.reasons[0].reason == verdict.REASON_KNOWN_MALWARE
    # decode-exec hook is DETERMINISTIC takeover but NOT "known-malware"
    res2 = verdict.evaluate([mk("static.decode_exec_hook")])
    assert res2.reasons[0].reason == verdict.REASON_MACHINE_TAKEOVER


def test_integrity_reason_for_non_r1_partial_ci():
    res = verdict.evaluate([mk("r3.response_injection")])
    assert res.reasons[0].reason == verdict.REASON_INTEGRITY


def test_availability_only_passes_with_warning():
    res = verdict.evaluate([mk("r6.server_crash"), mk("r6.oom")])
    assert res.decision is Decision.PASS
    assert res.warnings.get(verdict.WARN_AVAILABILITY) == 2
    assert res.max_residual_severity == HIGH


def test_static_suspicion_passes():
    res = verdict.evaluate([mk("static.taint_flow"), mk("static.tool_desc_suspicious")])
    assert res.decision is Decision.PASS
    assert res.warnings.get(verdict.WARN_STATIC_SUSPICION) == 2


def test_clean_scan_passes():
    res = verdict.evaluate([])
    assert res.decision is Decision.PASS
    assert res.max_residual_severity is None


# ---------------------------------------------------------------------------
# §8.4 — ERROR(검사 불가)
# ---------------------------------------------------------------------------

def test_coverage_void_is_error_not_pass():
    res = verdict.evaluate([], coverage_ok=False, error_message="server failed to boot")
    assert res.decision is Decision.ERROR
    assert res.error_code == "untestable"
    assert res.error_message == "server failed to boot"


def test_coverage_caveat_finding_forces_error():
    res = verdict.evaluate([mk(policy.COVERAGE_INCOMPLETE_KIND)])
    assert res.decision is Decision.ERROR
    # the caveat itself is not counted as a risk/warning finding
    assert res.warnings == {}


def test_reject_takes_precedence_over_error():
    # confirmed compromise during a partial scan stays REJECT (§8.4 priority)
    res = verdict.evaluate([mk("r5.cmd_injection")], coverage_ok=False)
    assert res.decision is Decision.REJECT


def test_scanner_set_severity_is_ignored():
    # mk() sets severity=INFO; the engine must derive CRITICAL from the kind
    f = mk("r5.path_traversal")
    assert f.severity is Severity.INFO
    _impact, _evidence, derived = verdict.classify(f)
    assert derived is CRIT
