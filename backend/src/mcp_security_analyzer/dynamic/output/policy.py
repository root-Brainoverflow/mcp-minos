"""Finding-kind → (Impact, Evidence) catalog — the single source of truth for
the severity/verdict model.

See docs/severity-verdict-model.md §9. Scanners tag each Finding with a ``kind``;
this module maps that kind to its ``(Impact, Evidence)`` coordinate, from which
``output.verdict`` derives severity (§5) and the server verdict (§8). Unknown
kinds fail closed to the weakest coordinate (§8.5) so a mis-tagged finding can
never silently drive a REJECT.
"""

from __future__ import annotations

from mcp_security_analyzer.dynamic.models import Evidence, Impact

# Short aliases for the catalog table below.
_T, _P, _A, _L = Impact.TAKEOVER, Impact.PARTIAL_CI, Impact.AVAILABILITY, Impact.LIMITED
_R, _D, _PT = Evidence.REALIZED, Evidence.DETERMINISTIC, Evidence.POTENTIAL

# A coverage caveat is NOT a risk finding (no Impact/Evidence); it only drives the
# §8.4 ERROR(검사 불가) path. The verdict engine special-cases this kind.
COVERAGE_INCOMPLETE_KIND = "r6.coverage_incomplete"

# kind → (Impact, Evidence). Mirrors docs/severity-verdict-model.md §9 exactly.
CATALOG: dict[str, tuple[Impact, Evidence]] = {
    # ── R1 — data access ──
    "r1.honeypot_access": (_T, _R),
    "r1.canary_leak": (_P, _R),
    "r1.cloud_metadata": (_T, _R),
    "r1.sensitive_read": (_P, _R),
    "r1.network_egress": (_P, _R),
    # ── R2 — code execution ──
    "r2.shell_exec": (_T, _R),
    "r2.installer_exec": (_T, _R),
    "r2.cmd_injection_exec": (_T, _R),
    "r2.rce_indicator": (_T, _R),
    # ── R3 — LLM manipulation ──
    "r3.invisible_unicode_bidi": (_T, _D),
    "r3.invisible_unicode_zw": (_T, _PT),
    "r3.response_injection": (_P, _R),
    "r3.resource_indirect_injection": (_P, _R),
    "r3.resource_anomaly": (_L, _R),
    # tool-metadata text suspicions detected at runtime from tools/list — same
    # POTENTIAL class as the static descriptions scanner (warn, not block).
    "r3.tool_desc_suspicious": (_P, _PT),
    "r3.tool_name_collision": (_P, _PT),
    # ── R3 — chain attacks ──
    "chain.readonly_mismatch": (_P, _PT),
    "chain.guided_chain": (_P, _PT),
    # ── R4 — behaviour drift ──
    "r4.rug_pull": (_P, _R),
    "r4.env_tool_divergence": (_P, _R),
    "r4.capability_mismatch": (_L, _R),
    # ── R5 — input validation ──
    "r5.path_traversal": (_T, _R),
    "r5.cmd_injection": (_T, _R),
    "r5.ssrf": (_T, _R),
    "r5.nosql_exfil": (_T, _R),
    "r5.sql_error_leak": (_L, _R),
    "r5.nosql_error_leak": (_L, _R),
    "r5.type_confusion": (_A, _R),
    # ── R6 — stability (all AVAILABILITY/LIMITED → never reject) ──
    "r6.server_crash": (_A, _R),
    "r6.oom": (_A, _R),
    "r6.stack_overflow": (_A, _R),
    "r6.high_error_rate": (_L, _R),
    "r6.sequence_timeout": (_L, _R),
    "r6.error_info_leak": (_L, _R),
    "r6.error_code_misuse": (_L, _R),
    "r6.parser_failure": (_L, _R),
    "r6.oom_handled": (_L, _R),
    "r6.crash_handled": (_L, _R),
    "r6.parser_handled": (_L, _R),
    # ── static scanners (join their R-type) ──
    "static.eval": (_T, _PT),
    "static.command_exec": (_T, _PT),
    "static.runtime_install": (_T, _PT),
    "static.secret_read": (_T, _PT),
    "static.taint_flow": (_T, _PT),
    "static.env_time_branch": (_P, _PT),
    "static.tool_desc_suspicious": (_P, _PT),
    "static.malicious_package": (_T, _D),
    "static.decode_exec_hook": (_T, _D),
    "static.encoded_payload_inline": (_T, _PT),
    "static.install_hook": (_L, _PT),
    "static.typosquat": (_L, _PT),
    "static.schema_permissive": (_L, _PT),
    "static.metadata_divergence": (_L, _PT),
}

# §8.5 fail-closed default for an unrecognised kind: weakest coordinate so it can
# never drive a REJECT and is surfaced as a static-only-suspicion warning.
FAIL_CLOSED: tuple[Impact, Evidence] = (_L, _PT)


def lookup(kind: str | None) -> tuple[Impact, Evidence]:
    """Return the (Impact, Evidence) for a finding kind, fail-closed on unknown."""
    if kind is None:
        return FAIL_CLOSED
    return CATALOG.get(kind, FAIL_CLOSED)


def is_known(kind: str | None) -> bool:
    """True iff ``kind`` is an explicit catalog entry (not the fail-closed path)."""
    return kind is not None and kind in CATALOG
