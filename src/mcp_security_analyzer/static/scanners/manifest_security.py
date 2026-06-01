"""Manifest security scanner (R2).

Inspects the dependency manifests in an extracted source tree for three classes
of supply-chain risk:

1. Known-malicious package names (a small built-in denylist; meant to be
   extended from an external feed later).
2. Typosquatting suspicion — a dependency whose name is a tiny edit away from a
   very popular package but is not that package.
3. Install-time script hooks (``preinstall`` / ``postinstall`` /
   ``install`` in package.json) that run shell on ``npm install`` — and a flag
   when those scripts contain high-risk patterns (piping a download into a
   shell, ``eval``, etc.).

Operates purely on files in the tree, so it works the same for a local checkout
and for an extracted tarball.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from mcp_security_analyzer.common.static_finding import StaticFinding
from mcp_security_analyzer.dynamic.models import RiskType, Severity

_SCANNER = "manifest_security"

# Tiny seed denylist. In production this would be backed by an external advisory
# feed; kept inline so the scanner is useful out of the box.
_KNOWN_MALICIOUS: frozenset[str] = frozenset({
    "node-ipc",            # protestware sabotage (2022)
    "event-stream",        # crypto-stealer payload (2018)
    "flatmap-stream",      # the actual malicious dep injected into event-stream
    "ua-parser-js-bad",    # placeholder for the compromised-release class
})

# Popular packages typosquatters imitate. Compared by edit distance == 1.
_POPULAR_TARGETS: frozenset[str] = frozenset({
    "react", "lodash", "express", "axios", "chalk", "commander", "request",
    "moment", "debug", "next", "vue", "webpack", "typescript", "ws", "zod",
    "requests", "urllib3", "numpy", "pandas", "flask", "django", "setuptools",
    "cryptography", "pyyaml", "boto3", "fastapi", "pydantic",
})

# Patterns inside an install script that indicate active risk, not just a build.
_DANGEROUS_SCRIPT_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("curl-pipe-sh",  re.compile(r"\b(curl|wget)\b[^\n|]*\|\s*(sh|bash|node|python)", re.I)),
    ("eval",          re.compile(r"\beval\b", re.I)),
    ("base64-decode", re.compile(r"base64\s+(-d|--decode)", re.I)),
    ("remote-fetch",  re.compile(r"https?://[^\s'\"]+\.(sh|py|js)\b", re.I)),
    # Staged-payload pattern: an install hook with a long encoded blob embedded
    # in the body. Common in advanced supply-chain malware that ships the real
    # payload inline (``node -e "<base64...>"``, hex-shifted string then decode).
    # Legitimate build scripts rarely contain blobs this long.
    ("base64-blob",   re.compile(r"[A-Za-z0-9+/]{60,}={0,2}")),
    ("hex-blob",      re.compile(r"(?:\\x[0-9a-fA-F]{2}){30,}|(?:0x[0-9a-fA-F]{2,}\s*,\s*){20,}")),
    ("node-eval",     re.compile(r"\bnode\s+-e\s+['\"]", re.I)),
    ("python-exec-c", re.compile(r"\bpython3?\s+-c\s+['\"]", re.I)),
)

_NPM_INSTALL_HOOKS = ("preinstall", "install", "postinstall")


def scan_manifest_security(root: Path) -> list[StaticFinding]:
    """Return supply-chain findings for the manifests under *root*."""
    findings: list[StaticFinding] = []

    pkg_json = root / "package.json"
    if pkg_json.is_file():
        findings.extend(_scan_package_json(pkg_json))

    # Python dependency names from the same readers the analyzer already uses.
    for manifest in ("pyproject.toml", "requirements.txt"):
        path = root / manifest
        if path.is_file():
            findings.extend(_scan_python_manifest(path))

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# package.json
# ─────────────────────────────────────────────────────────────────────────────


def _scan_package_json(path: Path) -> list[StaticFinding]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    if not isinstance(data, dict):
        return []

    findings: list[StaticFinding] = []
    label = path.name

    names: set[str] = set()
    for field_name in ("dependencies", "devDependencies", "optionalDependencies"):
        mapping = data.get(field_name)
        if isinstance(mapping, dict):
            names.update(k for k in mapping if isinstance(k, str))

    findings.extend(_check_dependency_names(names, f"{label} (dependencies)"))

    scripts = data.get("scripts")
    if isinstance(scripts, dict):
        findings.extend(_check_install_scripts(scripts, label))

    return findings


def _check_install_scripts(scripts: dict, label: str) -> list[StaticFinding]:
    findings: list[StaticFinding] = []
    for hook in _NPM_INSTALL_HOOKS:
        body = scripts.get(hook)
        if not isinstance(body, str) or not body.strip():
            continue

        matched_tags = [tag for tag, rx in _DANGEROUS_SCRIPT_PATTERNS if rx.search(body)]
        if matched_tags:
            findings.append(StaticFinding(
                risk_type=RiskType.R2,
                severity=Severity.HIGH,
                confidence=0.7,
                title=f"Install hook '{hook}' runs a high-risk command",
                description=(
                    f"The npm '{hook}' script executes on every install and "
                    f"matches risky pattern(s): {', '.join(matched_tags)}. "
                    "Install hooks run before any code review and are a common "
                    "supply-chain execution vector."
                ),
                scanner=_SCANNER,
                location=f"{label} (scripts.{hook})",
                evidence=body[:200],
                tags=("install-hook", *matched_tags),
            ))
        else:
            # An install hook that merely builds is low-signal but worth noting.
            findings.append(StaticFinding(
                risk_type=RiskType.R2,
                severity=Severity.LOW,
                confidence=0.25,
                title=f"Install hook '{hook}' present",
                description=(
                    f"The npm '{hook}' script runs on install. No high-risk "
                    "pattern detected, but install hooks execute code before "
                    "the package is ever used."
                ),
                scanner=_SCANNER,
                location=f"{label} (scripts.{hook})",
                evidence=body[:200],
                tags=("install-hook",),
            ))
    return findings


# ─────────────────────────────────────────────────────────────────────────────
# Python manifests
# ─────────────────────────────────────────────────────────────────────────────


def _scan_python_manifest(path: Path) -> list[StaticFinding]:
    names: set[str] = set()
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return []

    # Lightweight name extraction — we only need the package names, not full
    # requirement parsing. Picks up the leading identifier on each line.
    for line in text.splitlines():
        m = re.match(r"\s*[\"']?([A-Za-z0-9_.-]+)", line)
        if m:
            cand = m.group(1).lower().replace("_", "-")
            if cand and not cand.startswith(("#", "[", "-")):
                names.add(cand)

    return _check_dependency_names(names, f"{path.name} (dependencies)")


# ─────────────────────────────────────────────────────────────────────────────
# Shared name checks
# ─────────────────────────────────────────────────────────────────────────────


def _check_dependency_names(names: set[str], label: str) -> list[StaticFinding]:
    findings: list[StaticFinding] = []
    for name in sorted(names):
        bare = _strip_scope(name).lower()

        if bare in _KNOWN_MALICIOUS:
            findings.append(StaticFinding(
                risk_type=RiskType.R2,
                severity=Severity.CRITICAL,
                confidence=0.9,
                title=f"Known-malicious dependency '{name}'",
                description=(
                    f"'{name}' appears on the known-malicious package list. "
                    "Its presence in the dependency tree is a strong indicator "
                    "of a compromised or hostile supply chain."
                ),
                scanner=_SCANNER,
                location=label,
                tags=("malicious-package",),
            ))
            continue

        squat = _typosquat_target(bare)
        if squat:
            findings.append(StaticFinding(
                risk_type=RiskType.R2,
                severity=Severity.MEDIUM,
                confidence=0.4,
                title=f"Possible typosquat: '{name}' vs '{squat}'",
                description=(
                    f"Dependency '{name}' is one character different from the "
                    f"popular package '{squat}'. This may be a typosquatting "
                    "package impersonating the real one — verify it is intended."
                ),
                scanner=_SCANNER,
                location=label,
                tags=("typosquat",),
            ))
    return findings


def _strip_scope(name: str) -> str:
    # @scope/pkg → pkg
    if name.startswith("@") and "/" in name:
        return name.split("/", 1)[1]
    return name


def _typosquat_target(name: str) -> str | None:
    """Return a popular package name within edit distance 1 of *name*, else None.

    The package must not BE the popular package (only a near-miss counts).
    """
    if name in _POPULAR_TARGETS:
        return None
    for target in _POPULAR_TARGETS:
        if abs(len(name) - len(target)) <= 1 and _within_edit_distance_one(name, target):
            return target
    return None


def _within_edit_distance_one(a: str, b: str) -> bool:
    """True iff *a* and *b* differ by at most one insertion/deletion/substitution."""
    if a == b:
        return True
    la, lb = len(a), len(b)
    if abs(la - lb) > 1:
        return False
    if la == lb:
        # one substitution
        return sum(1 for x, y in zip(a, b) if x != y) == 1
    # one insertion/deletion — make a the shorter
    if la > lb:
        a, b = b, a
        la, lb = lb, la
    i = j = 0
    edited = False
    while i < la and j < lb:
        if a[i] == b[j]:
            i += 1
            j += 1
        else:
            if edited:
                return False
            edited = True
            j += 1
    return True
