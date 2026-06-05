"""Read a source tree (local checkout or extracted tarball) and extract
manifest metadata plus regex-based source signals.

Input is a single directory. Output is a ``SourceTreeFacts`` value that the
static runner combines with origin info to build the final environment
snapshot.

The extraction logic is intentionally tolerant: any single missing or
malformed file is skipped rather than failing the whole scan, so a half-
packaged tarball still yields whatever can be salvaged.
"""

from __future__ import annotations

import json
import os
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path


# ─────────────────────────────────────────────────────────────────────────────
# Limits — keep the scan bounded on huge source trees
# ─────────────────────────────────────────────────────────────────────────────

_SCAN_FILE_LIMIT = 500
_SCAN_BYTES_LIMIT = 256 * 1024

_SCAN_EXTENSIONS = {
    ".py", ".pyi", ".js", ".jsx", ".mjs", ".cjs",
    ".ts", ".tsx", ".mts", ".cts", ".json", ".toml",
}
_SCAN_SKIP_DIRS = {
    ".git", ".hg", ".svn", ".venv", "venv", "__pycache__",
    "node_modules", "dist", "build", ".next", ".turbo", ".cache",
    ".pytest_cache", ".mypy_cache", ".ruff_cache",
}

_MANIFEST_NAMES = ("package.json", "pyproject.toml", "requirements.txt")


# Source-code regex patterns that emit named signals. These are the same
# signals the dynamic side's recipe matcher looks for in its OR gates
# (chrome-vs-chromium discrimination, etc.). Keeping the set centralised here
# means both sides agree on what counts as a signal.
_SIGNAL_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("playwright.channel.chrome",  re.compile(r"""channel\s*[:=]\s*["']chrome["']""", re.IGNORECASE)),
    ("browser.exec.google-chrome", re.compile(r"""\bgoogle-chrome(?:-stable)?\b""",   re.IGNORECASE)),
    ("browser.path.google-chrome", re.compile(r"""/opt/google/chrome/chrome""",       re.IGNORECASE)),
    ("browser.selenium.chrome",    re.compile(r"""chrome(?:driver|options)\b""",      re.IGNORECASE)),
    ("browser.puppeteer.launch",   re.compile(r"""puppeteer\.launch\b""",             re.IGNORECASE)),
)


# ─────────────────────────────────────────────────────────────────────────────
# Public result type
# ─────────────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class SourceTreeFacts:
    """Manifest-derived metadata + signal scan results for one source tree."""

    package_name: str | None = None
    package_version: str | None = None
    engines_node: str | None = None
    requires_python: str | None = None
    node_dependencies: tuple[tuple[str, str], ...] = ()
    python_dependencies: tuple[str, ...] = ()
    source_signals: frozenset[str] = field(default_factory=frozenset)
    manifest_paths: tuple[str, ...] = ()

    @property
    def is_empty(self) -> bool:
        return not (
            self.node_dependencies
            or self.python_dependencies
            or self.source_signals
            or self.package_name
        )


# ─────────────────────────────────────────────────────────────────────────────
# Public entry point
# ─────────────────────────────────────────────────────────────────────────────


def analyze_source_tree(root: Path) -> SourceTreeFacts:
    """Read manifests and scan source under *root*; return collected facts."""
    if not root.is_dir():
        return SourceTreeFacts()

    manifest_paths: list[str] = []
    package_name: str | None = None
    package_version: str | None = None
    engines_node: str | None = None
    requires_python: str | None = None
    node_deps: dict[str, str] = {}
    python_deps: set[str] = set()

    pkg_json = root / "package.json"
    if pkg_json.is_file():
        data = _load_json(pkg_json)
        if isinstance(data, dict):
            manifest_paths.append(str(pkg_json))
            package_name = package_name or _maybe_str(data.get("name"))
            package_version = package_version or _maybe_str(data.get("version"))
            engines = data.get("engines")
            if isinstance(engines, dict):
                engines_node = _maybe_str(engines.get("node"))
            node_deps.update(_collect_node_dependencies(data))

    pyproject = root / "pyproject.toml"
    if pyproject.is_file():
        data = _load_toml(pyproject)
        if isinstance(data, dict):
            manifest_paths.append(str(pyproject))
            project = data.get("project")
            if isinstance(project, dict):
                package_name = package_name or _maybe_str(project.get("name"))
                package_version = package_version or _maybe_str(project.get("version"))
                requires_python = _maybe_str(project.get("requires-python"))
            python_deps.update(_collect_pyproject_dependencies(data))

    requirements = root / "requirements.txt"
    if requirements.is_file():
        try:
            text = requirements.read_text(encoding="utf-8")
        except OSError:
            text = ""
        if text:
            manifest_paths.append(str(requirements))
            python_deps.update(_parse_requirements_lines(text))

    signals = _scan_source_tree(root)

    return SourceTreeFacts(
        package_name=package_name,
        package_version=package_version,
        engines_node=engines_node,
        requires_python=requires_python,
        node_dependencies=tuple(sorted(node_deps.items())),
        python_dependencies=tuple(sorted(python_deps)),
        source_signals=frozenset(signals),
        manifest_paths=tuple(manifest_paths),
    )


# ─────────────────────────────────────────────────────────────────────────────
# Manifest readers
# ─────────────────────────────────────────────────────────────────────────────


def _load_json(path: Path) -> object:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _load_toml(path: Path) -> object:
    try:
        return tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, tomllib.TOMLDecodeError):
        return None


def _collect_node_dependencies(data: dict) -> dict[str, str]:
    out: dict[str, str] = {}
    for field_name in (
        "dependencies",
        "devDependencies",
        "optionalDependencies",
        "peerDependencies",
    ):
        mapping = data.get(field_name)
        if not isinstance(mapping, dict):
            continue
        for name, version in mapping.items():
            if isinstance(name, str) and isinstance(version, str):
                out[name] = version
    return out


def _collect_pyproject_dependencies(data: dict) -> set[str]:
    out: set[str] = set()

    project = data.get("project")
    if isinstance(project, dict):
        for raw in project.get("dependencies") or []:
            if isinstance(raw, str):
                dep = _normalise_python_requirement(raw)
                if dep:
                    out.add(dep)
        optional = project.get("optional-dependencies") or {}
        if isinstance(optional, dict):
            for group in optional.values():
                if isinstance(group, list):
                    for raw in group:
                        if isinstance(raw, str):
                            dep = _normalise_python_requirement(raw)
                            if dep:
                                out.add(dep)

    groups = data.get("dependency-groups") or {}
    if isinstance(groups, dict):
        for group in groups.values():
            if isinstance(group, list):
                for raw in group:
                    if isinstance(raw, str):
                        dep = _normalise_python_requirement(raw)
                        if dep:
                            out.add(dep)

    tool = data.get("tool") or {}
    if isinstance(tool, dict):
        poetry = tool.get("poetry") or {}
        if isinstance(poetry, dict):
            for name in (poetry.get("dependencies") or {}).keys():
                if isinstance(name, str) and name.lower() != "python":
                    out.add(name.lower().replace("_", "-"))

    return out


def _parse_requirements_lines(raw: str) -> set[str]:
    out: set[str] = set()
    for line in raw.splitlines():
        dep = _normalise_python_requirement(line)
        if dep:
            out.add(dep)
    return out


def _normalise_python_requirement(raw: str) -> str | None:
    line = raw.split("#", 1)[0].split(";", 1)[0].strip()
    if not line or line.startswith("-"):
        return None
    if "@" in line and "://" in line:
        line = line.split("@", 1)[0].strip()
    match = re.match(r"([A-Za-z0-9_.-]+)", line)
    if not match:
        return None
    return match.group(1).lower().replace("_", "-")


# ─────────────────────────────────────────────────────────────────────────────
# Signal scanner
# ─────────────────────────────────────────────────────────────────────────────


def _scan_source_tree(root: Path) -> set[str]:
    signals: set[str] = set()
    scanned = 0
    for current, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in _SCAN_SKIP_DIRS]
        for name in files:
            path = Path(current) / name
            if name not in _MANIFEST_NAMES and path.suffix.lower() not in _SCAN_EXTENSIONS:
                continue
            try:
                if path.stat().st_size > _SCAN_BYTES_LIMIT:
                    continue
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            for signal, pattern in _SIGNAL_PATTERNS:
                if pattern.search(text):
                    signals.add(signal)
            scanned += 1
            if scanned >= _SCAN_FILE_LIMIT:
                return signals
    return signals


# ─────────────────────────────────────────────────────────────────────────────
# Misc
# ─────────────────────────────────────────────────────────────────────────────


def _maybe_str(v: object) -> str | None:
    return v if isinstance(v, str) else None
