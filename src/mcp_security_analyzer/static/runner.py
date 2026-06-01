"""Static-analyzer entry point.

Takes a server config and produces an ``EnvironmentSnapshot`` plus a cleanup
callback. The dynamic analyzer is expected to call the cleanup after it is
done with the snapshot (because the snapshot may point at a temp directory
holding an extracted tarball that the sandbox is mounting).

Branches:
  1. ``server.args`` contains an absolute path that exists on disk →
     LOCAL_SOURCE; analyzer is pointed at the discovered project root.
  2. Command is a node package runner (``npx`` / ``pnpx`` / ``bunx``) and a
     package spec can be extracted from args → fetch and extract the tarball
     from npm, then analyze; EXTRACTED_TARBALL.
  3. Command is ``uvx`` / ``pipx`` and a package spec can be extracted →
     fetch sdist from PyPI, then analyze; EXTRACTED_TARBALL.
  4. None of the above, or any of the above fails → MANIFEST_ONLY (no facts)
     or NONE.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import structlog

from mcp_security_analyzer.common.environment_snapshot import (
    EMPTY_SNAPSHOT,
    CoverageLevel,
    EnvironmentSnapshot,
    SnapshotOrigin,
)
from mcp_security_analyzer.dynamic.config import ServerConfig
from mcp_security_analyzer.static.source_analyzer import (
    SourceTreeFacts,
    analyze_source_tree,
)
from mcp_security_analyzer.static.tarball_fetcher import (
    FetchError,
    fetch_and_extract,
)

log = structlog.get_logger()


_NODE_RUNNERS = {"npx", "pnpx", "bunx"}
_PYTHON_RUNNERS = {"uvx", "pipx"}

_NODE_SKIP_FLAGS = {
    "-y", "--yes", "-q", "--quiet", "--quietly", "--no",
    "--shell-auto-fallback", "--ignore-existing",
}
_NODE_VALUE_FLAGS = {"-p", "--package", "-c", "--call"}
_PYTHON_SKIP_FLAGS = {"--python", "--from", "--with", "--index-url", "--extra-index-url"}

_LOCAL_PROJECT_ASCENT = 5
_LOCAL_MANIFEST_NAMES = ("package.json", "pyproject.toml", "requirements.txt")


CleanupFn = Callable[[], None]


# ─────────────────────────────────────────────────────────────────────────────
# Public entry point
# ─────────────────────────────────────────────────────────────────────────────


def collect_environment_snapshot(
    server: ServerConfig,
) -> tuple[EnvironmentSnapshot, CleanupFn]:
    """Build an environment snapshot for *server*.

    Returns ``(snapshot, cleanup)``. Always returns a snapshot — even if
    nothing useful could be collected, the result will be ``EMPTY_SNAPSHOT``.
    *cleanup* is a no-op when nothing temporary was created, so callers can
    always call it unconditionally.
    """
    # 1. Local source path among args?
    local_root = _find_local_project_root(server)
    if local_root is not None:
        snap = _snapshot_from_local(local_root)
        log.info(
            "static.snapshot.local",
            root=str(local_root),
            coverage=snap.coverage.value,
            signals=sorted(snap.source_signals),
        )
        return snap, _noop

    # 2. Remote node package?
    node_spec = _extract_node_package_spec(server)
    if node_spec is not None:
        return _snapshot_from_remote("npm", node_spec)

    # 3. Remote python package?
    python_spec = _extract_python_package_spec(server)
    if python_spec is not None:
        return _snapshot_from_remote("pypi", python_spec)

    # 4. Nothing usable.
    log.info(
        "static.snapshot.empty",
        command=server.command,
        reason="no local path and no recognised package runner",
    )
    return EMPTY_SNAPSHOT, _noop


# ─────────────────────────────────────────────────────────────────────────────
# Local-source branch
# ─────────────────────────────────────────────────────────────────────────────


def _find_local_project_root(server: ServerConfig) -> Path | None:
    candidates: list[str] = [server.command, *server.args]
    for raw in candidates:
        if not raw:
            continue
        path = Path(raw)
        if not path.is_absolute() or not path.exists():
            continue
        start = path if path.is_dir() else path.parent
        for cand in [start, *list(start.parents)[:_LOCAL_PROJECT_ASCENT]]:
            if any((cand / name).is_file() for name in _LOCAL_MANIFEST_NAMES):
                return cand
    return None


def _snapshot_from_local(root: Path) -> EnvironmentSnapshot:
    facts = analyze_source_tree(root)
    # Source tree is present and was scanned, regardless of what the scan
    # turned up. An empty facts result just means there is nothing to report.
    return _facts_to_snapshot(
        facts,
        origin=SnapshotOrigin.LOCAL_SOURCE,
        coverage=CoverageLevel.FULL,
        source_tree_path=root,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Remote-package branch
# ─────────────────────────────────────────────────────────────────────────────


def _snapshot_from_remote(
    ecosystem: str,
    spec: str,
) -> tuple[EnvironmentSnapshot, CleanupFn]:
    try:
        pkg = fetch_and_extract(ecosystem, spec)  # type: ignore[arg-type]
    except FetchError as exc:
        log.warning(
            "static.snapshot.fetch_failed",
            ecosystem=ecosystem,
            spec=spec,
            error=str(exc),
        )
        # Could not even get the package — degrade to manifest-only / empty.
        return _empty_with_origin(SnapshotOrigin.MANIFEST_ONLY, CoverageLevel.NONE), _noop

    facts = analyze_source_tree(pkg.root_path)

    # Source tree was successfully extracted; coverage is FULL even if the
    # scan happened to find nothing recognisable (e.g. a bundled/minified
    # single-file build).
    snap = _facts_to_snapshot(
        facts,
        origin=SnapshotOrigin.EXTRACTED_TARBALL,
        coverage=CoverageLevel.FULL,
        source_tree_path=pkg.root_path,
        package_name_fallback=pkg.package_name,
        package_version_fallback=pkg.package_version,
        manifest_label_override=pkg.tarball_url,
    )
    log.info(
        "static.snapshot.remote",
        ecosystem=ecosystem,
        spec=spec,
        name=pkg.package_name,
        version=pkg.package_version,
        coverage=snap.coverage.value,
        signals=sorted(snap.source_signals),
    )
    return snap, pkg.cleanup


# ─────────────────────────────────────────────────────────────────────────────
# Package-spec extraction (mirrors the dynamic side's logic)
# ─────────────────────────────────────────────────────────────────────────────


def _extract_node_package_spec(server: ServerConfig) -> str | None:
    if _basename(server.command).lower() not in _NODE_RUNNERS:
        return None
    skip_next = False
    for arg in server.args:
        if skip_next:
            skip_next = False
            continue
        if arg in _NODE_VALUE_FLAGS:
            skip_next = True
            continue
        if arg in _NODE_SKIP_FLAGS or (arg.startswith("-") and arg not in _NODE_SKIP_FLAGS):
            continue
        if arg.startswith((".", "/")) or "\\" in arg:
            return None
        return arg
    return None


def _extract_python_package_spec(server: ServerConfig) -> str | None:
    if _basename(server.command).lower() not in _PYTHON_RUNNERS:
        return None
    skip_next = False
    for arg in server.args:
        if skip_next:
            skip_next = False
            continue
        if arg in _PYTHON_SKIP_FLAGS:
            skip_next = True
            continue
        if arg.startswith("-"):
            continue
        if arg.startswith((".", "/")) or "\\" in arg:
            return None
        return arg
    return None


def _basename(cmd: str) -> str:
    return Path(cmd.replace("\\", "/")).name


# ─────────────────────────────────────────────────────────────────────────────
# Snapshot builders
# ─────────────────────────────────────────────────────────────────────────────


def _facts_to_snapshot(
    facts: SourceTreeFacts,
    *,
    origin: SnapshotOrigin,
    coverage: CoverageLevel,
    source_tree_path: Path | None,
    package_name_fallback: str | None = None,
    package_version_fallback: str | None = None,
    manifest_label_override: str | None = None,
) -> EnvironmentSnapshot:
    label = manifest_label_override or (
        ", ".join(facts.manifest_paths) if facts.manifest_paths else None
    )
    return EnvironmentSnapshot(
        origin=origin,
        coverage=coverage,
        package_name=facts.package_name or package_name_fallback,
        package_version=facts.package_version or package_version_fallback,
        engines_node=facts.engines_node,
        requires_python=facts.requires_python,
        node_dependencies=facts.node_dependencies,
        python_dependencies=facts.python_dependencies,
        source_signals=facts.source_signals,
        source_tree_path=source_tree_path,
        manifest_label=label,
    )


def _empty_with_origin(
    origin: SnapshotOrigin,
    coverage: CoverageLevel,
) -> EnvironmentSnapshot:
    return EnvironmentSnapshot(origin=origin, coverage=coverage)


def _noop() -> None:
    pass
