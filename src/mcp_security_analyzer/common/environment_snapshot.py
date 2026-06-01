"""Environment snapshot produced by the static analyzer and consumed by the
dynamic analyzer.

The static analyzer inspects the target server (local source tree, or remote
package fetched as a tarball) and produces an ``EnvironmentSnapshot`` that the
dynamic analyzer can use in place of doing its own manifest reads and registry
queries. When no snapshot is supplied, the dynamic side falls back to its
existing discovery logic.

The snapshot intentionally avoids dynamic-side identifiers (sandbox image tag
names, recipe ids, etc.) so the static layer is not coupled to the dynamic
layer's internal naming.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path


class SnapshotOrigin(str, Enum):
    """How the snapshot was obtained."""

    LOCAL_SOURCE = "local-source"
    """User pointed at a directory or file already on the host disk."""

    EXTRACTED_TARBALL = "extracted-tarball"
    """Static analyzer downloaded a remote package and unpacked it to a temp dir."""

    MANIFEST_ONLY = "manifest-only"
    """Only registry metadata was reachable; no source tree was extracted."""

    NONE = "none"
    """Nothing usable was obtained; snapshot is effectively empty."""


class CoverageLevel(str, Enum):
    """How much depth the static analyzer was able to provide."""

    FULL = "full"
    """Source tree available; full scan (manifest + signals) was performed."""

    PARTIAL = "partial"
    """Registry metadata only; no source-tree scans were possible."""

    NONE = "none"
    """No usable information."""


@dataclass(frozen=True)
class EnvironmentSnapshot:
    """Environment information collected by the static analyzer.

    Field semantics mirror the dynamic side's preflight evidence so that the
    dynamic resolver and preflight inspector can use a snapshot as a drop-in
    replacement for their own discovery.
    """

    origin: SnapshotOrigin
    coverage: CoverageLevel

    package_name: str | None = None
    package_version: str | None = None

    # Raw version constraint strings as found in the manifest. The dynamic
    # resolver is responsible for translating these into its own image tags.
    engines_node: str | None = None
    requires_python: str | None = None

    # Same shape as the dynamic preflight evidence: ordered, hashable.
    node_dependencies: tuple[tuple[str, str], ...] = ()
    python_dependencies: tuple[str, ...] = ()
    source_signals: frozenset[str] = field(default_factory=frozenset)

    # Filesystem location of the source tree, if any. For ``LOCAL_SOURCE`` this
    # is the user-supplied directory. For ``EXTRACTED_TARBALL`` this is the
    # temp directory the tarball was unpacked into. The dynamic side may mount
    # this into the sandbox to avoid re-fetching the package at runtime.
    source_tree_path: Path | None = None

    # Manifest paths that were actually read, as a human-readable label
    # (paths joined by comma, or a registry URL string for remote sources).
    # Logged by the dynamic side for traceability.
    manifest_label: str | None = None

    @property
    def has_source_tree(self) -> bool:
        return self.source_tree_path is not None and self.source_tree_path.exists()

    @property
    def is_empty(self) -> bool:
        return (
            self.origin == SnapshotOrigin.NONE
            and not self.node_dependencies
            and not self.python_dependencies
            and not self.source_signals
        )

    def node_dependency_map(self) -> dict[str, str]:
        """Convenience: node dependencies as a dict (name → version constraint)."""
        return dict(self.node_dependencies)


EMPTY_SNAPSHOT = EnvironmentSnapshot(
    origin=SnapshotOrigin.NONE,
    coverage=CoverageLevel.NONE,
)
