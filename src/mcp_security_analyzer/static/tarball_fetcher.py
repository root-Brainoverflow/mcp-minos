"""Fetch a published package from npm or PyPI and unpack it to a temp directory.

The static analyzer uses this so that for remote-package targets (e.g.
``npx @scope/server-foo``) it can still inspect the actual source tree, the
same way it would for a local checkout. The extracted directory may also be
mounted into the dynamic sandbox to avoid re-downloading the package at
runtime.

Pure stdlib (urllib, tarfile, json, tempfile, shutil) — no host ``npm``/``pip``
required. The npm public registry and PyPI JSON API are both stable, public,
unauthenticated for public packages, and serve gzipped tar archives we can
extract directly.
"""

from __future__ import annotations

import json
import shutil
import tarfile
import tempfile
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

import structlog

log = structlog.get_logger()

Ecosystem = Literal["npm", "pypi"]

_NPM_REGISTRY = "https://registry.npmjs.org"
_PYPI_API = "https://pypi.org/pypi"

_NETWORK_TIMEOUT_SEC = 30


class FetchError(Exception):
    """Raised when a tarball cannot be fetched or extracted."""


@dataclass(frozen=True)
class ExtractedPackage:
    """A remote package that has been downloaded and unpacked locally.

    ``root_path`` is the directory the manifest sits in (so callers can read
    ``root_path / "package.json"`` directly). For npm tarballs this is the
    ``package/`` subdirectory inside the archive; for PyPI sdists it is the
    single top-level directory the sdist convention puts at the archive root.

    ``cleanup_dir`` is the temp directory containing ``root_path``; the caller
    should ``shutil.rmtree(cleanup_dir)`` when done, or use the
    ``cleanup()`` method.
    """

    ecosystem: Ecosystem
    package_name: str
    package_version: str
    root_path: Path
    cleanup_dir: Path
    tarball_url: str

    def cleanup(self) -> None:
        shutil.rmtree(self.cleanup_dir, ignore_errors=True)


# ─────────────────────────────────────────────────────────────────────────────
# Public entry point
# ─────────────────────────────────────────────────────────────────────────────


def fetch_and_extract(ecosystem: Ecosystem, package_spec: str) -> ExtractedPackage:
    """Download *package_spec* from *ecosystem* and unpack it to a temp dir.

    *package_spec* is the same string a user would put on the command line:
    ``"@scope/name"``, ``"name@1.2.3"`` for npm; ``"name"``, ``"name==1.2"``
    for PyPI. Version selection follows the registry's own resolution:
    when no version is given we take the registry's "latest" tag (npm) or
    the metadata's ``info.version`` (PyPI). Complex semver ranges
    (``^1.2``, ``>=2,<3``) are not resolved by this module — pass a pinned
    spec if you need exact reproducibility.
    """
    if ecosystem == "npm":
        return _fetch_npm(package_spec)
    if ecosystem == "pypi":
        return _fetch_pypi(package_spec)
    raise FetchError(f"unknown ecosystem: {ecosystem!r}")


# ─────────────────────────────────────────────────────────────────────────────
# npm
# ─────────────────────────────────────────────────────────────────────────────


def _fetch_npm(spec: str) -> ExtractedPackage:
    name, version_hint = _split_npm_spec(spec)
    metadata_url = f"{_NPM_REGISTRY}/{_url_encode_package_name(name)}"
    metadata = _http_get_json(metadata_url)

    dist_tags = metadata.get("dist-tags") or {}
    versions = metadata.get("versions") or {}

    # Resolve the version. The spec's ``@<x>`` part may be:
    #   - a real version number (``1.2.3``) → use directly,
    #   - a dist-tag (``latest``, ``next``, ``beta``) → resolve via dist-tags,
    #   - absent → fall back to the ``latest`` dist-tag.
    # Note ``npm view`` and ``npx`` both treat a bare ``@latest`` as a tag, not
    # a version, so we must resolve tags before indexing into ``versions``.
    if version_hint:
        if version_hint in versions:
            version = version_hint
        else:
            version = _maybe_str(dist_tags.get(version_hint))
            if not version:
                raise FetchError(
                    f"npm version/tag {version_hint!r} not found for {name!r}",
                )
    else:
        version = _maybe_str(dist_tags.get("latest"))
        if not version:
            raise FetchError(f"no version available for npm package {name!r}")

    version_meta = versions.get(version)
    if not isinstance(version_meta, dict):
        raise FetchError(
            f"npm version {version!r} not present in metadata for {name!r}",
        )

    dist = version_meta.get("dist") or {}
    tarball_url = _maybe_str(dist.get("tarball"))
    if not tarball_url:
        raise FetchError(f"no tarball URL for {name}@{version}")

    cleanup_dir = Path(tempfile.mkdtemp(prefix="mcp-static-npm-"))
    archive_path = cleanup_dir / "package.tgz"
    _http_download(tarball_url, archive_path)

    extract_root = cleanup_dir / "extracted"
    extract_root.mkdir()
    _safe_extract_tar(archive_path, extract_root)

    # npm's published tarballs always wrap contents in a ``package/`` directory.
    nested = extract_root / "package"
    root_path = nested if nested.is_dir() else extract_root

    log.info(
        "static.tarball.fetched",
        ecosystem="npm",
        name=name,
        version=version,
        root=str(root_path),
    )

    return ExtractedPackage(
        ecosystem="npm",
        package_name=name,
        package_version=version,
        root_path=root_path,
        cleanup_dir=cleanup_dir,
        tarball_url=tarball_url,
    )


def _split_npm_spec(spec: str) -> tuple[str, str | None]:
    """Split ``name`` / ``name@version`` / ``@scope/name@version`` into parts."""
    s = spec.strip()
    if not s:
        raise FetchError("empty npm spec")
    # Scoped packages start with @ and contain another @ for the version.
    if s.startswith("@"):
        # Skip the leading @ when looking for the version delimiter.
        sep = s.find("@", 1)
        if sep < 0:
            return s, None
        return s[:sep], s[sep + 1 :] or None
    sep = s.find("@")
    if sep < 0:
        return s, None
    return s[:sep], s[sep + 1 :] or None


def _url_encode_package_name(name: str) -> str:
    """``@scope/name`` → ``@scope%2Fname`` for use in registry paths."""
    return urllib.parse.quote(name, safe="@")


# ─────────────────────────────────────────────────────────────────────────────
# PyPI
# ─────────────────────────────────────────────────────────────────────────────


def _fetch_pypi(spec: str) -> ExtractedPackage:
    name = _strip_pypi_version_constraint(spec)
    metadata = _http_get_json(f"{_PYPI_API}/{urllib.parse.quote(name)}/json")

    info = metadata.get("info") or {}
    version = _maybe_str(info.get("version"))
    if not version:
        raise FetchError(f"no version available for PyPI package {name!r}")

    sdist_url = _pick_sdist_url(metadata.get("urls") or [])
    if not sdist_url:
        raise FetchError(
            f"PyPI package {name}=={version} has no source distribution "
            "(wheel-only — cannot do source-level analysis)",
        )

    cleanup_dir = Path(tempfile.mkdtemp(prefix="mcp-static-pypi-"))
    archive_path = cleanup_dir / Path(urllib.parse.urlparse(sdist_url).path).name
    _http_download(sdist_url, archive_path)

    extract_root = cleanup_dir / "extracted"
    extract_root.mkdir()
    _safe_extract_tar(archive_path, extract_root)

    # PyPI sdists by convention unpack into a single top-level directory
    # named ``<name>-<version>/``. Use that when present.
    entries = [p for p in extract_root.iterdir() if p.is_dir()]
    root_path = entries[0] if len(entries) == 1 else extract_root

    log.info(
        "static.tarball.fetched",
        ecosystem="pypi",
        name=info.get("name") or name,
        version=version,
        root=str(root_path),
    )

    return ExtractedPackage(
        ecosystem="pypi",
        package_name=_maybe_str(info.get("name")) or name,
        package_version=version,
        root_path=root_path,
        cleanup_dir=cleanup_dir,
        tarball_url=sdist_url,
    )


def _strip_pypi_version_constraint(spec: str) -> str:
    """Take ``name``, ``name==1.0``, ``name>=1.0,<2.0`` → ``name``."""
    s = spec.strip()
    if not s:
        raise FetchError("empty PyPI spec")
    for delim in ("==", ">=", "<=", "~=", "!=", ">", "<", "[", ";", " "):
        idx = s.find(delim)
        if idx > 0:
            s = s[:idx]
            break
    return s.strip()


def _pick_sdist_url(url_records: list[dict]) -> str | None:
    """Return the source-distribution URL from a PyPI ``urls`` array, or None."""
    for rec in url_records:
        if not isinstance(rec, dict):
            continue
        if rec.get("packagetype") == "sdist":
            url = _maybe_str(rec.get("url"))
            if url:
                return url
    return None


# ─────────────────────────────────────────────────────────────────────────────
# Generic HTTP + tar handling
# ─────────────────────────────────────────────────────────────────────────────


def _http_get_json(url: str) -> dict:
    try:
        with urllib.request.urlopen(url, timeout=_NETWORK_TIMEOUT_SEC) as resp:  # noqa: S310
            data = json.loads(resp.read().decode("utf-8"))
    except Exception as exc:  # noqa: BLE001 — any failure means we degrade
        raise FetchError(f"GET {url} failed: {exc}") from exc
    if not isinstance(data, dict):
        raise FetchError(f"unexpected JSON shape at {url}")
    return data


def _http_download(url: str, dest: Path) -> None:
    try:
        with urllib.request.urlopen(url, timeout=_NETWORK_TIMEOUT_SEC) as resp:  # noqa: S310
            dest.write_bytes(resp.read())
    except Exception as exc:  # noqa: BLE001
        raise FetchError(f"download {url} failed: {exc}") from exc


def _safe_extract_tar(archive: Path, dest: Path) -> None:
    """Extract *archive* into *dest* with traversal protection.

    Skips any member whose normalised path would escape *dest* (defends against
    a malicious tarball with ``../`` entries — a real-world risk for arbitrary
    npm/PyPI packages).
    """
    dest_resolved = dest.resolve()
    try:
        with tarfile.open(archive, mode="r:*") as tf:
            safe_members = []
            for m in tf.getmembers():
                # Strip leading slash; normalise.
                target = (dest_resolved / m.name).resolve()
                try:
                    target.relative_to(dest_resolved)
                except ValueError:
                    log.warning(
                        "static.tarball.skipped_unsafe_entry",
                        archive=str(archive),
                        member=m.name,
                    )
                    continue
                safe_members.append(m)
            tf.extractall(dest, members=safe_members)  # noqa: S202
    except (tarfile.TarError, OSError) as exc:
        raise FetchError(f"extract {archive} failed: {exc}") from exc


def _maybe_str(v: object) -> str | None:
    return v if isinstance(v, str) else None
