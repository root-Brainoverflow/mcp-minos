"""Prerequisite bootstrap planning for MCP server runtime environments.

Two-phase process
─────────────────
1. **Preflight inspection** – ``SourcePreflightInspector`` reads local
   manifests or queries remote registries (host-side ``npm view`` / PyPI JSON
   API) to collect the server's declared dependencies and source signals.

2. **Plan generation** – ``plan_bootstrap()`` passes that evidence to the
   ``RecipeRegistry``, which matches declarative YAML recipes against the
   evidence and returns ordered ``BootstrapAction`` steps.

All prerequisite knowledge lives in ``infrastructure/recipes/builtin.yaml``.
Adding support for a new tool only requires a new recipe entry there.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import shlex
import tomllib
import urllib.request
from dataclasses import dataclass
from pathlib import Path

import structlog

from mcp_security_analyzer.common.environment_snapshot import (
    EnvironmentSnapshot,
    SnapshotOrigin,
)
from mcp_security_analyzer.dynamic.config import ServerConfig
from mcp_security_analyzer.dynamic.infrastructure.recipes import (
    ArgRewrite,
    MatchContext,
    RecipeAction,
    RecipeRegistry,
    ServiceSpec,
)
from mcp_security_analyzer.dynamic.infrastructure.runtime_resolver import ResolvedRuntime

log = structlog.get_logger()

_LOCAL_MANIFEST_NAMES = ("package.json", "pyproject.toml", "requirements.txt")
_MAX_LOCAL_MANIFEST_ASCENT = 5

_NODE_SKIP_FLAGS = {
    "-y", "--yes", "-q", "--quiet", "--quietly", "--no",
    "--shell-auto-fallback", "--ignore-existing",
}
_NODE_VALUE_FLAGS = {"-p", "--package", "-c", "--call"}
_PYTHON_SKIP_FLAGS = {"--python", "--from", "--with", "--index-url", "--extra-index-url"}

_SOURCE_SCAN_FILE_LIMIT = 200
_SOURCE_SCAN_BYTES_LIMIT = 256 * 1024
_SOURCE_SCAN_EXTENSIONS = {
    ".py", ".pyi", ".js", ".jsx", ".mjs", ".cjs",
    ".ts", ".tsx", ".mts", ".cts", ".json", ".toml",
}
_SOURCE_SCAN_SKIP_DIRS = {
    ".git", ".hg", ".svn", ".venv", "venv", "__pycache__",
    "node_modules", "dist", "build", ".next", ".turbo", ".cache",
}
# Source-code patterns that produce named signals used by recipe matching.
_SOURCE_SIGNAL_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("playwright.channel.chrome",   re.compile(r"""channel\s*[:=]\s*["']chrome["']""",        re.IGNORECASE)),
    ("browser.exec.google-chrome",  re.compile(r"""\bgoogle-chrome(?:-stable)?\b""",           re.IGNORECASE)),
    ("browser.path.google-chrome",  re.compile(r"""/opt/google/chrome/chrome""",               re.IGNORECASE)),
    ("browser.selenium.chrome",     re.compile(r"""chrome(?:driver|options)\b""",              re.IGNORECASE)),
    ("browser.puppeteer.launch",    re.compile(r"""puppeteer\.launch\b""",                     re.IGNORECASE)),
)

_REGISTRY = RecipeRegistry()

_PYPI_API_TIMEOUT = 15


# ─────────────────────────────────────────────────────────────────────────────
# Public data classes
# ─────────────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class BootstrapAction:
    """A prerequisite installation step layered onto a base sandbox image.

    ``command_wrapper`` is prepended to the MCP server command at run time —
    used by package-runner pre-install actions to insert a tiny shim that
    stages a pre-built ``node_modules`` into the cwd so ``npx <pkg>`` finds
    the package locally and skips the registry. See
    ``_remote_install_action`` for the rationale (npm 10+ ``npx`` issues a
    manifest probe to ``registry.npmjs.org`` even for globally-installed
    packages, and the sidecar's ``--internal`` network blocks it).
    """

    action_id: str
    description: str
    dockerfile_lines: tuple[str, ...]
    env: tuple[tuple[str, str], ...] = ()
    services: tuple[ServiceSpec, ...] = ()
    arg_rewrites: tuple[ArgRewrite, ...] = ()
    command_wrapper: tuple[str, ...] = ()


@dataclass(frozen=True)
class BootstrapPlan:
    """Ordered bootstrap actions for a specific resolved runtime."""

    actions: tuple[BootstrapAction, ...]
    reason: str

    def image_tag(self, base_image: str) -> str:
        # Only image-mutating steps (Dockerfile lines / env) affect the base
        # image hash. Sidecars and arg rewrites are runtime concerns and
        # would otherwise force a needless image rebuild per recipe revision.
        image_relevant = [a for a in self.actions if a.dockerfile_lines]
        digest = hashlib.sha256(
            "|".join(a.action_id for a in image_relevant).encode(),
        ).hexdigest()[:12]
        return f"{base_image}-bootstrap-{digest}"

    @property
    def services(self) -> tuple[ServiceSpec, ...]:
        out: list[ServiceSpec] = []
        seen: set[str] = set()
        for action in self.actions:
            for svc in action.services:
                if svc.alias in seen:
                    continue
                seen.add(svc.alias)
                out.append(svc)
        return tuple(out)

    @property
    def arg_rewrites(self) -> tuple[ArgRewrite, ...]:
        out: list[ArgRewrite] = []
        for action in self.actions:
            out.extend(action.arg_rewrites)
        return tuple(out)

    @property
    def has_image_changes(self) -> bool:
        return any(a.dockerfile_lines for a in self.actions)

    @property
    def forced_runtime_env(self) -> dict[str, str]:
        """Env vars from sidecar-bearing recipes — must override user values.

        When a recipe declares ``services``, the recipe owns the connection
        endpoint by definition (the sidecar is the *only* legitimate target).
        Letting user-provided env (which may carry production credentials
        from their cursor/claude config) win would defeat the point of the
        sidecar redirect, so we hoist these env vars to highest priority.
        """
        out: dict[str, str] = {}
        for action in self.actions:
            if not action.services:
                continue
            for k, v in action.env:
                out[k] = v
        return out


@dataclass(frozen=True)
class PreflightEvidence:
    """Manifest or package metadata collected before the actual server run."""

    source: str
    manifest_path: str | None = None
    package_name: str | None = None
    package_version: str | None = None
    node_dependencies: tuple[tuple[str, str], ...] = ()
    python_dependencies: tuple[str, ...] = ()
    source_signals: tuple[str, ...] = ()

    def node_dependency_map(self) -> dict[str, str]:
        return dict(self.node_dependencies)


# ─────────────────────────────────────────────────────────────────────────────
# Preflight inspection
# ─────────────────────────────────────────────────────────────────────────────


def _evidence_from_snapshot(snapshot: EnvironmentSnapshot) -> PreflightEvidence | None:
    """Convert a static-analyzer snapshot into the dynamic side's evidence shape.

    Source label mapping:
    - LOCAL_SOURCE → ``"local-manifest"``. This makes the snapshot a drop-in
      replacement for the existing local-disk inspection path, including
      activating ``_local_install_action`` so the manifest's declared deps
      get installed into the sandbox image.
    - EXTRACTED_TARBALL → ``"extracted-tarball:<package_name>"``. A distinct
      label so dynamic-side branches that gate specifically on
      ``"local-manifest"`` do not fire — the package's own preinstall path
      (``_remote_install_action``) is the right install mechanism here.
    - MANIFEST_ONLY / NONE → ``None``; let the dynamic side fall back.
    """
    origin = snapshot.origin
    if origin == SnapshotOrigin.LOCAL_SOURCE:
        source = "local-manifest"
    elif origin == SnapshotOrigin.EXTRACTED_TARBALL:
        source = f"extracted-tarball:{snapshot.package_name or 'unknown'}"
    else:
        return None
    return PreflightEvidence(
        source=source,
        manifest_path=snapshot.manifest_label,
        package_name=snapshot.package_name,
        package_version=snapshot.package_version,
        node_dependencies=snapshot.node_dependencies,
        python_dependencies=snapshot.python_dependencies,
        source_signals=tuple(sorted(snapshot.source_signals)),
    )


class SourcePreflightInspector:
    """Inspect local manifests or remote registry metadata before server start.

    Remote Node.js inspection uses the host-side ``npm view`` command (no
    docker required).  Remote Python inspection queries the PyPI JSON API.
    """

    async def inspect(
        self,
        server: ServerConfig,
        runtime: ResolvedRuntime,  # kept for API compatibility; runtime selection now uses recipe matching
        *,
        network_mode: str = "allowlist",
        snapshot: EnvironmentSnapshot | None = None,
    ) -> PreflightEvidence | None:
        _ = runtime

        # If the static analyzer already collected this information (manifest
        # deps + source signals), use it directly and skip disk reads / network
        # calls entirely. This is how dynamic gets the right environment on
        # the first attempt for remote packages — the static side downloaded
        # and analyzed the tarball, we just consume that result.
        if snapshot is not None and not snapshot.is_empty:
            evidence = _evidence_from_snapshot(snapshot)
            if evidence is not None:
                return evidence

        local = _inspect_local_manifests(server)
        if local is not None:
            return local

        if network_mode == "none":
            return None

        node_spec = _extract_node_package_spec(server)
        if node_spec:
            return await self._inspect_remote_node(node_spec)

        python_spec = _extract_python_package_spec(server)
        if python_spec:
            return await self._inspect_remote_python(python_spec)

        return None

    # ------------------------------------------------------------------
    # Remote Node.js – host-side npm view (no docker)
    # ------------------------------------------------------------------

    async def _inspect_remote_node(self, package_spec: str) -> PreflightEvidence | None:
        try:
            proc = await asyncio.create_subprocess_exec(
                "npm", "view", package_spec, "--json",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=30)
        except (FileNotFoundError, asyncio.TimeoutError) as exc:
            log.debug("bootstrap.preflight.npm_view_unavailable", package_spec=package_spec, exc=str(exc))
            return None

        if proc.returncode != 0:
            log.debug(
                "bootstrap.preflight.npm_view_failed",
                package_spec=package_spec,
                rc=proc.returncode,
                stderr=stderr.decode(errors="replace")[-400:],
            )
            return None

        try:
            data = json.loads(stdout.decode())
        except ValueError:
            log.debug("bootstrap.preflight.npm_view_invalid_json", package_spec=package_spec)
            return None

        if isinstance(data, list):
            data = data[-1] if data else {}
        if not isinstance(data, dict):
            return None

        deps = _collect_node_dependencies(data)
        return PreflightEvidence(
            source=f"npm-view:{package_spec}",
            manifest_path="npm registry (package.json metadata)",
            package_name=_maybe_str(data.get("name")),
            package_version=_maybe_str(data.get("version")),
            node_dependencies=tuple(sorted(deps.items())),
        )

    # ------------------------------------------------------------------
    # Remote Python – PyPI JSON API (no docker)
    # ------------------------------------------------------------------

    async def _inspect_remote_python(self, package_spec: str) -> PreflightEvidence | None:
        pkg_name = _python_spec_to_name(package_spec)
        if not pkg_name:
            return None

        url = f"https://pypi.org/pypi/{pkg_name}/json"
        try:
            loop = asyncio.get_event_loop()
            data = await asyncio.wait_for(
                loop.run_in_executor(None, _fetch_json_url, url),
                timeout=_PYPI_API_TIMEOUT,
            )
        except Exception as exc:
            log.debug("bootstrap.preflight.pypi_api_failed", pkg_name=pkg_name, exc=str(exc))
            return None

        if not isinstance(data, dict):
            return None

        info = data.get("info") or {}
        raw_deps: list[str] = info.get("requires_dist") or []
        deps = tuple(
            sorted(
                {_normalise_python_requirement(r) for r in raw_deps} - {None}  # type: ignore[arg-type]
            )
        )
        return PreflightEvidence(
            source=f"pypi-api:{package_spec}",
            manifest_path="PyPI package metadata",
            package_name=_maybe_str(info.get("name")),
            package_version=_maybe_str(info.get("version")),
            python_dependencies=deps,
        )


# ─────────────────────────────────────────────────────────────────────────────
# Public API – plan generation
# ─────────────────────────────────────────────────────────────────────────────


def _local_install_action(evidence: PreflightEvidence | None) -> BootstrapAction | None:
    """Install a *local* server's declared dependencies into the sandbox image.

    A local server (``command`` is a path, e.g. ``.../my-server/.venv/bin/python
    server.py``) is launched inside the container with the *container's*
    interpreter — a host venv is meaningless there — so the deps it declares in
    its own ``requirements.txt`` / ``pyproject.toml`` / ``package.json`` must be
    installed into the image, or its tool bodies fail with ``ModuleNotFoundError``
    and R1/R2 coverage is effectively void. This is the generic counterpart to
    the per-server recipes in ``builtin.yaml``: it fires for *any* server whose
    preflight evidence came from a local manifest, not just the named ones.

    Failures are tolerated (``|| true``) — one bad spec (a git/local-path
    requirement, a conflicting pin) shouldn't sink the whole image build; the
    rest still installs, and an unmet dep simply surfaces as the server's own
    import error, which is the truthful signal anyway.
    """
    if evidence is None or evidence.source != "local-manifest":
        return None

    lines: list[str] = []
    env: list[tuple[str, str]] = []

    if evidence.python_dependencies:
        specs = " ".join(shlex.quote(d) for d in evidence.python_dependencies)
        lines.append(f"RUN python3 -m pip install --no-cache-dir {specs} || true")

    if evidence.node_dependencies:
        # npm version ranges in package.json (``^1.2``, git URLs, ``workspace:*``,
        # …) don't all translate to clean install specs; install by bare name
        # (latest), which is plenty for a security scan, and expose the global
        # module dir so a flat ``node server.js`` can ``require()`` them.
        names = " ".join(shlex.quote(name) for name, _ in evidence.node_dependencies)
        lines.append(f"RUN npm install -g {names} || true")
        env.append(("NODE_PATH", "/usr/local/lib/node_modules"))

    if not lines:
        return None

    digest = hashlib.sha256(
        repr((evidence.python_dependencies, evidence.node_dependencies)).encode(),
    ).hexdigest()[:12]
    return BootstrapAction(
        action_id=f"local-deps-{digest}",
        description="install local server dependencies declared in its manifest",
        dockerfile_lines=tuple(lines),
        env=tuple(env),
    )


# stderr substrings that mean "the server tried to fetch from a package
# registry and DNS / network refused". Matched case-insensitively. Covers
# both npm (EAI_AGAIN / registry.npmjs.org) and pip (pypi.org / glibc DNS
# error strings). Kept deliberately small — broader patterns risk false
# positives that would force unrelated rebuilds.
_REGISTRY_FETCH_FAILURE_TOKENS: tuple[str, ...] = (
    "registry.npmjs.org",
    "pypi.org",
    "eai_again",
    "getaddrinfo",
    "temporary failure in name resolution",
    "name or service not known",
)


def _is_registry_fetch_failure(stderr_snippet: str | None) -> bool:
    if not stderr_snippet:
        return False
    lowered = stderr_snippet.lower()
    return any(token in lowered for token in _REGISTRY_FETCH_FAILURE_TOKENS)


def _remote_install_action(
    server: ServerConfig,
    matched: list[RecipeAction],
    stderr_snippet: str | None = None,
) -> BootstrapAction | None:
    """Bake a package-runner server's own package into the sandbox image.

    A server launched as ``npx <pkg>`` / ``uvx <pkg>`` fetches its package from
    the registry on first run. That is fine on a normal bridged network, but
    the moment a matched recipe pulls in a sidecar backend the MCP server is
    moved onto an ``--internal`` docker network (see
    ``SandboxSession._create_sidecar_network``) with no route to the host or
    the internet. The runtime ``npx`` fetch then dies with ``getaddrinfo
    EAI_AGAIN`` and the server never starts — the whole scan crash-loops.

    Two gates fire this step:

    * **Proactive** — a matched recipe carries a sidecar, so we *know* the
      runtime network will be ``--internal`` and pre-install up front. This is
      the generic counterpart to the per-server ``*-install`` recipes in
      ``builtin.yaml`` (postgres shipped one; redis/mysql/mongodb did not —
      the original bug this closes).
    * **Reactive** — ``stderr_snippet`` from a failed first spawn shows a
      registry DNS/network error. This fires on the retry path
      (``Sandbox._retry_bootstrap_from_stderr``) and catches cases the
      proactive gate misses: ``network.mode=none``, in-process wrapper scripts
      that shell out to ``npx`` for a sub-tool, etc. Action ID is stable, so
      if proactive already installed the package the retry's
      ``action_id not in current_ids`` dedup skips it cleanly.

    Returns ``None`` when neither gate fires, when the command is not a
    recognised package runner, or when a matched recipe already installs the
    same package (so we never lay down a duplicate layer).
    """
    needs_offline_install = (
        any(action.services for action in matched)
        or _is_registry_fetch_failure(stderr_snippet)
    )
    if not needs_offline_install:
        return None

    node_spec = _extract_node_package_spec(server)
    python_spec = _extract_python_package_spec(server)
    spec = node_spec or python_spec
    if spec is None:
        return None

    # A per-server recipe (e.g. postgres-mcp-node-install) may already install
    # this exact package — don't stack a redundant RUN layer on top of it.
    if any(spec in line for action in matched for line in action.dockerfile_lines):
        return None

    quoted = shlex.quote(spec)
    env_pairs: tuple[tuple[str, str], ...] = ()
    command_wrapper: tuple[str, ...] = ()
    if node_spec is not None:
        # Plain ``npm install -g`` is not enough and neither is sharing the
        # npm cache + ``NPM_CONFIG_PREFER_OFFLINE``: empirically (npm 10 on
        # node:22-bookworm-slim) ``npx <pkg>`` *still* issues a manifest probe
        # to ``registry.npmjs.org`` for globally-installed scoped packages,
        # going around the cache. That probe is exactly what dies with
        # EAI_AGAIN on the sidecar's ``--internal`` network.
        #
        # What does work: putting the package in the *cwd's* ``node_modules``
        # tree so npx's local-resolution path matches and the manifest probe
        # never happens. The cwd is a tmpfs at ``/tmp`` (so it starts empty
        # every container start), so we stage the install in
        # ``/opt/mcp-prebuilt`` at image-build time and use a tiny entrypoint
        # shim to ``cp -a`` it into cwd before the user's command runs. The
        # shim is wired in via ``command_wrapper`` (see ``Sandbox._build_docker
        # _cmd``) so npx's argv stays untouched.
        dockerfile_lines: tuple[str, ...] = (
            "USER root",
            (
                "RUN mkdir -p /opt/mcp-prebuilt "
                "&& cd /opt/mcp-prebuilt "
                "&& printf '%s' "
                "'{\"name\":\"mcp-prebuilt\",\"version\":\"0.0.0\",\"private\":true}' "
                "> package.json "
                f"&& npm install --no-audit --no-fund --no-package-lock {quoted} "
                "&& chmod -R a+rX /opt/mcp-prebuilt"
            ),
            # Heredoc-free shim emit so this stays a single Dockerfile RUN.
            # The shim is best-effort: ``cp -a`` failures (e.g. a partial
            # earlier copy leaving entries in place) are tolerated so the
            # server still exec's — if the copy genuinely fails, npx will
            # surface the original registry error, which is the truthful
            # signal anyway.
            (
                "RUN { printf '%s\\n' "
                "'#!/bin/sh' "
                "'if [ -d /opt/mcp-prebuilt ] && [ ! -e ./node_modules ]; then' "
                "'    cp -a /opt/mcp-prebuilt/. . 2>/dev/null || true' "
                "'fi' "
                "'exec \"$@\"' "
                "; } > /usr/local/bin/mcp-prebuilt-shim "
                "&& chmod a+rx /usr/local/bin/mcp-prebuilt-shim"
            ),
            "USER user",
        )
        # Belt-and-suspenders: even though the local resolution should skip
        # the registry, set PREFER_OFFLINE so any *secondary* npm/npx call
        # the package might make (transitive scripts, etc.) also avoids the
        # registry on the --internal network.
        env_pairs = (("NPM_CONFIG_PREFER_OFFLINE", "true"),)
        command_wrapper = ("/usr/local/bin/mcp-prebuilt-shim",)
        registry = "npm"
    else:
        # NOTE: this covers ``uvx <pkg>`` / ``pipx <pkg>`` invocations whose
        # spec _extract_python_package_spec returns; both create their own
        # ephemeral venv and would re-fetch from PyPI even when the system
        # interpreter has the package installed. A fully offline-safe python
        # branch needs ``uv tool install`` / ``pipx install`` + a shared uv /
        # pipx home — left as a follow-up since the reported crash is npm.
        dockerfile_lines = (
            "USER root",
            f"RUN pip install --no-cache-dir {quoted}",
            "USER user",
        )
        registry = "PyPI"

    # Hash the *recipe* (dockerfile + env + wrapper), not just the spec, so
    # any future tweak to the install pattern auto-invalidates a previously-
    # built bootstrap image rather than silently reusing a stale broken layer.
    recipe_payload = repr((spec, dockerfile_lines, env_pairs, command_wrapper))
    digest = hashlib.sha256(recipe_payload.encode()).hexdigest()[:12]
    return BootstrapAction(
        action_id=f"remote-install-{digest}",
        description=(
            f"pre-install {registry} package '{spec}' so the sidecar-isolated "
            "server need not reach the registry at run time"
        ),
        dockerfile_lines=dockerfile_lines,
        env=env_pairs,
        command_wrapper=command_wrapper,
    )


def plan_bootstrap(
    server: ServerConfig,
    runtime: ResolvedRuntime,
    *,
    evidence: PreflightEvidence | None = None,
    stderr_snippet: str | None = None,
) -> BootstrapPlan | None:
    """Infer prerequisite bootstrap actions for a server/runtime pair."""
    ctx = _build_match_context(server, runtime, evidence, stderr_snippet)
    matched = _REGISTRY.match(ctx)

    actions: list[BootstrapAction] = [
        BootstrapAction(
            action_id=a.action_id,
            description=a.description,
            dockerfile_lines=_pin_playwright_version(a.action_id, a.dockerfile_lines, evidence),
            env=a.env,
            services=a.services,
            arg_rewrites=a.arg_rewrites,
        )
        for a in matched
    ]
    # Generic local-server dependency install — runs after any matched recipe
    # (recipes may lay down system prerequisites the deps build against).
    local_action = _local_install_action(evidence)
    if local_action is not None:
        actions.append(local_action)

    # Generic remote package-runner install — a sidecar-bound npx/uvx server
    # must have its package baked in before the --internal network cuts off
    # the registry. Also fires reactively when ``stderr_snippet`` shows a
    # registry DNS/network failure, so the retry path
    # (``Sandbox._retry_bootstrap_from_stderr``) can recover servers the
    # proactive gate missed. Passed the matched recipes so it can dedup
    # against any per-server install recipe that already covers the package.
    remote_action = _remote_install_action(server, matched, stderr_snippet)
    if remote_action is not None:
        actions.append(remote_action)

    if not actions:
        return None
    reasons = [a.description for a in matched]
    if local_action is not None:
        reasons.append(local_action.description)
    if remote_action is not None:
        reasons.append(remote_action.description)
    return BootstrapPlan(actions=tuple(actions), reason=", ".join(reasons))


def render_bootstrap_dockerfile(base_image: str, plan: BootstrapPlan) -> str:
    """Render a Dockerfile that extends *base_image* with *plan* actions."""
    lines = [f"FROM {base_image}"]
    seen_env: dict[str, str] = {}
    for action in plan.actions:
        lines.extend(action.dockerfile_lines)
        for key, value in action.env:
            seen_env[key] = value
    for key, value in seen_env.items():
        lines.append(f"ENV {key}={value}")
    lines.append("")
    return "\n".join(lines)


def merged_bootstrap_env(plan: BootstrapPlan | None) -> dict[str, str]:
    """Return env vars implied by the bootstrap plan."""
    if plan is None:
        return {}
    env: dict[str, str] = {}
    for action in plan.actions:
        for key, value in action.env:
            env[key] = value
    return env


# ─────────────────────────────────────────────────────────────────────────────
# Local manifest inspection
# ─────────────────────────────────────────────────────────────────────────────


def _inspect_local_manifests(server: ServerConfig) -> PreflightEvidence | None:
    root = _find_local_project_root(server)
    if root is None:
        return None

    manifest_paths: list[str] = []
    package_name: str | None = None
    package_version: str | None = None
    node_dependencies: dict[str, str] = {}
    python_dependencies: set[str] = set()
    source_signals = _scan_source_tree(root)

    package_json = root / "package.json"
    if package_json.exists():
        try:
            data = json.loads(package_json.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            data = {}
        if isinstance(data, dict):
            manifest_paths.append(str(package_json))
            package_name = package_name or _maybe_str(data.get("name"))
            package_version = package_version or _maybe_str(data.get("version"))
            node_dependencies.update(_collect_node_dependencies(data))

    pyproject = root / "pyproject.toml"
    if pyproject.exists():
        try:
            data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
        except (OSError, ValueError, tomllib.TOMLDecodeError):
            data = {}
        if isinstance(data, dict):
            manifest_paths.append(str(pyproject))
            project = data.get("project") or {}
            if isinstance(project, dict):
                package_name = package_name or _maybe_str(project.get("name"))
                package_version = package_version or _maybe_str(project.get("version"))
            python_dependencies.update(_collect_pyproject_dependencies(data))

    requirements = root / "requirements.txt"
    if requirements.exists():
        try:
            manifest_paths.append(str(requirements))
            python_dependencies.update(
                _parse_requirements_lines(requirements.read_text(encoding="utf-8")),
            )
        except OSError:
            pass

    if not node_dependencies and not python_dependencies and not source_signals:
        return None

    return PreflightEvidence(
        source="local-manifest",
        manifest_path=", ".join(manifest_paths) or str(root),
        package_name=package_name,
        package_version=package_version,
        node_dependencies=tuple(sorted(node_dependencies.items())),
        python_dependencies=tuple(sorted(python_dependencies)),
        source_signals=tuple(sorted(source_signals)),
    )


def _find_local_project_root(server: ServerConfig) -> Path | None:
    for raw in (server.command, *server.args):
        path = Path(raw)
        if not path.is_absolute() or not path.exists():
            continue
        start = path if path.is_dir() else path.parent
        for candidate in [start, *list(start.parents)[:_MAX_LOCAL_MANIFEST_ASCENT]]:
            if any((candidate / name).exists() for name in _LOCAL_MANIFEST_NAMES):
                return candidate
    return None


def _scan_source_tree(root: Path) -> set[str]:
    signals: set[str] = set()
    scanned = 0
    for current, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in _SOURCE_SCAN_SKIP_DIRS]
        for name in files:
            path = Path(current) / name
            if name not in _LOCAL_MANIFEST_NAMES and path.suffix.lower() not in _SOURCE_SCAN_EXTENSIONS:
                continue
            try:
                if path.stat().st_size > _SOURCE_SCAN_BYTES_LIMIT:
                    continue
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            for signal, pattern in _SOURCE_SIGNAL_PATTERNS:
                if pattern.search(text):
                    signals.add(signal)
            scanned += 1
            if scanned >= _SOURCE_SCAN_FILE_LIMIT:
                return signals
    return signals


# ─────────────────────────────────────────────────────────────────────────────
# Recipe matching context builder
# ─────────────────────────────────────────────────────────────────────────────


def _build_match_context(
    server: ServerConfig,
    runtime: ResolvedRuntime,
    evidence: PreflightEvidence | None,
    stderr_snippet: str | None,
) -> MatchContext:
    node_deps: frozenset[str] = frozenset()
    python_deps: frozenset[str] = frozenset()
    source_signals: frozenset[str] = frozenset()
    package_name = ""

    if evidence is not None:
        node_deps = frozenset(evidence.node_dependency_map().keys())
        python_deps = frozenset(evidence.python_dependencies)
        source_signals = frozenset(evidence.source_signals)
        package_name = evidence.package_name or ""

    identity_tokens = tuple(
        t.lower() for t in (server.command, *server.args) if t
    )

    return MatchContext(
        runtime_image=runtime.image,
        node_deps=node_deps,
        python_deps=python_deps,
        source_signals=source_signals,
        identity_tokens=identity_tokens,
        stderr_snippet=(stderr_snippet or "").lower(),
        package_name=package_name.lower(),
    )


# ─────────────────────────────────────────────────────────────────────────────
# Dependency collection helpers
# ─────────────────────────────────────────────────────────────────────────────


def _collect_node_dependencies(data: dict[str, object]) -> dict[str, str]:
    deps: dict[str, str] = {}
    for field in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        mapping = data.get(field)
        if not isinstance(mapping, dict):
            continue
        for name, version in mapping.items():
            if isinstance(name, str) and isinstance(version, str):
                deps[name] = version
    return deps


def _collect_pyproject_dependencies(data: dict[str, object]) -> set[str]:
    deps: set[str] = set()
    project = data.get("project")
    if isinstance(project, dict):
        for raw in project.get("dependencies") or []:
            if isinstance(raw, str):
                dep = _normalise_python_requirement(raw)
                if dep:
                    deps.add(dep)
        optional = project.get("optional-dependencies") or {}
        if isinstance(optional, dict):
            for group in optional.values():
                if isinstance(group, list):
                    for raw in group:
                        if isinstance(raw, str):
                            dep = _normalise_python_requirement(raw)
                            if dep:
                                deps.add(dep)
    groups = data.get("dependency-groups") or {}
    if isinstance(groups, dict):
        for group in groups.values():
            if isinstance(group, list):
                for raw in group:
                    if isinstance(raw, str):
                        dep = _normalise_python_requirement(raw)
                        if dep:
                            deps.add(dep)
    tool = data.get("tool") or {}
    if isinstance(tool, dict):
        poetry = tool.get("poetry") or {}
        if isinstance(poetry, dict):
            for name in (poetry.get("dependencies") or {}).keys():
                if isinstance(name, str) and name.lower() != "python":
                    deps.add(name.lower().replace("_", "-"))
    return deps


def _parse_requirements_lines(raw: str) -> set[str]:
    deps: set[str] = set()
    for line in raw.splitlines():
        dep = _normalise_python_requirement(line)
        if dep:
            deps.add(dep)
    return deps


# ─────────────────────────────────────────────────────────────────────────────
# Package spec extraction helpers
# ─────────────────────────────────────────────────────────────────────────────


def _extract_node_package_spec(server: ServerConfig) -> str | None:
    command = _basename(server.command).lower()
    if command not in {"npx", "pnpx", "bunx"}:
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
    command = _basename(server.command).lower()
    if command not in {"uvx", "pipx"}:
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


# ─────────────────────────────────────────────────────────────────────────────
# Version pinning post-processor
# ─────────────────────────────────────────────────────────────────────────────

_PLAYWRIGHT_NODE_PACKAGES = ("playwright", "@playwright/test", "playwright-core")


def _pin_playwright_version(
    action_id: str,
    lines: tuple[str, ...],
    evidence: PreflightEvidence | None,
) -> tuple[str, ...]:
    """Substitute a pinned version into Playwright install commands when available."""
    if evidence is None:
        return lines
    if action_id.startswith("playwright-node"):
        node_deps = evidence.node_dependency_map()
        version: str | None = None
        for pkg in _PLAYWRIGHT_NODE_PACKAGES:
            if pkg in node_deps:
                version = _extract_semver(node_deps[pkg])
                break
        if version:
            return tuple(
                line.replace("npx -y playwright install", f"npx -y playwright@{version} install")
                for line in lines
            )
    elif action_id.startswith("playwright-python"):
        version = _extract_semver(evidence.package_version)
        if version:
            return tuple(
                line.replace(
                    "pip install --no-cache-dir playwright",
                    f"pip install --no-cache-dir playwright=={version}",
                )
                for line in lines
            )
    return lines


def _extract_semver(raw: str | None) -> str | None:
    if not raw:
        return None
    match = re.search(r"(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)", raw)
    return match.group(1) if match else None


# ─────────────────────────────────────────────────────────────────────────────
# Misc helpers
# ─────────────────────────────────────────────────────────────────────────────


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


def _python_spec_to_name(spec: str) -> str | None:
    """Extract bare package name from a pip/uvx spec (strips version constraints)."""
    return _normalise_python_requirement(spec)


def _fetch_json_url(url: str) -> object:
    """Blocking HTTP GET → parsed JSON. Run in an executor."""
    with urllib.request.urlopen(url, timeout=_PYPI_API_TIMEOUT) as resp:  # noqa: S310
        return json.loads(resp.read().decode())


def _maybe_str(value: object) -> str | None:
    return value if isinstance(value, str) else None


def _basename(cmd: str) -> str:
    return Path(cmd.replace("\\", "/")).name
