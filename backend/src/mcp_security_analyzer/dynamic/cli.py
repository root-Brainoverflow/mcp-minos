"""CLI entry point: ``minos scan`` / ``analyze``."""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import click
import structlog
from rich.console import Console
from rich.table import Table

from mcp_security_analyzer.dynamic.config import AnalysisConfig, ServerConfig, load_config
from mcp_security_analyzer.dynamic.discovery import (
    DiscoveredServer,
    discover_servers,
    select_server,
)
from mcp_security_analyzer.dynamic.models import AnalysisOutput

log = structlog.get_logger()
console = Console(stderr=True)


@click.group()
def main() -> None:
    """MCP Dynamic Analyzer — dynamic security analysis for MCP servers."""
    # Route logs to stderr so stdout carries only command output (e.g. the
    # JSON report). The default structlog logger factory writes to stdout,
    # which would corrupt `--format json`.
    structlog.configure(
        processors=[
            structlog.stdlib.add_log_level,
            structlog.dev.ConsoleRenderer(),
        ],
        wrapper_class=structlog.stdlib.BoundLogger,
        logger_factory=structlog.PrintLoggerFactory(file=sys.stderr),
    )


# ---------------------------------------------------------------------------
# scan
# ---------------------------------------------------------------------------

@main.command()
def discover() -> None:
    """List MCP servers already configured on this machine.

    Scans Claude Desktop, Claude Code, Cursor, and VSCode config files.
    Use the server name shown here with ``scan --target <name>``.
    """
    servers = discover_servers()
    if not servers:
        console.print(
            "[yellow]No MCP servers found in any known config location.[/yellow]\n"
            "Checked: claude-desktop, claude-code, cursor, vscode."
        )
        return
    _print_discovered(servers)


@main.command()
@click.option("--target", default=None, help="Name of a discovered MCP server (see `discover`)")
@click.option("--command", default=None, help="Server launch command (e.g. npx, uvx, python3)")
@click.option("--arg", "args", multiple=True, help="Server argument (repeatable)")
@click.option(
    "--source",
    default=None,
    help="Restrict selection to one source (claude-desktop|claude-code|cursor|vscode)",
)
@click.option("--config", "config_path", type=click.Path(exists=True), default=None)
@click.option("--quick", is_flag=True, help="Quick scan (R1 + R3 + R5 only)")
@click.option("--format", "fmt", type=click.Choice(["json", "summary"]), default="summary")
@click.option("--no-docker", is_flag=True, help="Run server locally without Docker")
@click.option("--timeout", type=int, default=None,
              help="Sandbox scan-budget ceiling in seconds (overrides config; heavy servers need more)")
def scan(
    target: str | None,
    command: str | None,
    args: tuple[str, ...],
    source: str | None,
    config_path: str | None,
    quick: bool,
    fmt: str,
    no_docker: bool,
    timeout: int | None,
) -> None:
    """Run the combined static + dynamic analysis on an MCP server.

    Equivalent to running ``static`` and ``dynamic`` together: the static
    source-tree scanners (manifest security, Semgrep) run before the sandbox,
    and the description / schema scanners run after with the runtime
    ``tools/list`` as additional input. Use ``static`` or ``dynamic`` to run
    each phase on its own.

    Select the target either way:

        minos scan --target chrome-devtools
        minos scan --command npx --arg chrome-devtools-mcp@latest
    """
    if config_path:
        cfg = load_config(config_path)
    elif quick:
        # repo root: cli.py is at src/mcp_security_analyzer/dynamic/cli.py
        cfg = load_config(Path(__file__).parents[3] / "configs" / "quick.yaml")
    else:
        cfg = AnalysisConfig()

    if timeout is not None:
        cfg.sandbox.timeout = timeout

    if target:
        servers = discover_servers()
        if not servers:
            click.echo(
                "Error: no MCP servers found. Run `minos discover` "
                "to see what's available, or pass --command/--arg directly.",
                err=True,
            )
            sys.exit(1)
        try:
            picked = select_server(servers, target, source)
        except ValueError as exc:
            click.echo(f"Error: {exc}", err=True)
            sys.exit(1)
        # Pydantic models are immutable-by-convention here; replace the whole
        # server block with the discovered config so all fields transfer cleanly.
        cfg.server = picked.server
        console.print(
            f"[green]Target:[/green] {picked.name}  "
            f"[dim]({picked.source} — {picked.source_path})[/dim]"
        )
    elif command:
        cfg.server = ServerConfig(command=command, args=list(args))
    else:
        click.echo(
            "Error: provide either --target <name> or --command <cmd>.",
            err=True,
        )
        sys.exit(1)

    # Static phase: collect environment information (local source scan or
    # tarball fetch + scan) so the dynamic side can configure the sandbox
    # correctly on the first attempt instead of relying on the stderr-retry
    # path. Always safe to call — an empty snapshot is returned when nothing
    # can be inspected.
    from mcp_security_analyzer.static.findings_runner import run_static_findings
    from mcp_security_analyzer.static.runner import collect_environment_snapshot

    snapshot, snapshot_cleanup = collect_environment_snapshot(cfg.server)
    console.print(
        f"[green]Static:[/green] origin={snapshot.origin.value} "
        f"coverage={snapshot.coverage.value} "
        f"signals={sorted(snapshot.source_signals) or '[]'}"
    )

    from mcp_security_analyzer.dynamic.orchestrator import run_analysis, build_default_scanners

    drift: list = []
    try:
        # Documented order (docs/static-analysis.md): tarball → static → dynamic.
        # The source-tree scanners (manifest, semgrep) + description/schema audits
        # run on the extracted source BEFORE the sandbox boots. Only the
        # source↔runtime metadata-divergence (rug-pull) check needs the runtime
        # tools/list, so it's deferred until after the dynamic phase below.
        static_report = run_static_findings(snapshot, include_divergence=False)
        _print_static_report(static_report)

        output = asyncio.run(
            run_analysis(
                cfg,
                use_docker=not no_docker,
                scanners=build_default_scanners(cfg),
                environment_snapshot=snapshot,
            ),
        )

        # Runtime-drift check now that the dynamic phase captured tools/list.
        if static_report.source_tools and output.tools:
            from mcp_security_analyzer.static.scanners.metadata_divergence import (
                scan_metadata_divergence,
            )
            drift = list(scan_metadata_divergence(list(static_report.source_tools), output.tools))
    finally:
        # Remove any temp directory the static phase extracted a tarball into.
        snapshot_cleanup()

    static_findings = list(static_report.findings) + drift

    # Unified severity/verdict over the static + dynamic finding pool
    # (docs/severity-verdict-model.md §5 union).
    from mcp_security_analyzer.dynamic.output import verdict as verdict_mod

    unified_verdict = verdict_mod.evaluate(
        list(output.findings) + static_findings,
        coverage_ok=output.metadata.get("tools_tested", 0) > 0,
    )

    # run_analysis only persisted the dynamic findings + dynamic verdict. Merge
    # the static findings and the unified verdict into the session's
    # findings.json so the report (web UI / read API) reflects the full scan.
    _persist_unified(output, static_findings, unified_verdict)

    if fmt == "json":
        import json

        combined = {
            "static": static_report.to_dict(),
            "static_drift": [f.to_dict() for f in drift],
            "dynamic": json.loads(output.model_dump_json()),
            "verdict": unified_verdict.to_dict(),
        }
        click.echo(json.dumps(combined, indent=2, ensure_ascii=False))
    else:
        _print_summary(output)
        _print_verdict(unified_verdict.to_dict(), title="Unified verdict (static + dynamic)")


def _persist_unified(output: "object", static_findings: list, unified_verdict: "object") -> None:
    """Merge static findings + the unified verdict into the session's findings.json.

    ``run_analysis`` already wrote the dynamic findings + dynamic verdict; this
    appends the static findings (tagged ``phase=static``, enriched to the dynamic
    finding shape) and overwrites the verdict with the static+dynamic union so
    the persisted report matches what ``scan`` printed.
    """
    import json
    from datetime import UTC, datetime
    from pathlib import Path
    from uuid import uuid4

    session_dir = Path(output.event_log_path).parent  # type: ignore[attr-defined]
    fj = session_dir / "findings.json"
    try:
        data = json.loads(fj.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return

    now = datetime.now(UTC).isoformat()
    findings = data.get("findings") or []
    by_sev: dict[str, int] = {}
    for f in findings:
        by_sev[f.get("severity")] = by_sev.get(f.get("severity"), 0) + 1
    for finding in static_findings:
        sf = dict(finding.to_dict())
        sf.setdefault("finding_id", f"fnd-{uuid4()}")
        sf.setdefault("detected_at", now)
        sf.setdefault("related_events", [])
        sf.setdefault("reproduction", "")
        sf["phase"] = "static"
        sf["scanner"] = sf.get("scanner") or "semgrep"
        findings.append(sf)
        by_sev[sf.get("severity")] = by_sev.get(sf.get("severity"), 0) + 1

    uv = unified_verdict.to_dict()  # type: ignore[attr-defined]
    data["findings"] = findings
    meta = data.setdefault("metadata", {})
    meta["verdict"] = uv["decision"]
    meta["verdict_detail"] = uv
    meta["by_severity"] = by_sev
    fj.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")


def _print_static_report(report: "object") -> None:
    """Render the static-analysis findings as a rich table."""
    from mcp_security_analyzer.static.findings_runner import StaticReport

    assert isinstance(report, StaticReport)
    console.print(
        f"[green]Static scan:[/green] {len(report.findings)} finding(s), "
        f"{report.tools_analyzed} tool(s) analyzed ({report.tool_source}); "
        f"scanners: {', '.join(report.scanners_run) or 'none'}"
    )
    if not report.findings:
        return

    table = Table(title="Static Findings", show_lines=False)
    table.add_column("risk", style="bold")
    table.add_column("severity")
    table.add_column("conf", justify="right")
    table.add_column("scanner")
    table.add_column("location", overflow="fold")
    table.add_column("title", overflow="fold")
    _sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    for f in sorted(
        report.findings,
        key=lambda x: (_sev_order.get(x.severity.value, 9), x.risk_type.value),
    ):
        table.add_row(
            f.risk_type.value,
            f.severity.value,
            f"{f.confidence:.2f}",
            f.scanner,
            f.location or "",
            f.title,
        )
    console.print(table)


# ---------------------------------------------------------------------------
# static (static-only, no Docker)
# ---------------------------------------------------------------------------

@main.command()
@click.option("--target", default=None, help="Name of a discovered MCP server (see `discover`)")
@click.option("--command", default=None, help="Server launch command (e.g. npx, uvx, python3)")
@click.option("--arg", "args", multiple=True, help="Server argument (repeatable)")
@click.option("--format", "fmt", type=click.Choice(["json", "summary"]), default="summary")
def static(
    target: str | None,
    command: str | None,
    args: tuple[str, ...],
    fmt: str,
) -> None:
    """Run only the source-tree static scanners (no Docker, no server execution).

    Collects the environment snapshot (local source or fetched tarball) and
    runs the scanners that need only the source tree — manifest security and
    Semgrep. Description and schema scanners are skipped here because their
    authoritative input is the runtime tools/list, which only the dynamic
    phase (``scan``) can capture.

    Select the target the same way as `scan`, by discovered name:

        minos static --target browsermcp

    or pass an ad-hoc launch command for a package not in any config:

        minos static --command npx --arg @browsermcp/mcp@latest
    """
    from mcp_security_analyzer.static.findings_runner import run_static_findings
    from mcp_security_analyzer.static.runner import collect_environment_snapshot

    if target:
        servers = discover_servers()
        if not servers:
            click.echo(
                "Error: no MCP servers found. Run `minos discover` to see "
                "what's available, or pass --command/--arg directly.",
                err=True,
            )
            sys.exit(1)
        try:
            picked = select_server(servers, target, None)
        except ValueError as exc:
            click.echo(f"Error: {exc}", err=True)
            sys.exit(1)
        server = picked.server
        console.print(
            f"[green]Target:[/green] {picked.name}  "
            f"[dim]({picked.source} — {picked.source_path})[/dim]"
        )
    elif command:
        server = ServerConfig(command=command, args=list(args))
    else:
        click.echo(
            "Error: provide either --target <name> or --command <cmd>.",
            err=True,
        )
        sys.exit(1)

    snapshot, snapshot_cleanup = collect_environment_snapshot(server)
    console.print(
        f"[green]Static:[/green] origin={snapshot.origin.value} "
        f"coverage={snapshot.coverage.value} "
        f"package={snapshot.package_name or '-'}@{snapshot.package_version or '-'} "
        f"signals={sorted(snapshot.source_signals) or '[]'}"
    )
    try:
        report = run_static_findings(snapshot)
    finally:
        snapshot_cleanup()

    if fmt == "json":
        import json

        click.echo(json.dumps(report.to_dict(), indent=2, ensure_ascii=False))
    else:
        _print_static_report(report)


# ---------------------------------------------------------------------------
# dynamic (dynamic-only, runs the sandbox without static findings)
# ---------------------------------------------------------------------------

@main.command()
@click.option("--target", default=None, help="Name of a discovered MCP server (see `discover`)")
@click.option("--command", default=None, help="Server launch command (e.g. npx, uvx, python3)")
@click.option("--arg", "args", multiple=True, help="Server argument (repeatable)")
@click.option("--config", "config_path", type=click.Path(exists=True), default=None)
@click.option("--quick", is_flag=True, help="Quick scan (R1 + R3 + R5 only)")
@click.option("--format", "fmt", type=click.Choice(["json", "summary"]), default="summary")
@click.option("--no-docker", is_flag=True, help="Run server locally without Docker")
@click.option("--timeout", type=int, default=None,
              help="Sandbox scan-budget ceiling in seconds (overrides config; heavy servers need more)")
def dynamic(
    target: str | None,
    command: str | None,
    args: tuple[str, ...],
    config_path: str | None,
    quick: bool,
    fmt: str,
    no_docker: bool,
    timeout: int | None,
) -> None:
    """Run only the dynamic (sandboxed runtime) analysis — no static scanners.

    Boots the server in a sandbox, drives it with the payload sequencers, and
    runs the dynamic scanners (R1–R6). The environment snapshot is still
    collected so the sandbox can match the server's runtime requirements on
    the first attempt, but no static findings are produced.

    Use ``scan`` for the combined static + dynamic flow.

    Select the target the same way as `static`/`scan`:

        minos dynamic --target browsermcp
        minos dynamic --command npx --arg @browsermcp/mcp@latest
    """
    if config_path:
        cfg = load_config(config_path)
    elif quick:
        cfg = load_config(Path(__file__).parents[3] / "configs" / "quick.yaml")
    else:
        cfg = AnalysisConfig()

    if timeout is not None:
        cfg.sandbox.timeout = timeout

    if target:
        servers = discover_servers()
        if not servers:
            click.echo(
                "Error: no MCP servers found. Run `minos discover` to see "
                "what's available, or pass --command/--arg directly.",
                err=True,
            )
            sys.exit(1)
        try:
            picked = select_server(servers, target, None)
        except ValueError as exc:
            click.echo(f"Error: {exc}", err=True)
            sys.exit(1)
        cfg.server = picked.server
        console.print(
            f"[green]Target:[/green] {picked.name}  "
            f"[dim]({picked.source} — {picked.source_path})[/dim]"
        )
    elif command:
        cfg.server = ServerConfig(command=command, args=list(args))
    else:
        click.echo(
            "Error: provide either --target <name> or --command <cmd>.",
            err=True,
        )
        sys.exit(1)

    # Environment snapshot is collected so the sandbox configures correctly
    # on the first attempt — but the static security scanners are NOT run.
    from mcp_security_analyzer.static.runner import collect_environment_snapshot

    snapshot, snapshot_cleanup = collect_environment_snapshot(cfg.server)
    console.print(
        f"[green]Env:[/green] origin={snapshot.origin.value} "
        f"coverage={snapshot.coverage.value} "
        f"signals={sorted(snapshot.source_signals) or '[]'}"
    )

    from mcp_security_analyzer.dynamic.orchestrator import build_default_scanners, run_analysis

    try:
        output = asyncio.run(
            run_analysis(
                cfg,
                use_docker=not no_docker,
                scanners=build_default_scanners(cfg),
                environment_snapshot=snapshot,
            ),
        )
    finally:
        snapshot_cleanup()

    if fmt == "json":
        click.echo(output.model_dump_json(indent=2))
    else:
        _print_summary(output)


def _print_discovered(servers: list[DiscoveredServer]) -> None:
    """Render discovered servers as a rich table."""
    table = Table(title="Discovered MCP Servers", show_lines=False)
    table.add_column("#", style="dim", justify="right")
    table.add_column("name", style="bold")
    table.add_column("source")
    table.add_column("command", overflow="fold")
    for i, s in enumerate(servers, 1):
        preview = s.server.command
        if s.server.args:
            preview += " " + " ".join(s.server.args[:3])
            if len(s.server.args) > 3:
                preview += " ..."
        table.add_row(str(i), s.name, s.source, preview)
    console.print(table)
    console.print(
        "\n[dim]Run:[/dim] minos scan|static|dynamic --target <name>"
    )


# ---------------------------------------------------------------------------
# analyze (re-analysis)
# ---------------------------------------------------------------------------

@main.command()
@click.option("--session", required=True, type=click.Path(exists=True), help="Session directory")
@click.option("--config", "config_path", type=click.Path(exists=True), default=None)
def analyze(session: str, config_path: str | None) -> None:
    """Re-analyze a previously collected session with new scanners/config."""
    session_dir = Path(session)
    events_file = session_dir / "events.jsonl"
    if not events_file.exists():
        click.echo(f"Error: {events_file} not found", err=True)
        sys.exit(1)

    cfg = load_config(config_path) if config_path else AnalysisConfig()

    from mcp_security_analyzer.dynamic.correlation.event_store import EventStore
    from mcp_security_analyzer.dynamic.models import AnalysisContext
    from mcp_security_analyzer.dynamic.orchestrator import build_default_scanners
    from mcp_security_analyzer.dynamic.output.scorer import Scorer
    from mcp_security_analyzer.dynamic.output.exporter import Exporter
    from mcp_security_analyzer.dynamic.output.reporter import Reporter

    store = EventStore(session_dir)
    reader = store.reader

    async def _run() -> None:
        count = await reader.count()
        console.print(f"Re-analyzing session {session_dir.name} ({count} events)")

        ctx = AnalysisContext(
            session_id=session_dir.name,
            event_reader=reader,
            tools=[],
            config=cfg.model_dump(),
        )
        findings = []
        for scanner in build_default_scanners(cfg):
            scanner_cfg = cfg.model_dump().get("scanners", {}).get(scanner.name, {})
            if not scanner_cfg.get("enabled", True):
                continue
            try:
                result = await scanner.analyze(ctx)
                findings.extend(result)
                console.print(f"  {scanner.name}: {len(result)} findings")
            except Exception as exc:
                console.print(f"  [red]{scanner.name} error: {exc}[/red]")

        scores = Scorer().score(findings)
        exporter = Exporter()
        exporter.print_summary(
            type("_Out", (), {
                "session_id": session_dir.name,
                "findings": findings,
                "metadata": {"tools_tested": 0, "total_events": count},
                "event_log_path": str(store.events_path),
            })(),
            scores,
        )
        Reporter(session_dir).write(
            type("_Out", (), {
                "session_id": session_dir.name,
                "server": {},
                "findings": findings,
                "metadata": {"tools_tested": 0, "total_events": count, "duration_sec": 0},
                "event_log_path": str(store.events_path),
            })(),
            scores,
        )

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# Summary display
# ---------------------------------------------------------------------------

def _print_summary(output: AnalysisOutput) -> None:
    """Print a human-readable summary to stderr using rich."""
    from rich.panel import Panel

    tools_tested = output.metadata.get("tools_tested", 0)
    total_events = output.metadata.get("total_events", 0)

    # ── Pre-scan warnings ────────────────────────────────────────────────────
    if tools_tested == 0:
        console.print(
            Panel(
                "[bold yellow]No tools were discovered on the target server.[/bold yellow]\n\n"
                "Possible causes:\n"
                "  • The backend service required by the server is not running\n"
                "    (e.g. Ghidra HTTP API, database, external API endpoint).\n"
                "  • The server failed to start up correctly — check stderr output above.\n"
                "  • The server intentionally exposes no tools.\n\n"
                "Tip: re-run with [bold]--server-arg[/bold] to pass the backend URL, or\n"
                "     ensure the required service is reachable before scanning.",
                title="[yellow]⚠  0 Tools Discovered[/yellow]",
                border_style="yellow",
            )
        )
    elif total_events < 10:
        console.print(
            Panel(
                f"[yellow]Only {total_events} events were recorded.[/yellow]\n"
                "The server may have exited early or failed to respond to test sequences.\n"
                "Check the structured log output above for sandbox.server_stderr lines.",
                title="[yellow]⚠  Low Event Count[/yellow]",
                border_style="yellow",
            )
        )

    table = Table(title=f"MCP Dynamic Analysis — {output.session_id}", show_lines=True)
    table.add_column("Risk", style="bold")
    table.add_column("Score", justify="right")
    table.add_column("Findings", justify="right")

    risk_names = {
        "R1": "Data Access",
        "R2": "Code Exec",
        "R3": "LLM Manipulation",
        "R4": "Behavior Drift",
        "R5": "Input Validation",
        "R6": "Stability",
    }

    for risk, score in output.dynamic_risk_scores.items():
        count = sum(1 for f in output.findings if f.risk_type.value == risk)
        style = "red" if score >= 0.75 else "yellow" if score >= 0.5 else "green"
        table.add_row(
            f"{risk}: {risk_names.get(risk, '')}",
            f"[{style}]{score:.2f}[/{style}]",
            str(count),
        )

    console.print(table)
    meta = output.metadata
    console.print(
        f"\n  Tools tested: {meta.get('tools_tested', 0)}  |  "
        f"Events: {meta.get('total_events', 0)}  |  "
        f"Findings: {len(output.findings)}",
    )
    console.print(f"  Results: {output.event_log_path}\n")

    _print_verdict(meta.get("verdict"), title="Verdict (dynamic)")


def _print_verdict(v: dict | None, *, title: str = "Verdict") -> None:
    """Render the severity/verdict-model decision (docs/severity-verdict-model.md)."""
    if not v:
        return
    from rich.panel import Panel

    decision = v.get("decision", "?")
    style = {"REJECT": "red", "PASS": "green", "ERROR": "yellow"}.get(decision, "white")
    body = [f"[bold {style}]{decision}[/bold {style}]"]
    if decision == "ERROR":
        body.append(f"검사 불가 (untestable): {v.get('error_message') or v.get('error_code') or ''}")
    reasons = v.get("reasons") or []
    if reasons:
        body.append("사유: " + ", ".join(sorted({r.get("reason") for r in reasons if r.get("reason")})))
    warnings = v.get("warnings") or {}
    if warnings:
        body.append("경고: " + ", ".join(f"{k} ({n})" for k, n in warnings.items()))
    console.print(Panel("\n".join(body), title=f"[bold]{title}[/bold]", border_style=style))


if __name__ == "__main__":
    main()
