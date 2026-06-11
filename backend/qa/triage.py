#!/usr/bin/env python3
"""Auto-triage scan findings as true/false positives via headless Claude Code.

Hands each session's findings to ``claude -p`` (headless Claude Code, billed
under your Max login — NOT the metered Anthropic API) and asks it to judge each
as a real issue or a false positive (e.g. package-runtime bootstrap noise),
with a short reason + an optional fix hint. Advisory only — it never edits code.

Usage (from backend/):
    ../.venv/bin/python qa/triage.py <session_id> [<session_id> …]
    ../.venv/bin/python qa/triage.py --latest 3
    ../.venv/bin/python qa/triage.py ses-d81f2965 --model opus
    ../.venv/bin/python qa/triage.py --latest 1 --json     # machine-readable

Pairs with run_corpus.py: re-scan → regression diff → triage the drifted
sessions here → review the suggested fix → apply (by hand / in a Claude session).
"""

from __future__ import annotations

import argparse
import asyncio
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

from mcp_security_analyzer.api import store

_PROMPT = """You are auditing the output of an MCP-server security scanner for FALSE POSITIVES.

How the scanner works: it boots the target MCP server in a sandbox (via npx/uvx/\
python), fuzzes its tools, and flags risks R1 (data access/exfil), R2 (code/\
command execution), R3 (LLM manipulation), R4 (behaviour drift), R5 (input \
validation), R6 (stability). Evidence comes from syscalls (strace), the network \
monitor, planted honeypot/canary files, and fuzz responses.

KNOWN false-positive sources (judge these FP unless evidence shows otherwise):
- The package runtime's OWN bootstrap: npx/npm/node/uv spawning shells (sh -c, \
run-script) or the language interpreter (node script.js, python -m), and reads \
of node_modules / .npm / .npmrc / .cache / site-packages / /etc/hosts.
- A server reading its OWN install/source files, or config the runtime needs.
- An interpreter exec WITHOUT an inline-code flag (node foo.js = launcher; \
node -e "…" = real injection).
TRUE positives: honeypot/canary tripped, egress to internal/cloud-metadata IPs, \
a shell/installer/interpreter-with-inline-code exec correlated to a fuzz payload, \
reads of real secrets (/etc/shadow, ~/.ssh/id_rsa, .aws/credentials) NOT under \
the runtime, fuzz responses showing RCE/SSRF/path-traversal success.

Reply with ONLY a JSON object (no prose, no markdown fences):
{"overall": "false-reject" | "true-reject" | "pass-ok" | "error-untestable" | "uncertain",
 "findings": [{"finding_id": "...", "kind": "...", "judgment": "TP" | "FP" | "UNCERTAIN", "reason": "<=20 words"}],
 "suggestion": "<one-line code/config fix if false positives exist, else null>"}

SESSION TO AUDIT:
"""


def _resolve_sessions(args: argparse.Namespace) -> list[str]:
    if args.latest:
        dirs = sorted(store.results_dir().glob("ses-*"), key=lambda p: p.stat().st_mtime, reverse=True)
        return [d.name for d in dirs[: args.latest]]
    return list(args.sessions)


def _session_payload(session_id: str) -> dict[str, Any] | None:
    detail = store.read_session_detail(session_id)
    if detail is None:
        return None
    s = detail["session"]
    findings = []
    for f in detail.get("findings", []):
        findings.append({
            "finding_id": f.get("finding_id"),
            "kind": f.get("kind"),
            "risk_type": f.get("risk_type"),
            "severity": f.get("severity"),
            "phase": f.get("phase"),
            "tool_name": f.get("tool_name"),
            "title": f.get("title"),
            "location": f.get("location"),
            "description": (f.get("description") or "")[:300],
        })
    return {
        "server": detail.get("server"),
        "verdict": s.get("verdict"),
        "verdict_detail": s.get("verdict_detail"),
        "tools_tested": s.get("tools_tested"),
        "findings": findings[:25],
    }


def _extract_json(text: str) -> dict[str, Any] | None:
    text = text.strip()
    if text.startswith("```"):
        text = text.split("```", 2)[1]
        text = text[4:] if text.lower().startswith("json") else text
    start, end = text.find("{"), text.rfind("}")
    if start == -1 or end == -1:
        return None
    try:
        return json.loads(text[start : end + 1])
    except ValueError:
        return None


def _triage(payload: dict[str, Any], model: str) -> dict[str, Any] | None:
    prompt = _PROMPT + json.dumps(payload, ensure_ascii=False, indent=2)
    try:
        proc = subprocess.run(
            ["claude", "-p", prompt, "--output-format", "json", "--model", model],
            capture_output=True, text=True, timeout=300, check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        return {"_error": f"claude -p failed: {exc}"}
    if proc.returncode != 0:
        return {"_error": f"claude -p rc={proc.returncode}: {proc.stderr[:200]}"}
    try:
        envelope = json.loads(proc.stdout)
        result_text = envelope.get("result", proc.stdout) if isinstance(envelope, dict) else proc.stdout
    except ValueError:
        result_text = proc.stdout
    return _extract_json(result_text) or {"_error": "could not parse triage JSON", "_raw": result_text[:300]}


_ICON = {"FP": "🟡 FP", "TP": "🔴 TP", "UNCERTAIN": "⚪ ?"}
_OVERALL = {
    "false-reject": "⚠️  FALSE REJECT (blocking findings look bogus)",
    "true-reject": "🔴 TRUE REJECT (real blocking issue)",
    "pass-ok": "✅ PASS looks correct",
    "error-untestable": "◷ ERROR / untestable",
    "uncertain": "⚪ UNCERTAIN — needs a human",
}


async def _scan_target(args: argparse.Namespace) -> str | None:
    """Run a fresh scan (same path as the web API / corpus) and return its session id."""
    print(
        f"scanning: {args.command} {' '.join(args.cmd_args)}  "
        f"(profile={args.profile}, docker={'off' if args.no_docker else 'on'})…",
        file=sys.stderr,
    )
    scan_id = await store.start_scan(
        command=args.command,
        args=args.cmd_args,
        profile=args.profile,
        use_docker=not args.no_docker,
        name=args.command,
        timeout=args.scan_timeout,
    )
    # Hard wall-clock cap: a scan should never outlive this. The in-scan
    # timeouts (per-call / sequence / sandbox) occasionally fail to fire on a
    # wedged server or a stuck docker exec, leaving the scan hung indefinitely.
    # When the cap is hit, kill the minos subprocess so the QA loop moves on.
    loop = asyncio.get_running_loop()
    deadline = loop.time() + (args.max_seconds or 900)
    while True:
        entry = store.get_scan(scan_id)
        if entry is None or entry.get("status") != "running":
            break
        if loop.time() > deadline:
            print(f"scan exceeded {args.max_seconds or 900}s wall-clock — killing (likely hung)", file=sys.stderr)
            proc = (entry or {}).get("process")
            if proc is not None and proc.returncode is None:
                try:
                    proc.kill()
                except ProcessLookupError:
                    pass
            break
        await asyncio.sleep(2)
    return (store.get_scan(scan_id) or {}).get("session_id")


def main() -> int:
    ap = argparse.ArgumentParser(description="Auto-triage scan findings (TP/FP) via headless Claude Code")
    ap.add_argument("sessions", nargs="*", help="session ids (full or short ses-…)")
    ap.add_argument("--latest", type=int, metavar="N", help="triage the N most recent sessions")
    ap.add_argument("--model", default="sonnet", help="claude model alias (default sonnet; opus for tougher calls)")
    ap.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    # --scan: one-shot "scan a target, then triage it" — replaces the manual
    # "run minos scan → paste the report → judge" loop entirely.
    ap.add_argument("--scan", action="store_true", help="scan a target first, then triage it")
    ap.add_argument("--command", help="[--scan] launch command (npx/uvx/python3/…)")
    ap.add_argument("--arg", dest="cmd_args", action="append", default=[], help="[--scan] launch arg (repeatable)")
    ap.add_argument("--profile", default="dynamic", help="[--scan] scan|dynamic|quick|static (default dynamic)")
    ap.add_argument("--no-docker", action="store_true", help="[--scan] run the server without Docker")
    ap.add_argument("--scan-timeout", type=int, default=None, help="[--scan] sandbox budget seconds")
    ap.add_argument("--max-seconds", type=int, default=1800, help="[--scan] hard wall-clock cap; kill the scan if it hangs past this. Default 1800 — heavy backend-dependent servers (e.g. mongodb-mcp-server) build a large prebuilt image on first scan before the cap-bounded run.")
    args = ap.parse_args()

    if args.scan:
        if not args.command:
            print("--scan needs --command", file=sys.stderr)
            return 2
        sid = asyncio.run(_scan_target(args))
        if not sid:
            print("scan produced no session to triage", file=sys.stderr)
            return 2
        sessions = [sid]
    else:
        sessions = _resolve_sessions(args)
    if not sessions:
        print("give session id(s), --latest N, or --scan --command …", file=sys.stderr)
        return 2

    out = []
    for sid in sessions:
        payload = _session_payload(sid)
        if payload is None:
            print(f"  {sid}: not found", file=sys.stderr)
            continue
        verdict = payload["verdict"]
        triage = _triage(payload, args.model) or {}
        out.append({"session": sid, "verdict": verdict, "triage": triage})
        if args.json:
            continue
        print(f"\n══ {sid}  ({payload.get('server')})  verdict={verdict} ══")
        if triage.get("_error"):
            print(f"   triage failed: {triage['_error']}")
            continue
        print(f"   {_OVERALL.get(triage.get('overall'), triage.get('overall'))}")
        for fj in triage.get("findings", []):
            print(f"     {_ICON.get(fj.get('judgment'), fj.get('judgment')):8} {fj.get('kind'):24} {fj.get('reason')}")
        if triage.get("suggestion"):
            print(f"   💡 {triage['suggestion']}")

    if args.json:
        print(json.dumps(out, ensure_ascii=False, indent=2))
    # exit 1 if any session judged a false reject (actionable)
    return 1 if any((o["triage"] or {}).get("overall") == "false-reject" for o in out) else 0


if __name__ == "__main__":
    raise SystemExit(main())
