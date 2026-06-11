#!/usr/bin/env python3
"""QA golden-regression harness for the MCP-Minos scan pipeline.

Runs real scans over the servers in ``corpus.yaml`` (via the SAME path the web
API uses — ``store.start_scan`` → subprocess → deterministic session
attribution), compares each verdict + blocking-reason set against the recorded
golden, and prints only the drift. This automates the manual
"scan → eyeball result → fix → re-scan" loop into a repeatable regression check.

Usage (from backend/):
    ../.venv/bin/python qa/run_corpus.py            # check vs golden; exit 1 on drift
    ../.venv/bin/python qa/run_corpus.py --update    # record current results as golden
    ../.venv/bin/python qa/run_corpus.py --filter context7
    ../.venv/bin/python qa/run_corpus.py --no-docker --jobs 2
    ../.venv/bin/python qa/run_corpus.py --list

Real scans are slow (Docker + npm download + fuzzing) and need network, so this
is a manual/CI-nightly check, not a unit test.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
import time
from pathlib import Path
from typing import Any

import yaml

from mcp_security_analyzer.api import store

CORPUS = Path(__file__).parent / "corpus.yaml"
_HEADER = CORPUS.read_text(encoding="utf-8").split("cases:")[0] if CORPUS.exists() else ""


async def _run_case(case: dict[str, Any], *, docker_override: bool | None, sem: asyncio.Semaphore) -> dict[str, Any]:
    async with sem:
        t0 = time.monotonic()
        use_docker = case.get("docker", True) if docker_override is None else docker_override
        try:
            scan_id = await store.start_scan(
                command=case.get("command"),
                args=case.get("args") or [],
                profile=case.get("profile", "dynamic"),
                use_docker=use_docker,
                name=case.get("name"),
                timeout=case.get("timeout"),
            )
        except Exception as exc:  # noqa: BLE001
            return {"name": case.get("name"), "verdict": "SCANFAIL", "reasons": [],
                    "max_severity": None, "session": None, "secs": 0, "error": str(exc)}

        while True:
            entry = store.get_scan(scan_id)
            if entry is None or entry.get("status") != "running":
                break
            await asyncio.sleep(2)

        entry = store.get_scan(scan_id) or {}
        sid = entry.get("session_id")
        verdict, reasons, max_sev = "ERROR", [], None
        if sid:
            detail = store.read_session_detail(sid)
            if detail:
                s = detail["session"]
                verdict = s.get("verdict") or "ERROR"
                vd = s.get("verdict_detail") or {}
                # Golden contract (corpus.yaml): `reasons` is the sorted set of
                # blocking finding KINDS, not the §8.5 reason taxonomy strings.
                reasons = sorted({r.get("kind") for r in vd.get("reasons", []) if r.get("kind")})
                max_sev = vd.get("max_residual_severity")
        return {"name": case.get("name"), "verdict": verdict, "reasons": reasons,
                "max_severity": max_sev, "session": sid, "secs": round(time.monotonic() - t0, 1)}


def _compare(case: dict[str, Any], actual: dict[str, Any]) -> tuple[str, list[str]]:
    """Return (status, diffs). status ∈ NEW (uncalibrated) | PASS | FAIL."""
    exp = case.get("expect")
    if not exp:
        return "NEW", []
    diffs: list[str] = []
    if actual["verdict"] != exp.get("verdict"):
        diffs.append(f"verdict {exp.get('verdict')} → {actual['verdict']}")
    if "reasons" in exp and sorted(exp.get("reasons") or []) != actual["reasons"]:
        diffs.append(f"reasons {sorted(exp.get('reasons') or [])} → {actual['reasons']}")
    return ("PASS" if not diffs else "FAIL"), diffs


async def _run_all(cases: list[dict[str, Any]], docker_override: bool | None, jobs: int) -> list[dict[str, Any]]:
    sem = asyncio.Semaphore(max(1, jobs))
    return await asyncio.gather(*[_run_case(c, docker_override=docker_override, sem=sem) for c in cases])


def main() -> int:
    ap = argparse.ArgumentParser(description="MCP-Minos QA golden-regression runner")
    ap.add_argument("--filter", help="only run cases whose name contains this substring")
    ap.add_argument("--update", action="store_true", help="record current results into corpus.yaml as the golden expect")
    ap.add_argument("--no-docker", action="store_true", help="force --no-docker for every case")
    ap.add_argument("--jobs", type=int, default=1, help="concurrent scans (default 1; the backend is concurrency-safe)")
    ap.add_argument("--list", action="store_true", help="list cases and their golden verdict, then exit")
    args = ap.parse_args()

    data = yaml.safe_load(CORPUS.read_text(encoding="utf-8")) or {}
    all_cases = data.get("cases") or []
    cases = [c for c in all_cases if not args.filter or args.filter in (c.get("name") or "")]

    if args.list:
        for c in cases:
            print(f"  {c.get('name'):28} {(c.get('expect') or {}).get('verdict', '(uncalibrated)')}")
        return 0
    if not cases:
        print("no cases match", file=sys.stderr)
        return 2

    docker_override = False if args.no_docker else None
    print(f"running {len(cases)} case(s), jobs={args.jobs}, docker={'off' if args.no_docker else 'per-case'}…\n")
    results = asyncio.run(_run_all(cases, docker_override, args.jobs))
    by_name = {r["name"]: r for r in results}

    rows, n_fail, n_new = [], 0, 0
    for c in cases:
        a = by_name[c["name"]]
        status, diffs = _compare(c, a)
        if status == "FAIL":
            n_fail += 1
        elif status == "NEW":
            n_new += 1
        icon = {"PASS": "✓", "FAIL": "✗", "NEW": "•"}[status]
        rows.append((icon, c["name"], a["verdict"], ",".join(a["reasons"]) or "-", f"{a['secs']}s", "; ".join(diffs)))

    w = max((len(r[1]) for r in rows), default=10)
    print(f"  {'':1}  {'server':{w}}  {'verdict':8}  {'reasons':22}  {'time':>6}  drift")
    for icon, name, verdict, reasons, secs, drift in rows:
        print(f"  {icon}  {name:{w}}  {verdict:8}  {reasons:22.22}  {secs:>6}  {drift}")

    if args.update:
        for c in all_cases:
            a = by_name.get(c.get("name"))
            if a and a["verdict"] != "SCANFAIL":
                expect = {"verdict": a["verdict"], "reasons": a["reasons"]}
                note = (c.get("expect") or {}).get("note")
                if note:
                    expect["note"] = note
                c["expect"] = expect
        body = yaml.safe_dump(all_cases, sort_keys=False, allow_unicode=True, default_flow_style=False)
        CORPUS.write_text(_HEADER + "cases:\n" + body.replace("\n- ", "\n\n- "), encoding="utf-8")
        print(f"\nupdated golden for {len(cases)} case(s) → {CORPUS}")
        return 0

    print(f"\n{len(cases)-n_fail-n_new} ok · {n_fail} regressed · {n_new} uncalibrated")
    if n_new:
        print("  (uncalibrated cases have no golden yet — run with --update to record one)")
    return 1 if n_fail else 0


if __name__ == "__main__":
    raise SystemExit(main())
