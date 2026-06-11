"""Data access for the web API.

Reads real scan output from ``results/`` and the real Semgrep pattern packs
under ``static/patterns/``, and falls back to the curated demo dataset in
``sample_data.json`` for everything the local machine hasn't produced yet.

Everything returned here is plain JSON-serialisable dicts shaped to match the
frontend's ``MINOS_DATA`` model (see ``frontend/src/data.js``).
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import shutil
import sys
from datetime import UTC, datetime
from functools import lru_cache
from pathlib import Path
from typing import Any
from uuid import uuid4

import structlog
import yaml

log = structlog.get_logger()

_API_DIR = Path(__file__).resolve().parent          # .../mcp_security_analyzer/api
_PKG_DIR = _API_DIR.parent                           # .../mcp_security_analyzer
_BACKEND_DIR = _PKG_DIR.parents[1]                   # .../backend
_SAMPLE_PATH = _API_DIR / "sample_data.json"
_PATTERNS_DIR = _PKG_DIR / "static" / "patterns"

_LANG_LABEL = {"python": "python", "javascript": "js", "typescript": "ts"}

# Dynamic scanner that owns each risk type (findings.json doesn't record it).
_RISK_SCANNER = {
    "R1": "r1_data_access", "R2": "r2_code_exec", "R3": "r3_llm_manipulation",
    "R4": "r4_behavior_drift", "R5": "r5_input_validation", "R6": "r6_stability",
}
_SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

VERDICT_REASONS = {
    "REJECT": "Critical findings reachable from tool input. Do not deploy until "
    "the flagged sinks are fixed and the server re-scans clean.",
    "CONDITIONAL": "No critical issues, but medium-severity signals remain. Ship "
    "only behind the noted mitigations and re-scan once resolved.",
    "APPROVE": "No blocking findings. The server cleared the pre-deploy gate; keep "
    "scanning on each version bump.",
}

# Short, human names + the typical cause / remediation per risk type — used to
# compose the natural-language report summary.
_RISK_NAMES = {
    "R1": "Data Access", "R2": "Code Execution", "R3": "LLM Manipulation",
    "R4": "Behaviour Drift", "R5": "Input Validation", "R6": "Service Stability",
}
_RISK_CAUSE = {
    "R1": "tools can reach unauthorized data or exfiltrate it",
    "R2": "tool input can reach code or command execution",
    "R3": "tool descriptions or outputs can manipulate the agent",
    "R4": "behaviour changes between environments or over time",
    "R5": "tool inputs flow unvalidated into dangerous sinks",
    "R6": "the server crashes or stalls under input fuzzing",
}
_RISK_FIX = {
    "R1": "scope the data and credentials the tools can touch",
    "R2": "sanitize tool input before it reaches exec/eval sinks",
    "R3": "strip untrusted instructions from tool text",
    "R4": "remove environment- and time-gated branches",
    "R5": "validate and bound every tool input",
    "R6": "harden the crashing handlers or run behind a restart supervisor",
}
_VERDICT_PHRASE = {
    "REJECT": "was rejected for deployment",
    "CONDITIONAL": "passed conditionally",
    "APPROVE": "cleared the pre-deploy gate",
    "UNSCANNED": "has not been fully scanned",
}


def _compose_summary(
    server: str,
    verdict: str,
    score: float,
    findings: list[dict[str, Any]],
    risk_scores: dict[str, float],
    tools_tested: int,
) -> str:
    """A 3-sentence, plain-language summary of a session report (deterministic)."""
    n = len(findings)

    # Sentence 1 — verdict + score.
    phrase = _VERDICT_PHRASE.get(verdict, "was scanned")
    s1 = f"{server} {phrase} with a risk score of {score:.2f}."

    # Risk types present, worst-scoring first.
    present = sorted({f.get("risk_type") for f in findings if f.get("risk_type")},
                     key=lambda r: -risk_scores.get(r, 0.0))
    worst = present[0] if present else None

    # Severity tally for a representative descriptor.
    sev_counts: dict[str, int] = {}
    for f in findings:
        sev_counts[f.get("severity", "INFO")] = sev_counts.get(f.get("severity", "INFO"), 0) + 1
    top_sev = next((s for s in _SEVERITY_ORDER if sev_counts.get(s)), None)

    # Sentence 2 — where the risk concentrates.
    if n == 0:
        s2 = "No findings surfaced across the six risk types (R1–R6)."
    else:
        plural = "s" if n > 1 else ""
        if len(present) == 1 and worst:
            cause = _RISK_CAUSE.get(worst, "")
            lead = "all under" if n > 1 else "under"
            where = f"{lead} {_RISK_NAMES.get(worst, worst)} ({worst}) — {cause}"
        else:
            names = ", ".join(f"{_RISK_NAMES.get(r, r)} ({r})" for r in present[:3])
            where = f"spanning {names}"
        sev_txt = f"{top_sev.lower()}-severity " if top_sev else ""
        reach = ""
        if tools_tested:
            reach = f", seen across {tools_tested} runtime tool{'s' if tools_tested != 1 else ''}"
        s2 = f"It has {n} {sev_txt}finding{plural} {where}{reach}."

    # Sentence 3 — the action.
    if n == 0 or verdict == "APPROVE":
        s3 = "No blocking issues — keep scanning on each version bump."
    elif verdict == "REJECT":
        fix = _RISK_FIX.get(worst, "fix the flagged issues")
        s3 = f"Do not deploy until you {fix} and the server re-scans clean."
    else:  # CONDITIONAL / other
        fix = _RISK_FIX.get(worst, "address the flagged issues")
        s3 = f"Ship only behind mitigations — {fix} — then re-scan."

    return f"{s1} {s2} {s3}"


# ---------------------------------------------------------------------------
# Sample (fallback / demo) dataset
# ---------------------------------------------------------------------------

@lru_cache(maxsize=1)
def _sample() -> dict[str, Any]:
    return json.loads(_SAMPLE_PATH.read_text(encoding="utf-8"))


def results_dir() -> Path:
    """Directory holding ``ses-*`` scan output, overridable via env."""
    env = os.environ.get("MINOS_RESULTS_DIR")
    if env:
        return Path(env)
    return _BACKEND_DIR / "results"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _short_id(session_id: str) -> str:
    """``ses-894ebdc2-71b1-...`` -> ``ses-894ebdc2`` (frontend's stable key)."""
    parts = session_id.split("-")
    return "-".join(parts[:2]) if len(parts) >= 2 else session_id


_RUNNERS = {"npx", "uvx", "uv", "node", "python", "python3", "bun", "bunx", "docker", "deno", "run"}


def _derive_server_name(command: str | None, args: list[str]) -> str:
    """Best-effort friendly server name from a launch command.

    Examples:
      ``@modelcontextprotocol/server-redis`` -> ``redis``
      ``mcp-server-reddit``                  -> ``reddit``
      ``@browsermcp/mcp``                    -> ``browsermcp``
      ``chrome-devtools-mcp@latest``         -> ``chrome-devtools``
      ``@playwright/mcp@latest``             -> ``playwright``
      ``weather-mcp``                        -> ``weather``
    """
    for a in args:
        if not a or a.startswith("-"):
            continue  # skip flags like -y, --api-key

        spec = a
        # strip a trailing @version / @latest (keep the scope's leading @)
        if spec.startswith("@"):
            at = spec.rfind("@")
            if at > 0:
                spec = spec[:at]
        else:
            spec = spec.split("@", 1)[0]

        if "server-" in spec:
            return spec.split("server-", 1)[1].strip("/") or (command or "server")

        if spec.startswith("@") and "/" in spec:
            scope, pkg = spec[1:].split("/", 1)
            if pkg in ("mcp", "server", "mcp-server"):
                return scope
            pkg = pkg.replace("mcp-server-", "").replace("mcp-", "")
            if pkg.endswith("-mcp"):
                pkg = pkg[:-4]
            return pkg or scope

        base = spec.rsplit("/", 1)[-1]  # path → basename
        for ext in (".py", ".js", ".mjs", ".cjs", ".ts"):
            if base.endswith(ext):
                base = base[: -len(ext)]
        base = base.replace("mcp-server-", "")
        if base.endswith("-mcp"):
            base = base[:-4]
        elif base.startswith("mcp-"):
            base = base[4:]
        if base and base.lower() not in _RUNNERS:
            return base

    return command or "server"


def _server_name_from_data(data: dict[str, Any]) -> str:
    """Friendly server name: a recorded server.name if meaningful, else derived."""
    srv = data.get("server") or {}
    name = (srv.get("name") or "").strip()
    cmd = srv.get("command")
    if name and name != cmd and name.lower() not in _RUNNERS:
        return name
    return _derive_server_name(cmd, srv.get("args") or [])


def _fmt_time(ts: str) -> str:
    """``2026-05-24T17:28:06.514188Z`` -> ``17:28:06.514`` for compact display."""
    if "T" in ts:
        t = ts.split("T", 1)[1].rstrip("Z")
        # Trim microseconds to milliseconds.
        if "." in t:
            head, frac = t.split(".", 1)
            t = f"{head}.{frac[:3]}"
        return t
    return ts


def _fmt_generated(iso: str | None) -> str:
    """``2026-05-24T17:38:14.708314Z`` -> ``2026-05-24 17:38 UTC`` (report header)."""
    if not iso or "T" not in iso:
        return iso or ""
    date, t = iso.split("T", 1)
    return f"{date} {t[:5]} UTC"


_EVENT_DATA_KEYS = ("method", "id", "sequence", "note", "tool", "category", "status")


def _trim_event_data(data: dict[str, Any]) -> dict[str, Any]:
    """Keep only small scalar fields so the raw-event table stays readable."""
    return {
        k: data[k]
        for k in _EVENT_DATA_KEYS
        if k in data and not isinstance(data[k], (dict, list))
    }


def _read_jsonl(path: Path, limit: int | None = None) -> list[dict[str, Any]]:
    """Stream-parse a JSONL file. With `limit`, stops after N rows WITHOUT
    reading the rest of the file (events.jsonl can be many MB)."""
    rows: list[dict[str, Any]] = []
    if not path.exists():
        return rows
    try:
        with path.open(encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                rows.append(json.loads(line))
                if limit and len(rows) >= limit:
                    break
    except (OSError, ValueError) as exc:
        log.warning("api.events.parse_failed", path=str(path), error=str(exc))
    return rows


def _event_row(e: dict[str, Any]) -> dict[str, Any]:
    return {
        "event_id": _short_id(e.get("event_id", "")),
        "ts": _fmt_time(e.get("ts", "")),
        "source": e.get("source"),
        "type": e.get("type"),
        "direction": e.get("direction"),
        "variation_tag": e.get("variation_tag"),
        "data": _trim_event_data(e.get("data") or {}),
    }


# Cap how many event rows the UI receives — some sessions log thousands.
_EVENT_CAP = 100


def _events_for_ui(path: Path, limit: int = _EVENT_CAP) -> list[dict[str, Any]]:
    """The most recent `limit` events, mapped for the raw-event table.

    Reads the file once but JSON-parses only the last `limit` lines (some
    sessions log tens of thousands of events).
    """
    if not path.exists():
        return []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        log.warning("api.events.read_failed", path=str(path), error=str(exc))
        return []
    out: list[dict[str, Any]] = []
    for line in lines[-limit:]:
        line = line.strip()
        if not line:
            continue
        try:
            out.append(_event_row(json.loads(line)))
        except ValueError:
            continue
    return out


# ---------------------------------------------------------------------------
# Real results on disk
# ---------------------------------------------------------------------------

def _list_result_dirs() -> list[Path]:
    base = results_dir()
    if not base.exists():
        return []
    return sorted(d for d in base.iterdir() if d.is_dir() and d.name.startswith("ses-"))


def _load_findings(session_dir: Path) -> dict[str, Any] | None:
    fp = session_dir / "findings.json"
    if not fp.exists():
        return None
    try:
        return json.loads(fp.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        log.warning("api.findings.parse_failed", path=str(fp), error=str(exc))
        return None


def _find_session_dir(session_id: str) -> Path | None:
    want = _short_id(session_id)
    for d in _list_result_dirs():
        if d.name == session_id or _short_id(d.name) == want:
            return d
    return None


def read_session_detail(session_id: str) -> dict[str, Any] | None:
    """Build a full report payload from a real ``results/ses-*`` directory."""
    session_dir = _find_session_dir(session_id)
    if session_dir is None:
        return None
    data = _load_findings(session_dir)
    events = _events_for_ui(session_dir / "events.jsonl")
    short = _short_id(session_dir.name)

    if data is None:
        # Events-only session: synthesise a minimal shell.
        return {
            "session_id": short,
            "real": True,
            "server": "server",
            "session": {
                "session_id": session_dir.name,
                "generated": "",
                "duration_sec": 0,
                "verdict": "UNSCANNED",
                "overall_score": 0.0,
                "tools_tested": 0,
                "total_events": len(events),
            },
            "risk_scores": {f"R{i}": 0.0 for i in range(1, 7)},
            "static": [],
            "dynamic": [],
            "findings": [],
            "events": events,
            "static_meta": None,
            "reason": "",
        }

    meta = data.get("metadata") or {}
    verdict = meta.get("verdict", "CONDITIONAL")
    risk_scores = {f"R{i}": 0.0 for i in range(1, 7)}
    risk_scores.update({k: float(v) for k, v in (data.get("dynamic_risk_scores") or {}).items()})

    dynamic = []
    for f in data.get("findings", []):
        dynamic.append({
            **f,
            "phase": f.get("phase") or "dynamic",
            "scanner": f.get("scanner") or "dynamic",
        })

    # `findings.json` metadata carries no human-readable timestamp; derive the
    # report's "generated" string from the first finding's detected_at.
    generated = (meta.get("generated") or "").strip()
    if not generated:
        first_da = next(
            (f.get("detected_at") for f in data.get("findings", []) if f.get("detected_at")),
            None,
        )
        generated = _fmt_generated(first_da)

    server_name = _server_name_from_data(data)
    score = meta.get("overall_score", 0.0)
    return {
        "session_id": short,
        "real": True,
        "server": server_name,
        "session": {
            "session_id": data.get("session_id", session_dir.name),
            "generated": generated,
            "duration_sec": meta.get("duration_sec", 0),
            "verdict": verdict,
            # New (Impact × Evidence) model detail: decision/reasons/warnings/
            # coverage/error. Present for scans run after the verdict-model wiring;
            # None for older sessions (UI falls back to the scalar verdict).
            "verdict_detail": meta.get("verdict_detail"),
            "overall_score": score,
            "tools_tested": meta.get("tools_tested", 0),
            "total_events": meta.get("total_events", len(events)),
        },
        "risk_scores": risk_scores,
        "static": [],
        "dynamic": dynamic,
        "findings": dynamic,
        "events": events,
        "static_meta": None,
        "reason": VERDICT_REASONS.get(verdict, ""),
        "summary": _compose_summary(
            server_name, verdict, score, dynamic, risk_scores, meta.get("tools_tested", 0)
        ),
    }


# ---------------------------------------------------------------------------
# Discovery (real)
# ---------------------------------------------------------------------------

def discovered_servers() -> list[dict[str, Any]]:
    """Real MCP servers discovered on this machine; sample fallback if none."""
    try:
        from mcp_security_analyzer.dynamic.discovery import discover_servers

        found = discover_servers()
    except Exception as exc:  # discovery is best-effort
        log.warning("api.discover.failed", error=str(exc))
        found = []

    if not found:
        return []  # real discovery only — no demo servers

    sessions = get_sessions()  # computed once, shared across all servers
    servers = []
    for d in found:
        cfg = d.server
        derived = _derive_server_name(cfg.command, list(cfg.args))
        servers.append(
            {
                "name": d.name,
                "source": d.source,
                "sourcePath": str(d.source_path),
                "command": cfg.command,
                "args": list(cfg.args),
                "transport": getattr(cfg, "transport", "stdio"),
                # Match a session by the config key name or the derived name.
                "lastScan": _last_scan_for({d.name, derived}, sessions),
            }
        )
    return servers


def _last_scan_for(names: set[str], sessions: list[dict[str, Any]]) -> dict[str, Any] | None:
    best = None
    for s in sessions:
        if s.get("server") not in names:
            continue
        if best is None or s.get("at", "") > best.get("at", ""):
            best = s
    if best is None:
        return None
    return {"verdict": best["verdict"], "at": best["at"]}


# ---------------------------------------------------------------------------
# Ruleset (real Semgrep packs)
# ---------------------------------------------------------------------------

def _summarise_yaml_pack(path: Path) -> dict[str, Any] | None:
    try:
        doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as exc:
        log.warning("api.ruleset.parse_failed", path=str(path), error=str(exc))
        return None
    rules_in = doc.get("rules") or []
    rules = []
    risk = None
    taint = False
    for r in rules_in:
        meta = r.get("metadata") or {}
        risk = meta.get("risk") or risk
        langs = r.get("languages") or []
        if r.get("mode") == "taint" or "taint" in (r.get("id") or ""):
            taint = True
        rules.append(
            {
                "id": r.get("id", ""),
                "lang": " · ".join(_LANG_LABEL.get(x, x) for x in langs),
                "level": r.get("severity", "INFO"),
                "confidence": meta.get("confidence", "low"),
                "desc": " ".join((r.get("message") or "").split()),
            }
        )
    return {
        "risk": risk or path.stem.split("-")[0].upper(),
        "file": path.name,
        "taint": taint or "taint" in path.stem,
        "summary": "",
        "rules": rules,
    }


def get_ruleset() -> dict[str, Any]:
    """Parse the real pattern packs; fall back to the sample ruleset."""
    sample = _sample()["RULESET"]
    if not _PATTERNS_DIR.exists():
        return sample

    sample_by_file = {p["file"]: p for p in sample["packs"]}
    packs = []
    for yml in sorted(_PATTERNS_DIR.glob("*.yaml")):
        pack = _summarise_yaml_pack(yml)
        if not pack or not pack["rules"]:
            continue
        # Borrow the curated one-line summary from the sample when available.
        if yml.name in sample_by_file:
            pack["summary"] = sample_by_file[yml.name].get("summary", "")
        packs.append(pack)

    if not packs:
        return sample
    return {"packs": packs, "scanners": sample["scanners"]}


# ---------------------------------------------------------------------------
# Real sessions -> SCAN_SESSIONS / RECENT_SESSIONS / FLEET_FINDINGS / OVERVIEW
#
# Everything below is derived from the actual ``results/ses-*/findings.json``
# scan output. The curated sample dataset is only used as a fallback when the
# results/ directory has no completed scans yet.
# ---------------------------------------------------------------------------

@lru_cache(maxsize=1)
def _server_source_map() -> dict[str, str]:
    """server-name -> client source (cursor / claude-desktop / ...), from discover."""
    try:
        from mcp_security_analyzer.dynamic.discovery import discover_servers

        mp: dict[str, str] = {}
        for d in discover_servers():
            mp.setdefault(_derive_server_name(d.server.command, list(d.server.args)), d.source)
            mp.setdefault(d.name, d.source)
        return mp
    except Exception:
        return {}


def _first_event_ts(session_dir: Path) -> str | None:
    rows = _read_jsonl(session_dir / "events.jsonl", limit=1)
    return rows[0].get("ts") if rows else None


def _session_at(session_dir: Path, data: dict[str, Any]) -> str:
    """ISO timestamp: first finding's detected_at, else the first event ts."""
    da = next(
        (f.get("detected_at") for f in (data.get("findings") or []) if f.get("detected_at")),
        None,
    )
    return da or _first_event_ts(session_dir) or ""


# (fingerprint, records) cached as ONE tuple and swapped atomically — a single
# binding assignment is atomic in CPython, so a read on the FastAPI threadpool
# (sync read endpoints run on real OS threads) never sees a torn key/value mix
# while a scan task invalidates it. None = empty/invalidated.
_RECORDS_CACHE: tuple[tuple, list[dict[str, Any]]] | None = None


def _invalidate_records_cache() -> None:
    global _RECORDS_CACHE
    _RECORDS_CACHE = None


def _records_key() -> tuple:
    """Cheap fingerprint of the results/ dir: (name, findings.json mtime) per session."""
    out = []
    for d in _list_result_dirs():
        fp = d / "findings.json"
        try:
            mtime = fp.stat().st_mtime if fp.exists() else 0.0
        except OSError:
            mtime = 0.0
        out.append((d.name, mtime))
    return tuple(out)


def _real_records() -> list[dict[str, Any]]:
    """All on-disk sessions that have a findings.json, newest first.

    Cached on the results/ fingerprint so repeated calls (a single page load
    fans out to several endpoints) don't re-read; a new or changed scan
    invalidates the cache automatically.
    """
    global _RECORDS_CACHE
    key = _records_key()
    cached = _RECORDS_CACHE  # one atomic read of the binding
    if cached is not None and cached[0] == key:
        return cached[1]
    src_map = _server_source_map()
    recs: list[dict[str, Any]] = []
    for d in _list_result_dirs():
        data = _load_findings(d)
        if data is None:
            continue
        blk = data.get("server") or {}
        cmd = blk.get("command")
        args = [str(a) for a in (blk.get("args") or [])]
        name = _server_name_from_data(data)
        recs.append(
            {
                "dir": d,
                "short": _short_id(d.name),
                "data": data,
                "server": name,
                "command": (cmd or "") + (" " + " ".join(args) if args else ""),
                "source": src_map.get(name, "local"),
                "at": _session_at(d, data),
            }
        )
    recs.sort(key=lambda r: r["at"], reverse=True)
    _RECORDS_CACHE = (key, recs)  # one atomic write
    return recs


def _session_summary(rec: dict[str, Any]) -> dict[str, Any]:
    data = rec["data"]
    meta = data.get("metadata") or {}
    findings = data.get("findings") or []
    static_n = sum(1 for f in findings if (f.get("phase") or "dynamic") == "static")
    risk = {f"R{i}": 0.0 for i in range(1, 7)}
    risk.update({k: float(v) for k, v in (data.get("dynamic_risk_scores") or {}).items()})
    return {
        "session_id": rec["short"],
        "server": rec["server"],
        "command": rec["command"],
        "source": rec["source"],
        "verdict": meta.get("verdict", "UNSCANNED"),
        "overall_score": meta.get("overall_score", 0.0),
        "findings": len(findings),
        "by_severity": meta.get("by_severity") or {},
        "tools_tested": meta.get("tools_tested", 0),
        "static_n": static_n,
        "dynamic_n": len(findings) - static_n,
        "duration_sec": meta.get("duration_sec", 0),
        "risk_scores": risk,
        "at": rec["at"],
    }


def _finding_for_ui(f: dict[str, Any], server: str, session_id: str) -> dict[str, Any]:
    phase = f.get("phase") or "dynamic"
    if phase == "static":
        fallback = "semgrep"
    else:
        fallback = _RISK_SCANNER.get(f.get("risk_type") or "", "dynamic")
    return {
        **f,
        "phase": phase,
        "scanner": f.get("scanner") or fallback,
        "server": server,
        "session_id": session_id,
    }


def get_sessions() -> list[dict[str, Any]]:
    # Real scans only — no demo fallback. Empty results/ → empty list.
    return [_session_summary(r) for r in _real_records()]


def get_recent_sessions() -> list[dict[str, Any]]:
    """Latest session per server (newest first). Real scans only."""
    seen: dict[str, dict[str, Any]] = {}
    for r in _real_records():  # already newest-first
        seen.setdefault(r["server"], r)
    return [_session_summary(r) for r in seen.values()]


def get_findings() -> list[dict[str, Any]]:
    recs = _real_records()  # real scans only — no demo fallback
    out: list[dict[str, Any]] = []
    for r in recs:
        for f in r["data"].get("findings") or []:
            out.append(_finding_for_ui(f, r["server"], r["short"]))
    return out


def _parse_dt(s: str) -> datetime | None:
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None


def _findings_over_time(sessions: list[dict[str, Any]], weeks: int = 8) -> list[int]:
    """Findings bucketed into `weeks` weekly bins ending at the latest session."""
    dated = [(_parse_dt(s["at"]), s.get("findings", 0)) for s in sessions if _parse_dt(s["at"])]
    if not dated:
        return [0] * weeks
    end = max(d for d, _ in dated)
    buckets = [0] * weeks
    for d, n in dated:
        wk = (end - d).days // 7
        if 0 <= wk < weeks:
            buckets[weeks - 1 - wk] += n
    return buckets


def get_overview(servers: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    """Fleet overview aggregated from real sessions only (no demo fallback)."""
    # Zeroed base — everything reflects real discovery/scans or stays empty.
    ov: dict[str, Any] = {
        "servers_discovered": 0, "sources": {}, "clients": 0,
        "scans_run": 0, "scans_this_week": 0, "open_findings": 0, "critical_high": 0,
        "by_severity": {k: 0 for k in _SEVERITY_ORDER}, "verdict_mix": {}, "at_risk": 0,
        "risk_scores": {f"R{i}": 0.0 for i in range(1, 7)},
        "static_findings": 0, "dynamic_findings": 0, "findings_over_time": [0] * 8,
    }
    if servers is None:
        servers = discovered_servers()
    if servers:
        src_counts: dict[str, int] = {}
        for s in servers:
            src = s.get("source", "unknown")
            src_counts[src] = src_counts.get(src, 0) + 1
        ov["servers_discovered"] = len(servers)
        ov["sources"] = src_counts
        ov["clients"] = len(src_counts)

    sessions = get_sessions()
    if not sessions:
        return ov  # discovery only, no scans yet — zeros

    sev_total: dict[str, int] = {}
    vmix = {"APPROVE": 0, "CONDITIONAL": 0, "REJECT": 0, "UNSCANNED": 0}
    risk = {f"R{i}": 0.0 for i in range(1, 7)}
    total_findings = 0
    for s in sessions:
        v = s.get("verdict", "UNSCANNED")
        vmix[v] = vmix.get(v, 0) + 1
        for k, n in (s.get("by_severity") or {}).items():
            sev_total[k] = sev_total.get(k, 0) + n
        for k, val in (s.get("risk_scores") or {}).items():
            if k in risk:
                risk[k] = max(risk[k], float(val))
        total_findings += s.get("findings", 0)

    cutoff = max((_parse_dt(s["at"]) for s in sessions if _parse_dt(s["at"])), default=None)
    week_count = 0
    if cutoff is not None:
        for s in sessions:
            dt = _parse_dt(s["at"])
            if dt is not None and (cutoff - dt).days <= 7:
                week_count += 1

    ov["scans_run"] = len(sessions)
    ov["scans_this_week"] = week_count
    ov["open_findings"] = total_findings
    ov["critical_high"] = sev_total.get("CRITICAL", 0) + sev_total.get("HIGH", 0)
    ov["by_severity"] = {k: sev_total.get(k, 0) for k in _SEVERITY_ORDER}
    ov["verdict_mix"] = vmix
    ov["at_risk"] = vmix.get("REJECT", 0) + vmix.get("CONDITIONAL", 0)
    ov["risk_scores"] = risk
    ov["static_findings"] = 0
    ov["dynamic_findings"] = total_findings
    ov["findings_over_time"] = _findings_over_time(sessions)
    return ov


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------

def get_health() -> dict[str, Any]:
    docker_state = "unavailable"
    try:
        import docker  # type: ignore

        client = docker.from_env()
        client.ping()
        docker_state = "running"
    except Exception:
        docker_state = "unavailable"

    semgrep_state = "ready" if shutil.which("semgrep") else "missing"
    return {"status": "ok", "docker": docker_state, "semgrep": semgrep_state}


# ---------------------------------------------------------------------------
# Bootstrap — the whole MINOS_DATA model in one round-trip
# ---------------------------------------------------------------------------

def get_bootstrap() -> dict[str, Any]:
    """Return the full frontend data model, served from real scan output.

    Live everywhere there is data:
      * DISCOVERED_SERVERS  — real ``minos discover`` output
      * RULESET             — parsed from the real Semgrep packs
      * SCAN_SESSIONS / RECENT_SESSIONS / FLEET_FINDINGS / OVERVIEW — aggregated
        from every ``results/ses-*/findings.json``
      * SESSION / RISK_SCORES / DYNAMIC_FINDINGS / EVENTS — the most recent real
        session's report detail

    The curated sample (RISK_META, SEVERITY_ORDER, SOURCE_LABELS, SCAN_TIMELINE)
    only supplies static UI lookups, plus a full fallback when results/ is empty.
    """
    data = json.loads(_SAMPLE_PATH.read_text(encoding="utf-8"))  # fresh copy (fallback base)
    servers = discovered_servers()
    data["DISCOVERED_SERVERS"] = servers
    data["RULESET"] = get_ruleset()

    recs = _real_records()
    if not recs:
        # No completed scans on disk — show empty (real data only, no demo),
        # but still reflect real discovery in the overview server counts.
        data["SCAN_SESSIONS"] = []
        data["RECENT_SESSIONS"] = []
        data["FLEET_FINDINGS"] = []
        data["OVERVIEW"] = get_overview(servers)
        return data

    data["SCAN_SESSIONS"] = get_sessions()
    data["RECENT_SESSIONS"] = get_recent_sessions()
    data["FLEET_FINDINGS"] = get_findings()
    data["OVERVIEW"] = get_overview(servers)

    # Headline = most recent real session.
    detail = read_session_detail(recs[0]["short"])
    if detail:
        data["SESSION"] = detail["session"]
        data["SERVER"] = {"name": detail["server"], "display": "", "command": "", "args": []}
        data["RISK_SCORES"] = detail["risk_scores"]
        data["DYNAMIC_FINDINGS"] = detail["dynamic"]
        data["STATIC_FINDINGS"] = []  # dynamic-only scan output carries no static phase
        data["EVENTS"] = detail["events"]
    return data


# ---------------------------------------------------------------------------
# Real scan execution
# ---------------------------------------------------------------------------

# In-flight scans: {scan_id -> {status, lines, session_id, started_dirs}}
_SCANS: dict[str, dict[str, Any]] = {}


def _minos_bin() -> str:
    """Path to the `minos` CLI in the same virtualenv as this server."""
    return str(Path(sys.executable).parent / "minos")


def _build_cmd(  # noqa: PLR0913
    profile: str, name: str | None, command: str | None, args: list[str], use_docker: bool,
    timeout: int | None = None,
) -> list[str]:
    """Build the minos CLI command for a given profile.

    CLI matrix:
      - ``minos scan``    → --target only (no --command), creates results/
      - ``minos static``  → --target or --command, NO results/ (stdout JSON)
      - ``minos dynamic`` → --target or --command, creates results/

    Mapping:
      profile "scan"    → ``minos dynamic`` with --command/--arg
                          (minos scan requires --target which needs a discovered name;
                           minos dynamic runs the full dynamic pipeline with session output)
      profile "static"  → ``minos static --format json`` (stdout captured, saved manually)
      profile "dynamic" → ``minos dynamic`` with --command/--arg
      profile "quick"   → ``minos dynamic --quick`` with --command/--arg
    """
    minos = _minos_bin()

    if profile == "static":
        parts = [minos, "static", "--format", "json"]
    elif profile == "quick":
        parts = [minos, "dynamic", "--quick"]
    elif profile == "scan":
        # Full pre-deploy gate = static + dynamic (minos scan), now that
        # `minos scan` accepts --command/--arg as well as --target.
        parts = [minos, "scan"]
    else:
        # "dynamic" → runtime sandbox only (no static scanners)
        parts = [minos, "dynamic"]

    # Target resolution: prefer discovered name (works with all profiles that
    # support --target); fall back to ad-hoc --command/--arg.
    if name and profile == "static":
        # static supports both; use --command so we get ad-hoc flexibility
        pass  # fall through to --command below
    # dynamic/scan: use --command/--arg for ad-hoc servers
    if command:
        parts += ["--command", command]
        for a in args:
            parts += ["--arg", a]
    elif name:
        parts += ["--target", name]

    if not use_docker and profile != "static":
        parts.append("--no-docker")

    # static analysis has no sandbox budget; only dynamic/scan/quick honour it.
    if timeout is not None and profile != "static":
        parts += ["--timeout", str(timeout)]

    return parts


def _patch_session_name(session_dir: Path, name: str) -> None:
    """Record a friendly server name into a session's findings.json server block."""
    fp = session_dir / "findings.json"
    try:
        data = json.loads(fp.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return
    srv = data.get("server")
    if not isinstance(srv, dict):
        srv = {}
        data["server"] = srv
    srv["name"] = name
    try:
        fp.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
    except OSError as exc:
        log.warning("api.scan.patch_name_failed", path=str(fp), error=str(exc))


def _static_verdict(findings_raw: list[dict[str, Any]]) -> tuple[str, dict[str, Any]]:
    """Compute a static-only scan's verdict with the (Impact × Evidence) model.

    Static analysis always has coverage, so the outcome is REJECT or PASS (never
    ERROR). Reuses ``verdict.evaluate`` by wrapping each finding dict in a small
    duck-typed shim (the evaluator reads ``kind``/``risk_type`` via getattr).
    """
    from types import SimpleNamespace

    from mcp_security_analyzer.dynamic.models import RiskType
    from mcp_security_analyzer.dynamic.output import verdict as verdict_mod

    shims = []
    for f in findings_raw:
        try:
            rt = RiskType(f.get("risk_type"))
        except ValueError:
            rt = None
        shims.append(SimpleNamespace(
            kind=f.get("kind"),
            risk_type=rt,
            finding_id=f.get("finding_id"),
            impact=None,
            evidence=None,
        ))
    result = verdict_mod.evaluate(shims, coverage_ok=True)
    return result.decision.value, result.to_dict()


def _save_static_session(
    stdout_json: str, command: str | None, args: list[str], name: str | None = None
) -> str | None:
    """Persist a ``minos static --format json`` stdout blob as a real results/ session."""

    try:
        data = json.loads(stdout_json.strip()) if stdout_json.strip().startswith("{") else {}
    except (json.JSONDecodeError, ValueError):
        return None

    findings_raw: list[dict[str, Any]] = data.get("findings") or []
    if not findings_raw and not data:
        return None

    session_id_full = f"ses-{uuid4()}"
    session_dir = results_dir() / session_id_full
    session_dir.mkdir(parents=True, exist_ok=True)

    now = datetime.now(UTC).isoformat()
    findings: list[dict[str, Any]] = []
    by_sev: dict[str, int] = {}
    risk_scores: dict[str, float] = {f"R{i}": 0.0 for i in range(1, 7)}
    sev_weight = {"CRITICAL": 0.9, "HIGH": 0.7, "MEDIUM": 0.45, "LOW": 0.2, "INFO": 0.1}

    for f in findings_raw:
        sev = f.get("severity", "INFO")
        by_sev[sev] = by_sev.get(sev, 0) + 1
        rt = f.get("risk_type", "R5")
        risk_scores[rt] = max(risk_scores.get(rt, 0.0), sev_weight.get(sev, 0.1))
        findings.append({
            "finding_id": f.get("finding_id", f"fnd-{uuid4()}"),
            "risk_type": rt,
            "severity": sev,
            "confidence": f.get("confidence", 0.5),
            "title": f.get("title", ""),
            "description": f.get("description", ""),
            "related_events": [],
            "tool_name": f.get("tool_name"),
            "reproduction": f.get("reproduction", ""),
            "detected_at": now,
            # Preserve the static scanner's provenance so the report shows where
            # it was detected and that it came from the static phase.
            "phase": "static",
            "scanner": f.get("scanner") or "semgrep",
            "location": f.get("location"),
            "evidence": f.get("evidence"),
            "tags": f.get("tags") or [],
            "kind": f.get("kind"),
        })

    overall = max(risk_scores.values()) if findings else 0.0
    # Verdict via the (Impact × Evidence) model (docs/severity-verdict-model.md).
    # Static analysis always "covers" the source, so coverage_ok=True → decision
    # is REJECT (a strong-evidence C/I or takeover finding) or PASS, never ERROR.
    verdict, verdict_detail = _static_verdict(findings_raw)

    server_entry: dict[str, Any] = {"command": command or "", "args": args}
    if name:
        server_entry["name"] = name
    output = {
        "session_id": session_id_full,
        "server": server_entry,
        "findings": findings,
        "event_log_path": str(session_dir / "events.jsonl"),
        "dynamic_risk_scores": risk_scores,
        "metadata": {
            "duration_sec": 0.0,
            "tools_tested": data.get("tools_analyzed", 0),
            "total_events": 0,
            "overall_score": round(overall, 4),
            "verdict": verdict,
            "verdict_detail": verdict_detail,
            "by_severity": by_sev,
        },
    }

    findings_json = json.dumps(output, indent=2, default=str)
    (session_dir / "findings.json").write_text(findings_json, encoding="utf-8")
    (session_dir / "events.jsonl").write_text("", encoding="utf-8")
    return _short_id(session_id_full)


# Rough per-profile baseline durations (seconds) when there's no history yet.
_PROFILE_ETA = {"static": 30, "quick": 120, "scan": 420, "dynamic": 360}


def estimate_eta(profile: str) -> int:
    """Estimate a scan's duration (seconds) from past runs blended with a
    per-profile baseline. Dynamic phases dominate and vary a lot, so for the
    dynamic-ish profiles we lean on the median of real completed sessions."""
    base = _PROFILE_ETA.get(profile, 300)
    if profile in ("scan", "dynamic", "quick"):
        durs = sorted(
            d for d in (
                float((r["data"].get("metadata") or {}).get("duration_sec", 0) or 0)
                for r in _real_records()
            )
            if d > 5
        )
        if durs:
            median = durs[len(durs) // 2]
            return int(round((base + median) / 2))
    return base


async def start_scan(
    command: str | None,
    args: list[str],
    profile: str,
    use_docker: bool,
    name: str | None = None,
    timeout: int | None = None,
) -> str:
    """Spawn the appropriate minos command and return a scan_id.

    Connect to ``stream_scan(scan_id)`` for live stderr output + the final
    ``{done, status, session_id}`` message when the scan finishes.
    """
    scan_id = f"scan-{uuid4()}"
    known_dirs: set[str] = {d.name for d in _list_result_dirs()}
    _SCANS[scan_id] = {
        "status": "running",
        "lines": [],
        "session_id": None,
        "started_dirs": known_dirs,
        "is_static": profile == "static",
        "command": command,
        "args": args,
        "name": name,  # friendly discovered name (e.g. "chrome-devtools-mcp"), if any
        "eta_sec": estimate_eta(profile),
    }

    cmd_parts = _build_cmd(profile, name, command, args, use_docker, timeout)
    log.info("api.scan.start", scan_id=scan_id, cmd=" ".join(cmd_parts))

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd_parts,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=str(_BACKEND_DIR),
            # minos can log a single line >64 KiB (a big fuzz response / data
            # field), which would raise ValueError in the stderr drain below and
            # leave the scan wedged "running" forever. Lift the StreamReader limit.
            limit=2 ** 25,
        )
        _SCANS[scan_id]["process"] = proc
        asyncio.create_task(_run_scan(scan_id, proc))
    except Exception as exc:
        _SCANS[scan_id]["status"] = "error"
        _SCANS[scan_id]["lines"].append(f"[error] Failed to start minos: {exc}")
        log.error("api.scan.launch_failed", scan_id=scan_id, error=str(exc))

    return scan_id


# ses-<uuid> as emitted by minos (orchestrator.collection.start / done). ANSI is
# stripped first so structlog colour codes around the value don't break the match.
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
_SESSION_RE = re.compile(
    r"ses-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
)


def _session_id_from_lines(lines: list[str]) -> str | None:
    """Extract THIS scan's own full session id from its minos stderr.

    Deterministic per-subprocess — each scan's log only carries its own
    session_id — so it replaces the old "diff the shared results/ listing"
    heuristic that mis-attributed directories when scans ran concurrently.
    """
    for ln in reversed(lines):  # last occurrence = orchestrator.done
        m = _SESSION_RE.search(_ANSI_RE.sub("", ln))
        if m:
            return m.group(0)
    return None


async def _run_scan(scan_id: str, proc: asyncio.subprocess.Process) -> None:
    """Read stderr (live log) and stdout (JSON for static), then detect session."""
    entry = _SCANS[scan_id]

    # Read stderr (structlog) and stdout (JSON output) concurrently.
    stdout_buf: list[bytes] = []

    async def drain_stderr() -> None:
        assert proc.stderr
        while True:
            try:
                raw = await proc.stderr.readline()
            except ValueError:
                # A single log line exceeded even the 32 MiB limit; readline()
                # clears the buffer, so drop it and keep draining rather than
                # crashing _run_scan and wedging the scan as "running".
                continue
            if not raw:
                break
            entry["lines"].append(raw.decode(errors="replace").rstrip())

    async def drain_stdout() -> None:
        assert proc.stdout
        data = await proc.stdout.read()
        if data:
            stdout_buf.append(data)

    await asyncio.gather(drain_stderr(), drain_stdout())
    await proc.wait()

    rc = proc.returncode
    entry["status"] = "done" if rc == 0 else "error"
    log.info("api.scan.finished", scan_id=scan_id, rc=rc)

    # Attribute the session deterministically from THIS subprocess's own stderr
    # (minos logs ``session_id=ses-…``), not by diffing the shared results/
    # listing — the old diff mis-attributed directories when scans ran
    # concurrently (two scans could latch onto the same/other scan's dir).
    new_dir: Path | None = None
    full_id = _session_id_from_lines(entry["lines"])
    if full_id:
        entry["session_id"] = _short_id(full_id)
        candidate = results_dir() / full_id
        new_dir = candidate if candidate.is_dir() else None
        log.info("api.scan.session_detected", scan_id=scan_id, session=entry["session_id"])

    # Record the friendly discovered name into the session so the report shows
    # it (minos writes server.name = the launcher command, e.g. "npx").
    if new_dir is not None and entry.get("name"):
        _patch_session_name(new_dir, entry["name"])

    # For static-only scans, minos writes JSON to stdout (no session dir).
    # Parse it and persist a proper session so the frontend can open a report.
    if not entry["session_id"] and entry.get("is_static") and rc == 0 and stdout_buf:
        stdout_json = b"".join(stdout_buf).decode(errors="replace")
        saved = _save_static_session(
            stdout_json, entry.get("command"), entry.get("args") or [], entry.get("name")
        )
        if saved:
            entry["session_id"] = saved
            log.info("api.scan.static_session_saved", scan_id=scan_id, session=saved)

    # Invalidate the records cache so the results list picks up the new session.
    _invalidate_records_cache()


def get_scan(scan_id: str) -> dict[str, Any] | None:
    return _SCANS.get(scan_id)


async def stream_scan(scan_id: str):  # noqa: ANN201
    """Async generator that yields SSE-compatible dicts until the scan ends."""
    entry = _SCANS.get(scan_id)
    if entry is None:
        return

    sent = 0
    while True:
        lines = entry["lines"]
        while sent < len(lines):
            yield {"data": json.dumps({"line": lines[sent]})}
            sent += 1

        status = entry.get("status")
        if status != "running":
            yield {
                "data": json.dumps({
                    "done": True,
                    "status": status,
                    "session_id": entry.get("session_id"),
                })
            }
            return

        await asyncio.sleep(0.25)
