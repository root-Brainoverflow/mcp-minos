# mcp-minos

[![CI](https://github.com/root-Brainoverflow/mcp-minos/actions/workflows/ci.yml/badge.svg)](https://github.com/root-Brainoverflow/mcp-minos/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Pre-deployment security scanner for **MCP servers** — static analysis on
source / manifest / tool metadata plus sandboxed dynamic fuzzing, scored
against a six-type risk taxonomy (R1–R6) into a single deploy verdict —
`REJECT` / `PASS`, plus `ERROR` for an untestable scan (no coverage) — derived
from an (Impact × Evidence) model. Ships with a web UI (English/Korean).

```
┌─ frontend (React/Vite, nginx) ─┐      ┌─ backend (FastAPI) ─┐      ┌ minos CLI ┐
│  dashboard · discover · scan   │ ─/api▶│  read-API + live    │ ─spawn▶│  static   │
│  live progress · report · PDF  │  SSE │  scan orchestration  │      │  dynamic  │──▶ Docker sandbox
└────────────────────────────────┘      └──────────────────────┘      └───────────┘
```

## Repository layout

```
mcp-minos/
├── backend/        Python — the scanner (CLI) + a FastAPI read/scan API
│   ├── src/mcp_security_analyzer/
│   │   ├── static/   static scanners + Semgrep pattern packs
│   │   ├── dynamic/  sandboxed dynamic analysis + the `minos` CLI
│   │   ├── common/   shared models
│   │   └── api/      FastAPI app the frontend talks to
│   ├── docker/       sandbox base images / seccomp profile (dynamic phase)
│   ├── configs/      scan config presets
│   ├── results/      scan output (ses-*/findings.json, events.jsonl) — git-ignored
│   └── Dockerfile
├── frontend/       React (Vite) web UI → built to static + nginx (/api proxy)
├── docker-compose.yml
└── .github/workflows/   CI + GHCR release
```

## Quick start

Run both services **locally** (not via Docker) — the backend on the host so it
can read your editor configs and spawn the `minos` scanner, and the frontend via
the Vite dev server. The analyzer still uses your local Docker *for the sandbox*
during dynamic scans, but the app itself is not containerized to run.

**Backend** (Python ≥ 3.11):

```bash
cd backend
uv sync                          # or: python -m venv .venv && pip install -e .
source .venv/bin/activate        # put minos / minos-api on PATH (or prefix each command with `uv run`)
minos-api                        # FastAPI on http://localhost:8000 (uvicorn)
# the scanner CLI is unchanged:
minos discover
minos dynamic --command npx --arg -y --arg @modelcontextprotocol/server-redis
```

**Frontend** (Node ≥ 18):

```bash
cd frontend
npm install
npm run dev             # Vite on http://localhost:5173, proxies /api → :8000
```

Open http://localhost:5173 and the UI is fully live: discovery reads your
Claude Desktop / Claude Code / Cursor / VS Code configs, **New scan** runs the
real `minos` CLI and streams progress, and every report is read from
`backend/results/`.

## How the UI connects to the backend

Each screen fetches its own endpoint (with retry + error states); there is no
silent sample fallback once the backend is reachable.

| Endpoint | Serves |
|----------|--------|
| `GET  /api/health` | Docker / Semgrep availability (sidebar status) |
| `GET  /api/overview` | dashboard KPIs + fleet risk surface |
| `GET  /api/servers` | **live** `minos discover` output |
| `GET  /api/sessions` · `/sessions/recent` | scan-session list |
| `GET  /api/sessions/{id}` | **live** per-session report from `results/` |
| `GET  /api/findings` | fleet-wide findings |
| `GET  /api/ruleset` | **live** Semgrep packs parsed from `static/patterns/*.yaml` |
| `POST /api/scans` | start a real scan — spawns `minos`, returns `scan_id` + ETA |
| `GET  /api/scans/{id}/stream` | **SSE** live stderr → structured progress steps |

**Real scans, not simulated.** `POST /api/scans` launches the appropriate `minos`
command (`static` / `dynamic` / `quick` / full) as a subprocess; the UI subscribes
to the SSE stream and renders structured steps with a raw-log toggle and a
history-blended ETA. When the scan finishes it opens the freshly written session
report. Static scans are persisted as synthetic sessions so their findings keep
their real phase / scanner / source location.

> **Login** is client-side only (email/password + provider buttons; role derived
> from the email, persisted to `localStorage`). There is no auth backend — this
> is a local developer tool.

## UI features

- **Bilingual** — full English / Korean localization (UI, findings, and a
  natural-language report summary written from the actual findings).
- **Live progress** — per-profile phase rail (static / dynamic / scoring),
  structured steps, raw-output toggle, ETA, and crash/timeout markers. The
  dynamic phase is labeled "analysis" (not "sandbox") when Docker is off.
- **Report → PDF** — export via the browser print path (vector, selectable text;
  every finding expanded).- **Deploy verdict** — the report surfaces the (Impact × Evidence) verdict
  (`REJECT` / `PASS` / `ERROR`) with its blocking reasons and non-blocking
  warnings (including the potential-memory-corruption crash flag).

## <a name="real-scans-in-docker-optional"></a>Real scans in Docker (optional)

To run real discovery + scans from the composed backend, give it the Docker
socket and your config dir, e.g. a `docker-compose.override.yml`:

```yaml
services:
  backend:
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock   # spawn sandbox containers
      - ${HOME}/.cursor:/root/.cursor:ro             # MCP configs for discovery
      - ./backend/results:/app/results               # rw, persist scan output
```

This grants the container Docker access — only do it on a machine you trust.

## Container images (GHCR)

Tagged releases publish both images to the GitHub Container Registry:

```bash
docker pull ghcr.io/root-brainoverflow/mcp-minos-backend:latest
docker pull ghcr.io/root-brainoverflow/mcp-minos-frontend:latest
```

Cut a release by pushing a tag:

```bash
git tag v0.1.0 && git push origin v0.1.0   # → .github/workflows/release.yml
```

## Risk taxonomy

| ID | Risk | Examples |
|----|------|----------|
| R1 | Unauthorized data access / exfiltration | Secret env reads, broad fs scans, file/env → HTTP exfil |
| R2 | Unauthorized code / command execution | Dangerous calls, dynamic eval, runtime installs, malicious deps |
| R3 | LLM behavior manipulation | Hidden instructions in tool descriptions, invisible Unicode |
| R4 | Behavioral inconsistency / deception | Env/time-gated branches, source vs. runtime metadata divergence |
| R5 | Input handling vulnerabilities | Command/SQL/path injection (taint-tracked), permissive schemas |
| R6 | Service stability | Timeout-less HTTP, unbounded reads, OOM-prone payloads |

See [backend/README.md](backend/README.md) for scanner internals and
[backend/docs/](backend/docs/) for the static/dynamic deep-dives.

## License

[MIT](LICENSE).
