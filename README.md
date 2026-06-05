# mcp-minos

Pre-deployment security scanner for **MCP servers** — static analysis on
source / manifest / tool metadata plus sandboxed dynamic fuzzing, scored
against a six-type risk taxonomy (R1–R6) into a single deploy verdict
(`APPROVE` / `CONDITIONAL` / `REJECT`).

This repository is a **monorepo**:

```
mcp-minos/
├── backend/        Python — the scanner (CLI) + a FastAPI read-API
│   ├── src/mcp_security_analyzer/
│   │   ├── static/       static scanners + Semgrep pattern packs
│   │   ├── dynamic/      sandboxed dynamic analysis + the `minos` CLI
│   │   ├── common/       shared models
│   │   └── api/          FastAPI read-API the frontend talks to   ← new
│   ├── docker/      sandbox base images / seccomp profile (dynamic phase)
│   ├── configs/     scan config presets
│   ├── results/     scan output (ses-*/findings.json, events.jsonl)
│   ├── tests/
│   ├── Dockerfile   builds the read-API image
│   └── pyproject.toml
├── frontend/       React (Vite) — the web UI, built from the design handoff
│   ├── src/
│   │   ├── components/   ui primitives (ui.jsx, common.jsx)
│   │   ├── screens/      dashboard, discover, scanflow, report, sidebar, login
│   │   ├── App.jsx       shell + navigation state machine
│   │   ├── api.js        backend client (graceful offline fallback)
│   │   ├── data.js       bundled sample dataset (offline fallback)
│   │   └── theme.css     design tokens
│   ├── Dockerfile   build → nginx static serve (+ /api proxy)
│   └── nginx.conf
└── docker-compose.yml   backend + frontend, one command
```

## Quick start (Docker)

```bash
docker compose up --build
```

- Frontend → http://localhost:3000
- Backend API → http://localhost:8000 (OpenAPI docs at `/docs`)

nginx in the frontend container reverse-proxies `/api` to the backend service,
so the UI talks to the API with no CORS setup.

## Local development

**Backend** (Python 3.11+):

```bash
cd backend
uv sync          # or: pip install -e .
minos-api        # FastAPI on http://localhost:8000  (uvicorn)
# the original scanner CLI is unchanged:
minos discover
minos scan --target redis --format json
```

**Frontend** (Node 18+):

```bash
cd frontend
npm install
npm run dev      # Vite on http://localhost:5173, proxies /api → :8000
```

## How the frontend connects to the backend

At startup the frontend calls `GET /api/bootstrap` and overlays the response
onto its in-memory data model. If the backend is unreachable it falls back to
the bundled sample dataset (`frontend/src/data.js`) so the UI always renders.

| Endpoint | Serves |
|----------|--------|
| `GET /api/bootstrap` | the whole UI data model in one round-trip |
| `GET /api/health` | Docker / Semgrep availability (sidebar status) |
| `GET /api/overview` | dashboard KPIs + fleet risk surface |
| `GET /api/servers` | **live** `minos discover` output |
| `GET /api/sessions` | scan-session list |
| `GET /api/sessions/{id}` | **live** per-session report read from `results/` |
| `GET /api/findings` | fleet-wide findings |
| `GET /api/ruleset` | **live** Semgrep pattern packs parsed from `static/patterns/*.yaml` |
| `POST /api/scans` | simulated scan trigger (returns session + phased timeline) |

### Live vs. demo data

When the backend runs on the host, **everything is real**:

- **Discovered servers** — parsed from your Claude Desktop / Claude Code /
  Cursor / VS Code config files.
- **Ruleset** — the 23 Semgrep rules across 6 packs, read from the real YAML.
- **Scan results, dashboard overview, fleet findings, and every per-session
  report** — aggregated from every `backend/results/ses-*/findings.json`
  (+ `events.jsonl`). Server names are derived from the launch command
  (`@modelcontextprotocol/server-redis` → `redis`), verdicts/scores/severity
  come from each session's metadata, and the raw-event table shows the most
  recent 100 of N events.

Notes on real data:

- These sessions are **dynamic-phase output**, so the static/dynamic split shows
  0 static findings — that's accurate for what's on disk (run `minos scan` to
  produce static findings too).
- The bundled sample dataset
  (`backend/src/mcp_security_analyzer/api/sample_data.json`, mirrored at
  `frontend/src/sample_data.json`) is now only a **fallback**: the backend uses
  it when `results/` has no completed scans, and the frontend uses it when the
  backend is unreachable.

> Inside Docker the backend container can't see your host's MCP config files or
> Docker daemon, so `docker compose up` shows the **sample** servers and an
> empty/limited results set. For real host data, run the backend locally
> (`cd backend && minos-api`) and the frontend with `npm run dev`.

### Simulated scans & auth (by design)

- **Launch scan** plays the phased live-progress animation client-side and then
  opens the resulting report. It does **not** spawn the Docker sandbox from the
  web app — running real dynamic scans stays in the `minos` CLI (it needs a
  Docker daemon). `POST /api/scans` is the simulated trigger.
- **Login** is simulated client-side: email/password + GitHub/Google buttons,
  role derived from the email (`admin@…` → admin, otherwise developer),
  persisted to `localStorage`. There is no auth backend.

## Risk taxonomy

| ID | Risk | Examples |
|----|------|----------|
| R1 | Unauthorized data access / exfiltration | Secret env reads, broad fs scans, file/env → HTTP exfil |
| R2 | Unauthorized code / command execution | Dangerous calls, dynamic eval, runtime installs, malicious deps |
| R3 | LLM behavior manipulation | Hidden instructions in tool descriptions, invisible Unicode |
| R4 | Behavioral inconsistency / deception | Env/time-gated branches, source vs. runtime metadata divergence |
| R5 | Input handling vulnerabilities | Command/SQL/path injection (taint-tracked), permissive schemas |
| R6 | Service stability | Timeout-less HTTP, unbounded reads, OOM-prone payloads |

See [backend/README.md](backend/README.md) for the scanner internals and the
`docs/` directory for the static/dynamic layer deep-dives.
