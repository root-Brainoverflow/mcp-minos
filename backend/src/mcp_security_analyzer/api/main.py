"""FastAPI application for the mcp-minos frontend.

Run locally::

    uvicorn mcp_security_analyzer.api.main:app --reload --port 8000

``POST /api/scans`` launches the real ``minos`` CLI scanner as a subprocess.
``GET /api/scans/{id}/stream`` streams its stderr output via SSE so the
frontend progress screen shows live output. All other endpoints are read-only.
"""

from __future__ import annotations

import os

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sse_starlette.sse import EventSourceResponse

from mcp_security_analyzer.api import store


class ScanRequest(BaseModel):
    name: str | None = None      # discovered server name (e.g. "redis")
    command: str | None = None   # launch command (e.g. "npx")
    args: list[str] = []
    profile: str = "scan"
    docker: bool = True


def _cors_origins() -> list[str]:
    raw = os.environ.get("MINOS_CORS_ORIGINS", "*")
    if raw.strip() == "*":
        return ["*"]
    return [o.strip() for o in raw.split(",") if o.strip()]


def create_app() -> FastAPI:
    app = FastAPI(
        title="mcp-minos API",
        version="0.1.0",
        description="API for the mcp-minos MCP security scanner frontend.",
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=_cors_origins(),
        allow_credentials=False,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    api = "/api"

    @app.get("/")
    def root() -> dict:
        return {"name": "mcp-minos API", "version": "0.1.0", "docs": "/docs"}

    @app.get(f"{api}/health")
    def health() -> dict:
        return store.get_health()

    @app.get(f"{api}/bootstrap")
    def bootstrap() -> dict:
        return store.get_bootstrap()

    @app.get(f"{api}/overview")
    def overview() -> dict:
        return store.get_overview()

    @app.get(f"{api}/servers")
    def servers() -> list[dict]:
        return store.discovered_servers()

    @app.get(f"{api}/sessions")
    def sessions() -> list[dict]:
        return store.get_sessions()

    @app.get(f"{api}/sessions/recent")
    def recent_sessions() -> list[dict]:
        return store.get_recent_sessions()

    @app.get(f"{api}/sessions/{{session_id}}")
    def session_detail(session_id: str) -> dict:
        detail = store.read_session_detail(session_id)
        if detail is None:
            raise HTTPException(status_code=404, detail=f"No session '{session_id}'")
        return detail

    @app.get(f"{api}/findings")
    def findings() -> list[dict]:
        return store.get_findings()

    @app.get(f"{api}/ruleset")
    def ruleset() -> dict:
        return store.get_ruleset()

    # ── Real scan execution ────────────────────────────────────────────────────

    @app.post(f"{api}/scans")
    async def create_scan(req: ScanRequest) -> dict:
        """Launch a real ``minos`` scan and return a scan_id.

        Connect to ``GET /api/scans/{scan_id}/stream`` (SSE) to receive live
        stderr output from the CLI, and the session_id when it completes.
        """
        scan_id = await store.start_scan(
            command=req.command,
            args=req.args,
            profile=req.profile,
            use_docker=req.docker,
            name=req.name,
        )
        entry = store.get_scan(scan_id) or {}
        return {"scan_id": scan_id, "eta_sec": entry.get("eta_sec")}

    @app.get(f"{api}/scans/{{scan_id}}")
    def scan_status(scan_id: str) -> dict:
        """Poll scan status (status, session_id when done)."""
        entry = store.get_scan(scan_id)
        if entry is None:
            raise HTTPException(status_code=404, detail=f"No scan '{scan_id}'")
        return {
            "scan_id": scan_id,
            "status": entry["status"],
            "lines": len(entry["lines"]),
            "session_id": entry.get("session_id"),
        }

    @app.get(f"{api}/scans/{{scan_id}}/stream")
    async def stream_scan(scan_id: str) -> EventSourceResponse:
        """SSE stream of live stderr output from the running minos process.

        Each event is ``{"line": "..."}`` while running, then a final
        ``{"done": true, "status": "done"|"error", "session_id": "..."}`` event.
        """
        entry = store.get_scan(scan_id)
        if entry is None:
            raise HTTPException(status_code=404, detail=f"No scan '{scan_id}'")
        return EventSourceResponse(store.stream_scan(scan_id))

    return app


app = create_app()


def run() -> None:
    """Console-script entrypoint: ``minos-api`` -> uvicorn server."""
    import uvicorn

    uvicorn.run(
        "mcp_security_analyzer.api.main:app",
        host=os.environ.get("MINOS_API_HOST", "0.0.0.0"),  # noqa: S104
        port=int(os.environ.get("MINOS_API_PORT", "8000")),
        reload=os.environ.get("MINOS_API_RELOAD", "").lower() in {"1", "true", "yes"},
    )


if __name__ == "__main__":
    run()
