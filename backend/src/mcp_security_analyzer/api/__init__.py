"""HTTP API layer for the MCP security analyzer.

A thin FastAPI read-API that serves the data the ``mcp-minos`` web frontend
renders: discovered servers, scan sessions, per-session reports, fleet
findings and the static ruleset. It reads real scan output from the
``results/`` directory and the real Semgrep pattern packs, falling back to a
curated demo dataset (``sample_data.json``) so the UI is reviewable without a
prior scan.

The dynamic scanner itself remains a CLI tool (``minos`` / ``minos.cli``);
this layer never executes scans — the "Launch scan" flow in the UI is
simulated client-side (see the project README).
"""

from mcp_security_analyzer.api.main import app, create_app

__all__ = ["app", "create_app"]
