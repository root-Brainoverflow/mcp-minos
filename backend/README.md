# mcp-minos

Pre-deployment security scanner for MCP servers. Combines static analysis on
source / manifest / tool metadata with sandboxed dynamic analysis driven by
payload fuzzing.

## Risk taxonomy

The analyzer classifies findings under six risk types.

| ID | Risk | Examples |
|----|------|----------|
| R1 | Unauthorized data access / exfiltration | Secret env reads, broad filesystem scans, file/env → HTTP exfil |
| R2 | Unauthorized code / command execution | Dangerous calls, dynamic eval, runtime package install, malicious dependencies |
| R3 | LLM behavior manipulation | Hidden instructions in tool descriptions, invisible Unicode, encoded payloads |
| R4 | Behavioral inconsistency / deception | Env/time-gated branches, source vs. runtime metadata divergence |
| R5 | Input handling vulnerabilities | Command/SQL/path injection (taint-tracked), permissive schemas |
| R6 | Service stability | Timeout-less HTTP, unbounded reads, OOM-prone payloads |

## Install

Requires Python 3.11+. Docker is needed for the dynamic phase; the static
phase runs without it.

```
uv sync
# or
pip install -e .
```

Semgrep is an optional host dependency for the static code-pattern scanner.
If it is missing the rest of static analysis still runs.

## Commands

Three commands share the same target selection interface
(`--target <name>` for discovered servers, or `--command --arg ...` for an
ad-hoc spec).

- `minos discover` — list MCP servers found in Claude Desktop, Claude
  Code, Cursor, and VSCode configs.
- `minos static --target <name>` — run only the static scanners (manifest
  security, Semgrep, descriptions, schema audit). No Docker required.
- `minos dynamic --target <name>` — run only the dynamic phase (sandboxed
  server + payload fuzzing). Docker required.
- `minos scan --target <name>` — run both. Static source-tree scanners
  before Docker, then dynamic, then static metadata scanners on the
  captured `tools/list` response. JSON output via `--format json`.

Ad-hoc example without prior discovery:

```
minos static --command npx --arg @browsermcp/mcp@latest
```

## Architecture

Two layers cooperate through a shared environment snapshot and a captured
runtime tool list.

```
   ServerConfig
       │
       ▼
 [static] environment snapshot ───────────────┐
       │  (manifest, deps, version constraints,│
       │   source signals, extracted tarball)  │
       │                                       ▼
       │                                  [dynamic] sandbox
       │                                       │  match runtime
       │                                       │  on first attempt
       │                                       ▼
       │                                  init → tools/list
       │                                       │  (runtime tools)
       │  source-tree scanners                 │
       │  (manifest, Semgrep,                  │
       │   descriptions, schema)               │
       │                                       │
       ▼                                       ▼
   StaticReport ◄──── metadata divergence ──── runtime tools
       │                                       │
       └──────────► merged report ◄────────────┘
                       │
                       ▼
                JSON / summary
```

### Static layer (`src/mcp_security_analyzer/static/`)

- `tarball_fetcher.py` — download and extract a published package
  (npm / PyPI) without needing host npm or pip.
- `source_analyzer.py` — read manifests and scan the source tree for
  named signals.
- `tool_extractor.py` + `zod_to_schema.py` + `pydantic_to_schema.py` —
  recover tool name, description, and JSON Schema from source. Handles
  zod (with `.extend({...})` and symbol references) and pydantic
  (BaseModel, FastMCP `@tool` decorators, low-level `Tool()` calls,
  `Annotated[T, Field(...)]`, `Class.model_json_schema()` invocations).
- `scanners/manifest_security.py` (R2) — denylist, edit-distance
  typosquatting, install-hook patterns, encoded-payload blobs.
- `scanners/code_patterns.py` + `patterns/` (R1/R2/R4/R5/R6) — Semgrep
  wrapper with 23 rules across 6 YAML files. Includes taint-mode rules
  sourcing from MCP tool-handler arguments and sinking to shell / SQL /
  filesystem calls with `shlex.quote` and `pathlib.resolve` sanitizers.
- `scanners/descriptions.py` (R3) — rule-card pattern matching over every
  text field of a tool object: top-level description, parameter
  descriptions, defaults, enum values, examples.
- `scanners/schema_audit.py` (R5) — input-schema permissiveness scoring
  capped as a support signal.
- `scanners/metadata_divergence.py` (R4) — when both source-extracted
  and runtime tool definitions are available, flag missing-on-one-side
  tools and description differences as rug-pull / evasion signals.

### Dynamic layer (`src/mcp_security_analyzer/dynamic/`)

- `infrastructure/sandbox.py` — Docker-based sandbox with profile-matched
  base images. Consumes the static snapshot for first-attempt environment
  match and falls back to stderr-learning retry when needed.
- `scanners/r1` … `scanners/r6` — payload sequencers + finding scanners
  per risk type.
- `scanners/r3_llm_manipulation.py` — runtime injection checks on tool
  call responses and resource bodies. Static layer owns the description
  text scan.
- `scanners/chain_attack.py` — server-metadata-based chain attack
  detection (`readOnlyHint` mismatches, destructive follow-up steering).
- `protocol/`, `correlation/`, `output/` — JSON-RPC client, event store,
  scorer, exporter.

## Documentation

- [docs/static-analysis.md](docs/static-analysis.md) — static layer in
  detail, scanner-by-scanner.
- [docs/sandbox-environment-matching.md](docs/sandbox-environment-matching.md)
  — how the sandbox uses the static snapshot to match the server's
  runtime requirements on the first attempt.
- [docs/static-tarball-fetch.md](docs/static-tarball-fetch.md) — tarball
  fetcher in isolation.
- [docs/dynamic-analysis.md](docs/dynamic-analysis.md) — dynamic phase
  overview.
- [docs/threat-payload-mapping.md](docs/threat-payload-mapping.md) —
  payload-to-risk mapping.

## Limitations

- Compressed (minified) published bundles reduce Semgrep precision for
  name-based rules and data flow tracking. Unminified bundles (most MCP
  servers) work normally.
- Wheel-only PyPI packages have no source distribution; analysis is
  limited to manifest-level checks.
- Schema recovery covers common zod and pydantic shapes. zod refinement
  / custom transform and pydantic custom validators are not represented;
  the schema auditor falls back to the runtime `tools/list` for those
  tools.
- Static and dynamic findings are emitted side-by-side; a unified scoring
  model is not yet implemented.
- Extracted tarballs are removed at the end of a run. New rules require
  refetching the package.
