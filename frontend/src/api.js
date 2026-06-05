// api.js — thin client for the mcp-minos FastAPI read-API.
//
// Every call degrades gracefully: if the backend is unreachable the UI keeps
// working on the bundled sample dataset (see data.js). The base URL defaults
// to "/api" (proxied by Vite in dev and by nginx in prod); override with
// VITE_API_BASE at build time.

import { MINOS_DATA } from "./data.js";

const BASE = (import.meta.env && import.meta.env.VITE_API_BASE) || "/api";

let _online = false;
export const isOnline = () => _online;

async function get(path, { timeoutMs = 8000 } = {}) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(`${BASE}${path}`, {
      signal: ctrl.signal,
      headers: { Accept: "application/json" },
    });
    if (!res.ok) throw new Error(`HTTP ${res.status} for ${path}`);
    return await res.json();
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Fetch the whole data model in one round-trip and merge it into MINOS_DATA.
 * Resolves to `true` when the backend answered, `false` when we fell back to
 * the bundled sample. Never rejects — the app must boot either way.
 */
export async function hydrate() {
  try {
    const data = await get("/bootstrap");
    Object.assign(MINOS_DATA, data);
    _online = true;
    return true;
  } catch (err) {
    // eslint-disable-next-line no-console
    console.warn("[mcp-minos] backend unavailable — using bundled sample data.", err?.message || err);
    _online = false;
    return false;
  }
}

// ── Per-resource fetchers (used by screens via useApi) ───────────────────────
// These THROW on failure (no silent fallback) so the UI can show a clear
// "backend unreachable — retry" state instead of misleading sample data.
export const fetchOverview = () => get("/overview");
export const fetchServers = () => get("/servers");
export const fetchSessions = () => get("/sessions");
export const fetchRecentSessions = () => get("/sessions/recent");
export const fetchFindings = () => get("/findings");
export const fetchRuleset = () => get("/ruleset");

// Health drives a non-critical sidebar indicator — keep its soft fallback.
export const fetchHealth = () =>
  get("/health").catch(() => ({ status: "offline", docker: "unavailable", semgrep: "missing" }));

/** Fetch one session's full report detail (real, read from results/). */
export const fetchSessionDetail = (id) => get(`/sessions/${encodeURIComponent(id)}`).catch(() => null);

/**
 * Start a real scan — POSTs to the backend, which spawns `minos` as a
 * subprocess. Returns { scan_id }. Use connectScanStream(scan_id, ...) to
 * receive live output.
 *
 * payload: { name?, command?, args[], profile, docker }
 */
export async function createScan(payload) {
  const res = await fetch(`${BASE}/scans`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: "application/json" },
    body: JSON.stringify(payload),
  });
  if (!res.ok) {
    const msg = await res.text().catch(() => `HTTP ${res.status}`);
    throw new Error(msg || `HTTP ${res.status}`);
  }
  return await res.json(); // { scan_id }
}

/**
 * Connect to the SSE stream for a running scan.
 *
 * @param {string} scanId
 * @param {{ onLine, onDone, onError }} handlers
 *   onLine(line: string)
 *   onDone({ status, session_id })
 *   onError(err)
 * @returns {() => void}  close() function
 */
export function connectScanStream(scanId, { onLine, onDone, onError }) {
  const es = new EventSource(`${BASE}/scans/${encodeURIComponent(scanId)}/stream`);

  es.onmessage = (e) => {
    try {
      const msg = JSON.parse(e.data);
      if (msg.done) {
        es.close();
        onDone({ status: msg.status, session_id: msg.session_id });
      } else if (msg.line !== undefined) {
        onLine(msg.line);
      }
    } catch { /* ignore malformed events */ }
  };

  es.onerror = () => {
    es.close();
    onError(new Error("Lost connection to scan stream"));
  };

  return () => es.close();
}
