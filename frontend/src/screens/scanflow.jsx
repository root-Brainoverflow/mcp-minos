// scanflow.jsx — Discover, Configure, Live Progress.
import React, { useState, useEffect, useRef, useMemo } from "react";
import { Card, Button, Mono, VerdictPill, Spinner, RefreshButton, Loading, ErrorState } from "../components/ui.jsx";
import { ScreenHead, SectionLabel, Meta } from "../components/common.jsx";
import { MINOS_DATA } from "../data.js";
import { fetchServers } from "../api.js";
import { useApi } from "../hooks.js";
import { t, getLang } from "../i18n.js";

// Format a duration (seconds) → "Xm Ys" / "X분 Y초".
function fmtDur(secs) {
  const s = Math.max(0, Math.round(secs));
  const m = Math.floor(s / 60);
  const r = s % 60;
  if (getLang() === "ko") return m > 0 ? `${m}분 ${r}초` : `${r}초`;
  return m > 0 ? `${m}m ${r}s` : `${r}s`;
}

// ═══════════════════════════════════════════════════════════════════════════
// DISCOVER
// ═══════════════════════════════════════════════════════════════════════════
export function DiscoverScreen({ onSelect }) {
  const { data, loading, error, reload } = useApi(fetchServers);
  const servers = data || [];
  const sources = MINOS_DATA.SOURCE_LABELS;
  const initial = loading && !data;
  return (
    <div className="fade-up" style={{ maxWidth: "var(--maxw)", margin: "0 auto", padding: "0 28px 80px" }}>
      <ScreenHead
        eyebrow={t("discover.eyebrow")}
        title={t("discover.title")}
        sub={t("discover.sub")}
        subMaxWidth={960}
      />

      <div style={{ display: "flex", alignItems: "center", gap: 12, margin: "0 0 14px" }}>
        <Mono style={{ background: "var(--text)", color: "#e9e9e6", border: "1px solid var(--text)" }}>
          <span style={{ color: "#8a897f" }}>$</span> minos discover
        </Mono>
        <span style={{ fontFamily: "var(--mono)", fontSize: 12, color: "var(--text-3)" }}>
          {error ? t("discover.unreachable") : initial ? t("common.scanning") + "…" : t("discover.found", { n: servers.length })}
        </span>
        <RefreshButton onClick={reload} loading={loading} size="lg" label={t("common.rescan")} title="Re-run minos discover" style={{ marginLeft: "auto" }} />
      </div>

      {error ? (
        <ErrorState onRetry={reload} />
      ) : initial ? (
        <Card pad={0}><Loading label={t("discover.scanningConfigs")} /></Card>
      ) : (
        <Card pad={0} style={{ overflow: "hidden" }}>
          <div style={{
            display: "grid", gridTemplateColumns: "1.1fr 1fr 0.8fr 120px",
            padding: "10px 18px", borderBottom: "1px solid var(--border)",
            fontSize: 11, fontWeight: 600, letterSpacing: "0.05em", color: "var(--text-3)",
            textTransform: "uppercase", fontFamily: "var(--mono)", background: "var(--surface-2)",
          }}>
            <span>{t("dash.col.server")}</span><span>{t("dash.col.launch")}</span><span>{t("dash.col.source")}</span><span>{t("dash.col.lastScan")}</span>
          </div>
          {servers.length === 0 && (
            <div style={{ padding: "28px", textAlign: "center", color: "var(--text-3)", fontSize: 13.5 }}>
              {t("discover.empty")}
            </div>
          )}
          {servers.map((s, i) => (
            <ServerRow key={s.name + i} s={s} sources={sources} last={i === servers.length - 1} onSelect={onSelect} />
          ))}
        </Card>
      )}

      <p style={{ fontSize: 12.5, color: "var(--text-3)", marginTop: 16, display: "flex", gap: 8, alignItems: "center" }}>
        <span style={{ fontFamily: "var(--mono)" }}>↳</span>
        {t("discover.adhoc")}
        <code style={{ fontFamily: "var(--mono)", background: "var(--surface-inset)", padding: "1px 6px", borderRadius: 5, color: "var(--text-2)" }}>minos scan --command npx --arg …</code>
      </p>
    </div>
  );
}

function ServerRow({ s, sources, last, onSelect }) {
  const [hover, setHover] = useState(false);
  const cmdPreview = s.command + " " + s.args.join(" ");
  return (
    <div
      onMouseEnter={() => setHover(true)} onMouseLeave={() => setHover(false)}
      onClick={() => onSelect(s)}
      style={{
        display: "grid", gridTemplateColumns: "1.1fr 1fr 0.8fr 120px", alignItems: "center",
        padding: "14px 18px", borderBottom: last ? "none" : "1px solid var(--border-faint)",
        cursor: "pointer", background: hover ? "var(--surface-2)" : "transparent",
        transition: "background 0.12s ease",
      }}>
      <div style={{ display: "flex", alignItems: "center", gap: 11 }}>
        <span style={{
          width: 30, height: 30, borderRadius: 8, flex: "none", background: "var(--surface-inset)",
          border: "1px solid var(--border)", display: "flex", alignItems: "center", justifyContent: "center",
          fontFamily: "var(--mono)", fontSize: 13, fontWeight: 700, color: "var(--text-2)",
        }}>{s.name[0].toUpperCase()}</span>
        <div>
          <div style={{ fontWeight: 600, fontSize: 14 }}>{s.name}</div>
          <div style={{ fontSize: 11.5, color: "var(--text-faint)", fontFamily: "var(--mono)" }}>{s.transport}</div>
        </div>
      </div>
      <div style={{
        fontFamily: "var(--mono)", fontSize: 12, color: "var(--text-3)", whiteSpace: "nowrap",
        overflow: "hidden", textOverflow: "ellipsis", paddingRight: 14,
      }} title={cmdPreview}>
        <span style={{ color: "var(--text-2)" }}>{s.command}</span> {s.args.join(" ")}
      </div>
      <div style={{ fontSize: 12.5, color: "var(--text-2)" }}>{sources[s.source] || s.source}</div>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 8 }}>
        {s.lastScan
          ? <VerdictPill verdict={s.lastScan.verdict} />
          : <span style={{ fontSize: 12, color: "var(--text-faint)", fontFamily: "var(--mono)" }}>never</span>}
        <span style={{
          fontSize: 16, color: "var(--text-3)", transform: hover ? "translateX(2px)" : "none",
          transition: "transform 0.14s ease", opacity: hover ? 1 : 0.4,
        }}>→</span>
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════
// CONFIGURE
// ═══════════════════════════════════════════════════════════════════════════
const PROFILES = [
  { id: "scan", name: "Full scan", desc: "Static source analysis + sandboxed runtime fuzzing. The complete pre-deploy gate.", risks: "R1–R6", time: "~6–10 min", reco: true },
  { id: "quick", name: "Quick scan", desc: "Fast pass — R1, R3 and R5 only. Good for tight CI loops.", risks: "R1·R3·R5", time: "~2 min" },
  { id: "static", name: "Static only", desc: "Source, manifest and schema scanners. No Docker, no execution.", risks: "R1–R6", time: "~30 sec" },
  { id: "dynamic", name: "Dynamic only", desc: "Sandboxed runtime payloads, skips the static scanners.", risks: "R1–R6", time: "~5–8 min" },
];

export function ConfigureScreen({ server, onBack, onLaunch }) {
  const [profile, setProfile] = useState("scan");
  const [docker, setDocker] = useState(true);
  const [budget, setBudget] = useState("");        // scan timeout (s); "" = profile default
  const budgetActive = profile !== "static" && budget !== "" && Number(budget) > 0;
  const cmd = server.command + " " + server.args.join(" ");
  return (
    <div className="fade-up" style={{ maxWidth: "var(--maxw)", margin: "0 auto", padding: "0 28px 80px" }}>
      <button onClick={onBack} className="focusable" style={{
        background: "none", border: "none", color: "var(--text-3)", fontSize: 13, fontWeight: 500,
        padding: "4px 0", marginBottom: 6, display: "inline-flex", alignItems: "center", gap: 6,
      }}>← {t("configure.allServers")}</button>

      <ScreenHead
        eyebrow={t("configure.eyebrow")}
        title={<span>{t("step.scan")} <span style={{ fontFamily: "var(--mono)" }}>{server.name}</span></span>}
        sub={null}
      />

      {/* target card */}
      <Card pad="16px 18px" style={{ marginBottom: 22 }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", gap: 16, flexWrap: "wrap" }}>
          <div>
            <div style={{ fontSize: 11, fontWeight: 600, letterSpacing: "0.05em", color: "var(--text-3)", textTransform: "uppercase", marginBottom: 7, fontFamily: "var(--mono)" }}>{t("configure.target")}</div>
            <Mono copyable style={{ display: "inline-block" }}>{cmd}</Mono>
          </div>
          <div style={{ display: "flex", gap: 24 }}>
            <Meta label={t("configure.source")} value={server.source} />
            <Meta label={t("configure.transport")} value={server.transport} />
          </div>
        </div>
      </Card>

      <SectionLabel>{t("configure.profile")}</SectionLabel>
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 14, marginBottom: 26 }}>
        {PROFILES.map((p) => (
          <ProfileCard key={p.id} p={p} active={profile === p.id} onClick={() => setProfile(p.id)} />
        ))}
      </div>

      <SectionLabel>{t("configure.sandbox")}</SectionLabel>
      <Card pad="4px 18px" style={{ marginBottom: 26 }}>
        <ToggleRow
          label={t("configure.sandboxLabel")}
          sub={t("configure.sandboxSub")}
          value={docker} onChange={setDocker}
          disabled={profile === "static"}
        />
      </Card>

      <SectionLabel>{t("configure.budget")}</SectionLabel>
      <Card pad="14px 18px" style={{ marginBottom: 26 }}>
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 16, flexWrap: "wrap" }}>
          <div style={{ flex: 1, minWidth: 240 }}>
            <div style={{ fontSize: 13.5, fontWeight: 600, color: "var(--text)" }}>{t("configure.budgetLabel")}</div>
            <div style={{ fontSize: 12.5, color: "var(--text-3)", marginTop: 4, lineHeight: 1.5, maxWidth: 560 }}>{t("configure.budgetSub")}</div>
          </div>
          <div style={{ display: "inline-flex", alignItems: "center", gap: 8, flex: "none" }}>
            <input
              type="number" min="30" step="30" value={budget}
              onChange={(e) => setBudget(e.target.value)}
              placeholder={t("configure.budgetDefault")} disabled={profile === "static"}
              className="focusable"
              style={{
                width: 110, padding: "8px 11px", fontSize: 13.5, fontFamily: "var(--mono)", color: "var(--text)",
                background: "var(--surface)", border: "1px solid var(--border-strong)", borderRadius: 8,
                opacity: profile === "static" ? 0.45 : 1,
              }}
            />
            <span style={{ fontSize: 12.5, color: "var(--text-3)" }}>{t("configure.budgetUnit")}</span>
          </div>
        </div>
      </Card>

      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 16, flexWrap: "wrap" }}>
        <Mono style={{ flex: 1, minWidth: 260, background: "var(--text)", color: "#e9e9e6", border: "1px solid var(--text)" }}>
          <span style={{ color: "#8a897f" }}>$</span> minos {profile} --target {server.name}{profile !== "static" && !docker ? " --no-docker" : ""}{budgetActive ? ` --timeout ${budget}` : ""}
        </Mono>
        <Button size="lg" onClick={() => onLaunch(profile, docker, budgetActive ? Number(budget) : null)} icon={<span style={{ fontSize: 15 }}>▶</span>}>
          {t("configure.launch")}
        </Button>
      </div>
    </div>
  );
}

function ProfileCard({ p, active, onClick }) {
  const [hover, setHover] = useState(false);
  return (
    <div onClick={onClick} onMouseEnter={() => setHover(true)} onMouseLeave={() => setHover(false)}
      className="focusable" tabIndex={0}
      style={{
        position: "relative", padding: "16px 17px", borderRadius: "var(--r-lg)", cursor: "pointer",
        background: active ? "var(--surface)" : "var(--surface-2)",
        border: `1.5px solid ${active ? "var(--accent)" : (hover ? "var(--border-strong)" : "var(--border)")}`,
        boxShadow: active ? "var(--shadow-md)" : "none", transition: "all 0.15s ease",
      }}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 8 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 9 }}>
          <span style={{
            width: 16, height: 16, borderRadius: 999, flex: "none",
            border: `1.5px solid ${active ? "var(--accent)" : "var(--border-strong)"}`,
            display: "flex", alignItems: "center", justifyContent: "center",
          }}>
            {active && <span style={{ width: 8, height: 8, borderRadius: 999, background: "var(--accent)" }} />}
          </span>
          <span style={{ fontWeight: 600, fontSize: 14.5 }}>{t(`profile.${p.id}.name`)}</span>
          {p.reco && <span style={{
            fontSize: 10, fontWeight: 600, letterSpacing: "0.04em", color: "var(--green)",
            background: "var(--green-bg)", border: "1px solid var(--green-border)", padding: "1px 6px",
            borderRadius: 5, fontFamily: "var(--mono)",
          }}>{t("configure.recommended")}</span>}
        </div>
      </div>
      <p style={{ margin: "0 0 12px", fontSize: 12.8, color: "var(--text-2)", lineHeight: 1.5 }}>{t(`profile.${p.id}.desc`)}</p>
      <div style={{ display: "flex", gap: 16, fontFamily: "var(--mono)", fontSize: 11.5, color: "var(--text-3)" }}>
        <span><span style={{ color: "var(--text-faint)" }}>risks </span>{p.risks}</span>
        <span><span style={{ color: "var(--text-faint)" }}>est </span>{p.time}</span>
      </div>
    </div>
  );
}

function ToggleRow({ label, sub, value, onChange, disabled }) {
  return (
    <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 20, padding: "13px 0", opacity: disabled ? 0.5 : 1 }}>
      <div>
        <div style={{ fontWeight: 600, fontSize: 13.5 }}>{label}</div>
        {sub && <div style={{ fontSize: 12.5, color: "var(--text-3)", marginTop: 3, lineHeight: 1.5, maxWidth: 560 }}>{sub}</div>}
      </div>
      <button
        onClick={() => !disabled && onChange(!value)} disabled={disabled} className="focusable"
        style={{
          width: 42, height: 24, borderRadius: 999, flex: "none", position: "relative",
          background: value && !disabled ? "var(--accent)" : "var(--border-strong)",
          border: "none", transition: "background 0.16s ease", cursor: disabled ? "not-allowed" : "pointer",
        }}>
        <span style={{
          position: "absolute", top: 3, left: value ? 21 : 3, width: 18, height: 18, borderRadius: 999,
          background: "#fff", boxShadow: "var(--shadow-sm)", transition: "left 0.16s cubic-bezier(.3,.7,.3,1)",
        }} />
      </button>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════
// LIVE PROGRESS  — real minos CLI execution via SSE
//   Structured step view (default) + collapsible raw output.
// ═══════════════════════════════════════════════════════════════════════════

const ANSI_RE = /\x1b\[[0-9;]*m/g;

// Parse a raw structlog line → { eventName, rest }. minos ConsoleRenderer emits
// "[info     ] event.name   key=val key=val ..." (optionally timestamp-prefixed).
function parseMinos(raw) {
  const clean = raw.replace(ANSI_RE, "").trim();
  const m = clean.match(/^(?:\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\s+)?\[(\w+)\s*\]\s+(\S+)\s*(.*)$/);
  if (m) return { level: m[1], eventName: m[2], rest: (m[3] || "").trim(), clean };
  return { level: "info", eventName: "", rest: clean, clean };
}

// key=val pairs from a structlog rest string (handles 'quoted' and [list] values).
function parseKV(rest) {
  const out = {};
  for (const m of (rest || "").matchAll(/(\w+)=('[^']*'|\[[^\]]*\]|[^\s]+)/g)) {
    out[m[1]] = m[2].replace(/^'|'$/g, "");
  }
  return out;
}

// Map a minos event name → a friendly step. `key` is an i18n key; `keyLocal` is
// the wording used when the scan runs without Docker (no real sandbox).
const STEP_DEFS = [
  { pat: /^static\.tarball/,            key: "progress.step.tarball",    phase: "static" },
  { pat: /^static\.snapshot/,           key: "progress.step.snapshot",   phase: "static" },
  { pat: /^static\.semgrep/,            key: "progress.step.semgrep",    phase: "static" },
  { pat: /^static\.(manifest|description|schema)/, key: "progress.step.scanners", phase: "static" },
  { pat: /^static\.findings/,           key: "progress.step.staticDone", phase: "static" },
  { pat: /^orchestrator\.collection/,   key: "progress.step.dynStart",   phase: "dynamic" },
  { pat: /^honeypot/,                    key: "progress.step.honeypot",   phase: "dynamic" },
  { pat: /^sandbox\.runtime_resolved/,  key: "progress.step.runtime",    keyLocal: "progress.step.runtimeLocal", phase: "dynamic" },
  { pat: /^sandbox\.preflight/,         key: "progress.step.preflight",  keyLocal: "progress.step.preflightLocal", phase: "dynamic" },
  { pat: /^sandbox\.bootstrap\.start/,  key: "progress.step.imgBuild",   phase: "dynamic" },
  { pat: /^sandbox\.bootstrap\.done/,   key: "progress.step.imgReady",   phase: "dynamic" },
  { pat: /^sandbox\.(start|boot)/,      key: "progress.step.boot",       keyLocal: "progress.step.bootLocal", phase: "dynamic" },
  { pat: /^sandbox\.ready/,             key: "progress.step.ready",      phase: "dynamic" },
  { pat: /^(sandbox\.(crash|killed)|.*server_crash)/, key: "progress.step.crash", phase: "dynamic", status: "crash" },
  { pat: /^sandbox\.restart/,           key: "progress.step.restart",    keyLocal: "progress.step.restartLocal", phase: "dynamic" },
  { pat: /(sequence_timeout|client_timeout)/, key: "progress.step.timeout", phase: "dynamic", status: "timeout" },
  { pat: /^(test\.|sequencer|payload)/, key: "progress.step.testseq",    phase: "dynamic" },
  { pat: /^scanner\./,                   key: "progress.step.analyse",    phase: "dynamic" },
  { pat: /^(scorer|scoring|verdict)/,   key: "progress.step.scoring",    phase: "analysis" },
  { pat: /^(exporter|report)/,          key: "progress.step.report",     phase: "analysis" },
];

function eventToStep(eventName) {
  if (!eventName) return null;
  return STEP_DEFS.find((d) => d.pat.test(eventName)) || null;
}

// Concise detail string per event type (values stay technical; words localized).
function formatDetail(eventName, rest) {
  const kv = parseKV(rest);
  if (eventName.startsWith("static.tarball"))   return [kv.name, kv.version && `v${kv.version}`].filter(Boolean).join(" · ");
  if (eventName.startsWith("static.snapshot"))  return [kv.coverage && `coverage=${kv.coverage}`, kv.version && `v${kv.version}`].filter(Boolean).join(" · ");
  if (eventName.startsWith("static.findings")) {
    if (kv.findings != null && kv.tools != null) return t("progress.detail.findingsTools", { f: kv.findings, t: kv.tools });
    if (kv.findings != null) return t("progress.detail.findings", { n: kv.findings });
    return "";
  }
  if (eventName.startsWith("static.semgrep"))   return kv.findings != null ? t("progress.detail.findings", { n: kv.findings }) : "";
  if (eventName.startsWith("orchestrator"))     return kv.session_id ? kv.session_id.slice(0, 22) + "…" : "";
  if (eventName.startsWith("honeypot"))         return kv.files ? t("progress.detail.decoy", { n: kv.files }) : "";
  if (eventName.startsWith("sandbox.runtime"))  return kv.image || "";
  if (eventName.startsWith("sandbox.preflight")) return [kv.package, kv.version && `v${kv.version}`].filter(Boolean).join(" · ");
  if (eventName.startsWith("sandbox.bootstrap")) return kv.base_image || kv.image || "";
  if (/timeout/.test(eventName))                return kv.sequence || kv.tool || "";
  if (/crash|killed/.test(eventName))           return kv.sequence || kv.reason || "";
  return "";
}

// Phase ids shown in the rail, by profile.
function _phaseIdsFor(profile) {
  return profile === "static" ? ["static", "analysis"]
    : profile === "dynamic" ? ["dynamic", "analysis"]
    : ["static", "dynamic", "analysis"];
}

// Pure reduction of the minos stderr lines into structured step rows + the
// current phase. `finalStatus` (when the scan ended) appends a completion row.
// This replaces the old incremental handleLine so the SSE stream can live in
// App (one per concurrent scan) and ProgressScreen just renders from props.
function buildSteps(lines, profile, noDocker, finalStatus, sessionId) {
  const phaseIds = _phaseIdsFor(profile);
  let steps = [];
  let phase = phaseIds[0];
  for (const rawLine of lines) {
    const { eventName, rest } = parseMinos(rawLine);
    const def = eventToStep(eventName);
    if (!def) continue;
    if (phaseIds.includes(def.phase)) phase = def.phase;
    const detail = formatDetail(eventName, rest);
    const labelKey = noDocker && def.keyLocal ? def.keyLocal : def.key;
    const marked = steps.length ? [...steps.slice(0, -1), { ...steps[steps.length - 1], done: true }] : steps;
    const last = marked[marked.length - 1];
    if (last && last.labelKey === labelKey && !def.status) {
      steps = [...marked.slice(0, -1), { ...last, detail: detail || last.detail, done: false }];
    } else {
      steps = [...marked, { labelKey, phase: def.phase, detail, status: def.status || null, done: false }];
    }
  }
  if (finalStatus) {
    const ok = finalStatus === "done" && !!sessionId;
    steps = steps.map((s) => ({ ...s, done: true }));
    steps.push({
      labelKey: ok ? "progress.complete" : sessionId ? "progress.finishedErrors" : "progress.failedNoReport",
      phase: "analysis", detail: sessionId || "", status: ok ? "ok" : "crash", done: true,
    });
  }
  return { steps, phase };
}

// Renderer for ONE scan. The scan object (incl. live `lines` + `status`) is
// owned/streamed by App so this stays a pure view that survives navigation and
// works for any of several concurrent scans.
export function ProgressScreen({ scan, onBack, onViewResults, onBackToList }) {
  const server = scan.server;
  const scanId = scan.id;
  const profile = (server && server.profile) || "scan";
  const noDocker = server && server.docker === false;
  const phaseIds = _phaseIdsFor(profile);

  const [rawOpen, setRawOpen] = useState(false);
  const [elapsed, setElapsed] = useState(Math.max(0, (Date.now() - scan.startedAt) / 1000));
  const rawRef = useRef(null);

  const lines = scan.lines || [];
  const status = scan.status || "running";
  const done = status !== "running";
  const scanError = scan.error || null;
  const hasSession = !!scan.sessionId;

  const { steps, phase } = useMemo(
    () => buildSteps(lines, profile, noDocker, done ? status : null, scan.sessionId),
    [scan.key, lines, status, scan.sessionId, profile, noDocker],
  );
  const rawLines = useMemo(
    () => lines.map((l) => l.replace(ANSI_RE, "").trim()).filter(Boolean),
    [lines],
  );

  // Auto-scroll raw log when open
  useEffect(() => {
    if (rawOpen && rawRef.current) rawRef.current.scrollTop = rawRef.current.scrollHeight;
  }, [rawLines, rawOpen]);

  useEffect(() => {
    if (done) return undefined;
    const i = setInterval(() => setElapsed((Date.now() - scan.startedAt) / 1000), 250);
    return () => clearInterval(i);
  }, [done, scan.startedAt]);

  const phaseLabel = (id) =>
    id === "dynamic" && noDocker ? t("progress.phase.dynamicLocal") : t(`progress.phase.${id}`);
  const phases = phaseIds.map((id) => ({ id, label: phaseLabel(id) }));
  const curIdx = phaseIds.indexOf(phase);
  const running = !done && !scanError;
  const remaining = scan.etaSec != null ? Math.max(0, scan.etaSec - elapsed) : null;

  return (
    <div className="fade" style={{ maxWidth: 760, margin: "0 auto", padding: "0 28px 80px" }}>
      <ScreenHead
        eyebrow={t("progress.eyebrow")}
        title={<span>{t("progress.scanning")} <span style={{ fontFamily: "var(--mono)" }}>{server.name}</span></span>}
        sub={null}
      />

      {/* phase rail */}
      <div style={{ display: "flex", gap: 10, marginBottom: 22 }}>
        {phases.map((ph, i) => {
          const isDone = done ? true : i < curIdx;
          const isActive = !done && i === curIdx;
          return (
            <div key={ph.id} style={{ flex: 1 }}>
              <div style={{ height: 4, borderRadius: 999, background: "var(--surface-inset)", overflow: "hidden", marginBottom: 7 }}>
                <div style={{
                  height: "100%", borderRadius: 999,
                  width: isDone ? "100%" : isActive ? "60%" : "0%",
                  background: isDone ? "var(--green)" : "var(--accent)",
                  transition: "width 0.6s ease",
                }} />
              </div>
              <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                <span style={{ fontSize: 12, fontWeight: 600, color: isActive || isDone ? "var(--text)" : "var(--text-faint)" }}>
                  {ph.label}
                </span>
                {isActive && running && <Spinner size={11} />}
                {isDone && <span style={{ color: "var(--green)", fontSize: 13 }}>✓</span>}
              </div>
            </div>
          );
        })}
      </div>

      {/* error banner */}
      {scanError && (
        <Card pad="18px 22px" style={{ borderColor: "var(--red-border)", background: "var(--red-bg)", marginBottom: 16 }}>
          <div style={{ fontWeight: 600, color: "var(--red)", marginBottom: 4 }}>{t("progress.failedStart")}</div>
          <div style={{ fontFamily: "var(--mono)", fontSize: 12.5, color: "var(--text-2)" }}>{scanError}</div>
        </Card>
      )}

      {/* starting state */}
      {!scanId && !scanError && (
        <Card pad={0}>
          <div style={{ padding: "40px 24px", display: "flex", justifyContent: "center", alignItems: "center", gap: 12, fontFamily: "var(--mono)", fontSize: 13, color: "var(--text-3)" }}>
            <Spinner size={14} /> {t("progress.starting")}
          </div>
        </Card>
      )}

      {/* structured step log + raw toggle */}
      {scanId && (
        <Card pad={0} style={{ overflow: "hidden" }}>
          <div style={{
            display: "flex", alignItems: "center", justifyContent: "space-between",
            padding: "11px 16px", borderBottom: "1px solid var(--border)", background: "var(--surface-2)",
          }}>
            <span style={{ fontFamily: "var(--mono)", fontSize: 12, color: "var(--text-3)", display: "flex", alignItems: "center", gap: 8 }}>
              <span style={{
                width: 7, height: 7, borderRadius: 999, flex: "none",
                background: done ? "var(--green)" : scanError ? "var(--red)" : "var(--orange)",
                animation: running ? "mn-pulse 1.2s infinite" : "none",
              }} />
              {scanId.slice(0, 28)}
            </span>
            <span style={{ fontFamily: "var(--mono)", fontSize: 12, color: "var(--text-3)", display: "flex", alignItems: "center", gap: 10 }}>
              {running && remaining != null && (
                <span style={{ color: "var(--text-faint)" }}>
                  {remaining > 0 ? t("progress.eta", { t: fmtDur(remaining) }) : t("progress.etaOver")}
                </span>
              )}
              <span className="tnum">{elapsed.toFixed(0)}s</span>
            </span>
          </div>

          {/* steps */}
          <div style={{ padding: "8px 0", minHeight: 80 }}>
            {steps.length === 0 && (
              <div style={{ padding: "16px 18px", fontFamily: "var(--mono)", fontSize: 12, color: "var(--text-faint)" }}>
                {t("progress.waiting")}
              </div>
            )}
            {steps.map((step, i) => <StepRow key={i} step={step} isLast={i === steps.length - 1} running={running} />)}
          </div>

          {/* raw output toggle */}
          <div style={{ borderTop: "1px solid var(--border)" }}>
            <button onClick={() => setRawOpen((o) => !o)} style={{
              display: "flex", alignItems: "center", justifyContent: "space-between", width: "100%",
              padding: "10px 16px", background: "var(--surface-2)", border: "none", cursor: "pointer",
              fontFamily: "var(--mono)", fontSize: 11.5, color: "var(--text-3)",
            }}>
              <span style={{ display: "flex", alignItems: "center", gap: 7 }}>
                <span style={{ transform: rawOpen ? "rotate(90deg)" : "none", transition: "transform 0.15s ease", display: "inline-block" }}>›</span>
                {t("progress.rawOutput")}
              </span>
              <span className="tnum">{rawLines.length} lines</span>
            </button>
            {rawOpen && (
              <div ref={rawRef} className="scroll fade" style={{ maxHeight: 280, overflowY: "auto", background: "#1a1a18", padding: "8px 0" }}>
                {rawLines.map((line, i) => (
                  <div key={i} style={{ padding: "2px 16px", fontFamily: "var(--mono)", fontSize: 11.5, color: "#9ca3af", lineHeight: 1.65, whiteSpace: "pre-wrap", wordBreak: "break-all" }}>{line}</div>
                ))}
              </div>
            )}
          </div>
        </Card>
      )}

      <div style={{ display: "flex", justifyContent: "center", gap: 12, marginTop: 18, flexWrap: "wrap", alignItems: "center" }}>
        {onBackToList && (
          <Button variant="ghost" size="md" onClick={onBackToList}>{t("active.backToList")}</Button>
        )}
        {done && !hasSession && (
          <Button variant="secondary" size="md" onClick={onBack}>{t("progress.back")}</Button>
        )}
        {!done && !scanError && (
          <span style={{ fontSize: 12.5, color: "var(--text-faint)", fontFamily: "var(--mono)" }}>
            {!scanId ? t("progress.startingShort") : t("progress.running")}
          </span>
        )}
        {done && !hasSession && onViewResults && (
          <Button variant="ghost" size="md" onClick={onViewResults}>{t("progress.viewResults")}</Button>
        )}
      </div>
    </div>
  );
}

// List of concurrently-running scans (shown when more than one is active).
// Clicking a row opens that scan's ProgressScreen.
export function ActiveScansList({ scans, onOpen }) {
  return (
    <div className="fade-up" style={{ maxWidth: 760, margin: "0 auto", padding: "0 28px 80px" }}>
      <ScreenHead
        eyebrow={t("progress.eyebrow")}
        title={t("active.title")}
        sub={t("active.sub", { n: scans.length })}
      />
      <div style={{ display: "grid", gap: 10 }}>
        {scans.map((s) => <ActiveScanRow key={s.key} scan={s} onOpen={() => onOpen(s.key)} />)}
      </div>
    </div>
  );
}

function ActiveScanRow({ scan, onOpen }) {
  const [elapsed, setElapsed] = useState(Math.max(0, (Date.now() - scan.startedAt) / 1000));
  useEffect(() => {
    if (scan.status !== "running") return undefined;
    const i = setInterval(() => setElapsed((Date.now() - scan.startedAt) / 1000), 1000);
    return () => clearInterval(i);
  }, [scan.status, scan.startedAt]);
  const running = scan.status === "running";
  const profile = (scan.server && scan.server.profile) || "scan";
  return (
    <Card pad={0} hover onClick={onOpen} style={{ cursor: "pointer" }}>
      <div style={{ display: "flex", alignItems: "center", gap: 14, padding: "15px 18px" }}>
        <span style={{
          width: 8, height: 8, borderRadius: 999, flex: "none",
          background: running ? "var(--orange)" : scan.error ? "var(--red)" : "var(--green)",
          animation: running ? "mn-pulse 1.2s infinite" : "none",
        }} />
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ fontSize: 14.5, fontWeight: 600, fontFamily: "var(--mono)", letterSpacing: "-0.01em" }}>{scan.server?.name || scan.server?.command}</div>
          <div style={{ fontSize: 12, color: "var(--text-3)", marginTop: 3, fontFamily: "var(--mono)" }}>
            {profile} · {running ? t("active.running") : scan.error ? t("active.failed") : t("active.done")}
          </div>
        </div>
        <span className="tnum" style={{ fontFamily: "var(--mono)", fontSize: 12.5, color: "var(--text-3)" }}>{elapsed.toFixed(0)}s</span>
        <span style={{ fontSize: 14, color: "var(--text-faint)" }}>›</span>
      </div>
    </Card>
  );
}

// Single structured step row.
function StepRow({ step, isLast, running }) {
  const { labelKey, detail, status } = step;
  const label = t(labelKey);
  const isCrash = status === "crash";
  const isTimeout = status === "timeout";
  const isActive = isLast && running && !isCrash && !isTimeout && status !== "ok";
  return (
    <div className={isLast ? "fade" : ""} style={{ display: "flex", gap: 12, padding: "8px 16px", alignItems: "flex-start" }}>
      <span style={{ width: 16, flex: "none", marginTop: 2, textAlign: "center" }}>
        {isActive
          ? <Spinner size={12} />
          : isCrash
          ? <span style={{ color: "var(--red)", fontWeight: 700, fontSize: 13 }}>✕</span>
          : isTimeout
          ? <span style={{ color: "var(--amber)", fontWeight: 700 }}>◷</span>
          : <span style={{ color: "var(--green)", fontSize: 13 }}>✓</span>}
      </span>
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 9, flexWrap: "wrap" }}>
          <span style={{ fontSize: 13, fontWeight: isActive ? 600 : 500, color: isActive ? "var(--text)" : "var(--text-2)" }}>{label}</span>
          {isCrash && <span style={{ fontFamily: "var(--mono)", fontSize: 10, fontWeight: 600, color: "var(--red)", textTransform: "uppercase", letterSpacing: "0.04em" }}>CRASH</span>}
          {isTimeout && <span style={{ fontFamily: "var(--mono)", fontSize: 10, fontWeight: 600, color: "var(--amber)", textTransform: "uppercase", letterSpacing: "0.04em" }}>TIMEOUT</span>}
        </div>
        {detail && (
          <div style={{ fontFamily: "var(--mono)", fontSize: 11.5, color: "var(--text-faint)", marginTop: 2, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{detail}</div>
        )}
      </div>
    </div>
  );
}
