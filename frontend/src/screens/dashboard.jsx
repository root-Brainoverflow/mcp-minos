// dashboard.jsx — Overview / Home. The landing surface.
import React, { useState } from "react";
import { Card, Button, VerdictPill, ScoreBar, scoreColor, SEV_COLOR, Loading, ErrorState } from "../components/ui.jsx";
import { MINOS_DATA } from "../data.js";
import { fetchOverview, fetchRecentSessions, fetchServers } from "../api.js";
import { useApi } from "../hooks.js";
import { t } from "../i18n.js";
import { riskName, riskFull } from "../ruleset_ko.js";

// relative-time helper
function relTime(iso) {
  const then = new Date(iso).getTime();
  const days = Math.round((Date.now() - then) / 86400000);
  if (days <= 0) return "today";
  if (days === 1) return "yesterday";
  if (days < 7) return `${days}d ago`;
  if (days < 30) return `${Math.round(days / 7)}w ago`;
  return `${Math.round(days / 30)}mo ago`;
}

export function DashboardScreen({ onDiscover, onOpenSession, onSelectServer }) {
  const ov = useApi(fetchOverview);
  const rec = useApi(fetchRecentSessions);
  const srv = useApi(fetchServers);
  const reload = () => { ov.reload(); rec.reload(); srv.reload(); };

  const header = (
    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-end", gap: 18, padding: "10px 0 26px", flexWrap: "wrap" }}>
      <div>
        <div style={{ fontFamily: "var(--mono)", fontSize: 11.5, fontWeight: 600, letterSpacing: "0.08em", color: "var(--text-3)", marginBottom: 12 }}>{t("dash.eyebrow")}</div>
        <h1 style={{ margin: 0, fontSize: 28, fontWeight: 700, letterSpacing: "-0.02em", lineHeight: 1.15 }}>MCP-Minos</h1>
        <p style={{ margin: "10px 0 0", fontSize: 14.5, color: "var(--text-2)", lineHeight: 1.55, maxWidth: 730 }}>
          {t("dash.sub")}
        </p>
      </div>
      <div style={{ display: "flex", gap: 10, alignItems: "center" }}>
        <Button variant="secondary" size="md" onClick={onDiscover} icon={<span style={{ fontSize: 13 }}>⊞</span>}>{t("common.discover")}</Button>
        <Button variant="primary" size="md" onClick={onDiscover} icon={<span style={{ fontSize: 13 }}>▶</span>}>{t("common.newScan")}</Button>
      </div>
    </div>
  );

  if (ov.error) {
    return (
      <div className="fade-up" style={{ maxWidth: "var(--maxw)", margin: "0 auto", padding: "0 28px 90px" }}>
        {header}<ErrorState onRetry={reload} />
      </div>
    );
  }
  if (ov.loading && !ov.data) {
    return (
      <div className="fade-up" style={{ maxWidth: "var(--maxw)", margin: "0 auto", padding: "0 28px 90px" }}>
        {header}<Loading label={t("dash.eyebrow")} />
      </div>
    );
  }

  const O = ov.data;
  const sessions = rec.data || [];
  const servers = srv.data || [];

  return (
    <div className="fade-up" style={{ maxWidth: "var(--maxw)", margin: "0 auto", padding: "0 28px 90px" }}>

      {/* 1 — Header */}
      {header}

      {/* 2 — KPI row */}
      <div className="kpi-row" style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 14, marginBottom: 16 }}>
        <StatCard label={t("dash.kpi.servers")} value={O.servers_discovered} sub={t("dash.kpi.serversSub", { n: O.clients })} />
        <StatCard label={t("dash.kpi.scans")} value={O.scans_run} sub={t("dash.kpi.scansSub", { n: O.scans_this_week })} />
        <StatCard label={t("dash.kpi.open")} value={O.open_findings} sub={t("dash.kpi.openSub", { n: O.critical_high })} subColor="var(--orange)" />
        <StatCard label={t("dash.kpi.atRisk")} value={O.at_risk} valueColor="var(--red)" sub={t("dash.kpi.atRiskSub")} />
      </div>

      {/* 3 — First row: MCP server list (full width) */}
      <div style={{ marginBottom: 16 }}>
        <McpServerList servers={servers} onSelectServer={onSelectServer} />
      </div>

      {/* 4 — Recent scans + verdict/source breakdown */}
      <div className="two-col" style={{ display: "grid", gridTemplateColumns: "1.6fr 1fr", gap: 16, marginBottom: 16 }}>
        <RecentScans sessions={sessions} onOpenSession={onOpenSession} />
        <div style={{ display: "grid", gap: 16, alignContent: "start" }}>
          <VerdictMix mix={O.verdict_mix} />
          <DiscoveredVia sources={O.sources} />
        </div>
      </div>

      {/* 5 — Fleet risk surface */}
      <FleetRiskSurface scores={O.risk_scores} sessions={sessions} />

      {/* 6 — Extras */}
      <div className="two-col" style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16, marginTop: 16 }}>
        <FindingsBySeverity bySeverity={O.by_severity} staticN={O.static_findings} dynamicN={O.dynamic_findings} />
        <FindingsOverTime data={O.findings_over_time} />
      </div>

    </div>
  );
}

// ── StatCard ─────────────────────────────────────────────────────────────────
function StatCard({ label, value, sub, valueColor, subColor }) {
  return (
    <Card hover pad="var(--row-pad)" style={{ padding: "18px 18px 16px" }}>
      <div style={{ fontFamily: "var(--mono)", fontSize: 10.5, fontWeight: 600, letterSpacing: "0.06em", color: "var(--text-3)", textTransform: "uppercase", marginBottom: 12 }}>{label}</div>
      <div className="tnum" style={{ fontSize: 34, fontWeight: 700, letterSpacing: "-0.025em", lineHeight: 1, color: valueColor || "var(--text)" }}>{value}</div>
      <div style={{ fontSize: 12, color: subColor || "var(--text-3)", marginTop: 8, fontWeight: subColor ? 600 : 400 }}>{sub}</div>
    </Card>
  );
}

// ── Recent scans table ───────────────────────────────────────────────────────
function RecentScans({ sessions, onOpenSession }) {
  return (
    <Card pad={0} style={{ overflow: "hidden" }}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "16px 18px 13px" }}>
        <h2 style={{ margin: 0, fontSize: 15, fontWeight: 700, letterSpacing: "-0.01em" }}>{t("dash.recent")}</h2>
        <span style={{ fontFamily: "var(--mono)", fontSize: 11.5, color: "var(--text-3)" }}>{t("dash.recentHint")}</span>
      </div>
      <div style={{
        display: "grid", gridTemplateColumns: "1.6fr 1fr 1.4fr 78px", gap: 12,
        padding: "8px 18px", borderTop: "1px solid var(--border)", borderBottom: "1px solid var(--border)",
        background: "var(--surface-2)", fontFamily: "var(--mono)", fontSize: 10, fontWeight: 600,
        letterSpacing: "0.05em", color: "var(--text-faint)", textTransform: "uppercase",
      }}>
        <span>{t("dash.col.server")}</span><span>{t("dash.col.source")}</span><span>{t("dash.col.verdict")}</span><span style={{ textAlign: "right" }}>{t("dash.col.when")}</span>
      </div>
      {sessions.map((s, i) => (
        <ScanRow key={s.session_id} s={s} last={i === sessions.length - 1} onClick={() => onOpenSession(s)} />
      ))}
    </Card>
  );
}

function ScanRow({ s, last, onClick }) {
  const [hover, setHover] = useState(false);
  return (
    <div
      onClick={onClick}
      onMouseEnter={() => setHover(true)} onMouseLeave={() => setHover(false)}
      style={{
        display: "grid", gridTemplateColumns: "1.6fr 1fr 1.4fr 78px", gap: 12, alignItems: "center",
        padding: "13px 18px", borderBottom: last ? "none" : "1px solid var(--border-faint)",
        cursor: "pointer", background: hover ? "var(--surface-2)" : "transparent", transition: "background 0.12s ease",
      }}>
      {/* server */}
      <div style={{ minWidth: 0 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <span style={{ fontFamily: "var(--mono)", fontSize: 13.5, fontWeight: 600 }}>{s.server}</span>
          {s.real && <span title="real session — read from results/ on disk" style={{ fontFamily: "var(--mono)", fontSize: 9, color: "var(--green)", background: "var(--green-bg)", border: "1px solid var(--green-border)", padding: "0px 5px", borderRadius: 4, letterSpacing: "0.03em" }}>REAL</span>}
        </div>
        <div style={{ fontFamily: "var(--mono)", fontSize: 11, color: "var(--text-faint)", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis", marginTop: 2 }}>{s.command}</div>
      </div>
      {/* source */}
      <span style={{ fontSize: 12, color: "var(--text-2)" }}>{MINOS_DATA.SOURCE_LABELS[s.source] || s.source}</span>
      {/* verdict + risk */}
      <div style={{ display: "flex", alignItems: "center", gap: 10, minWidth: 0 }}>
        <VerdictPill verdict={s.verdict} />
        <div style={{ flex: 1, minWidth: 36, display: "flex", alignItems: "center", gap: 7 }}>
          <div style={{ flex: 1, minWidth: 24 }}><ScoreBar value={s.overall_score} animate={false} /></div>
          <span className="tnum" style={{ fontFamily: "var(--mono)", fontSize: 11.5, fontWeight: 600, color: scoreColor(s.overall_score) }}>{s.overall_score.toFixed(2)}</span>
        </div>
      </div>
      {/* when */}
      <div style={{ display: "flex", alignItems: "center", justifyContent: "flex-end", gap: 6 }}>
        <span style={{ fontFamily: "var(--mono)", fontSize: 11.5, color: "var(--text-3)" }}>{relTime(s.at)}</span>
        <span style={{ fontSize: 14, color: "var(--text-3)", opacity: hover ? 1 : 0.35, transform: hover ? "translateX(2px)" : "none", transition: "all 0.14s ease" }}>→</span>
      </div>
    </div>
  );
}

// ── MCP server list (full-width table, mirrors the Discover screen) ──────────
const MCP_COLS = "1.1fr 1fr 0.8fr 130px";

function McpServerList({ servers, onSelectServer }) {
  return (
    <Card pad={0} style={{ overflow: "hidden" }}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "16px 18px 13px" }}>
        <h2 style={{ margin: 0, fontSize: 15, fontWeight: 700, letterSpacing: "-0.01em" }}>{t("dash.mcpServers")}</h2>
        <span style={{ fontFamily: "var(--mono)", fontSize: 11.5, color: "var(--text-3)" }}>{t("dash.discovered", { n: servers.length })}</span>
      </div>
      {/* column header */}
      <div style={{
        display: "grid", gridTemplateColumns: MCP_COLS,
        padding: "10px 18px", borderTop: "1px solid var(--border)", borderBottom: "1px solid var(--border)",
        fontSize: 11, fontWeight: 600, letterSpacing: "0.05em", color: "var(--text-3)",
        textTransform: "uppercase", fontFamily: "var(--mono)", background: "var(--surface-2)",
      }}>
        <span>{t("dash.col.server")}</span><span>{t("dash.col.launch")}</span><span>{t("dash.col.source")}</span><span>{t("dash.col.lastScan")}</span>
      </div>
      {/* scrolls when servers overflow ~5 rows */}
      <div className="scroll" style={{ maxHeight: 348, overflowY: "auto" }}>
        {servers.map((srv, i) => (
          <McpServerRow key={srv.name + i} srv={srv} last={i === servers.length - 1} onClick={() => onSelectServer(srv)} />
        ))}
      </div>
    </Card>
  );
}

function McpServerRow({ srv, last, onClick }) {
  const [hover, setHover] = useState(false);
  const cmdPreview = srv.command + " " + srv.args.join(" ");
  return (
    <div
      onClick={onClick}
      onMouseEnter={() => setHover(true)} onMouseLeave={() => setHover(false)}
      style={{
        display: "grid", gridTemplateColumns: MCP_COLS, alignItems: "center",
        padding: "14px 18px", borderBottom: last ? "none" : "1px solid var(--border-faint)",
        cursor: "pointer", background: hover ? "var(--surface-2)" : "transparent", transition: "background 0.12s ease",
      }}>
      <div style={{ display: "flex", alignItems: "center", gap: 11 }}>
        <span style={{
          width: 30, height: 30, borderRadius: 8, flex: "none", background: "var(--surface-inset)",
          border: "1px solid var(--border)", display: "flex", alignItems: "center", justifyContent: "center",
          fontFamily: "var(--mono)", fontSize: 13, fontWeight: 700, color: "var(--text-2)",
        }}>{srv.name[0].toUpperCase()}</span>
        <div>
          <div style={{ fontWeight: 600, fontSize: 14 }}>{srv.name}</div>
          <div style={{ fontSize: 11.5, color: "var(--text-faint)", fontFamily: "var(--mono)" }}>{srv.transport}</div>
        </div>
      </div>
      <div style={{
        fontFamily: "var(--mono)", fontSize: 12, color: "var(--text-3)", whiteSpace: "nowrap",
        overflow: "hidden", textOverflow: "ellipsis", paddingRight: 14,
      }} title={cmdPreview}>
        <span style={{ color: "var(--text-2)" }}>{srv.command}</span> {srv.args.join(" ")}
      </div>
      <div style={{ fontSize: 12.5, color: "var(--text-2)" }}>{MINOS_DATA.SOURCE_LABELS[srv.source] || srv.source}</div>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 8 }}>
        {srv.lastScan
          ? <VerdictPill verdict={srv.lastScan.verdict} />
          : <span style={{ fontSize: 12, color: "var(--text-faint)", fontFamily: "var(--mono)" }}>never</span>}
        <span style={{
          fontSize: 16, color: "var(--text-3)", transform: hover ? "translateX(2px)" : "none",
          transition: "transform 0.14s ease", opacity: hover ? 1 : 0.4,
        }}>→</span>
      </div>
    </div>
  );
}

// ── Verdict mix ──────────────────────────────────────────────────────────────
function VerdictMix({ mix }) {
  // Preferred display order; render only verdicts actually present so old
  // (APPROVE/CONDITIONAL) and new (PASS/ERROR) sessions both show cleanly.
  const PREFERRED = ["PASS", "APPROVE", "CONDITIONAL", "REJECT", "ERROR", "UNSCANNED"];
  const present = Object.keys(mix).filter((v) => mix[v] > 0);
  const order = [
    ...PREFERRED.filter((v) => present.includes(v)),
    ...present.filter((v) => !PREFERRED.includes(v)),
  ];
  const total = Object.values(mix).reduce((a, b) => a + b, 0);
  return (
    <Card pad="16px 18px 18px">
      <h2 style={{ margin: "0 0 16px", fontSize: 14.5, fontWeight: 700 }}>{t("dash.verdictMix")}</h2>
      <div style={{ display: "grid", gap: 13 }}>
        {order.map((v) => {
          const n = mix[v] || 0;
          const c = VERDICT_COLOR_LOCAL[v] || { fg: "var(--slate)" };
          const pct = total ? (n / total) * 100 : 0;
          return (
            <div key={v} style={{ display: "flex", alignItems: "center", gap: 11 }}>
              <span style={{ width: 8, height: 8, borderRadius: 999, background: c.fg, flex: "none" }} />
              <span style={{ fontSize: 12, fontWeight: 600, color: v === "UNSCANNED" ? "var(--text-3)" : "var(--text-2)", width: 92, fontFamily: "var(--mono)", letterSpacing: "0.01em" }}>{v}</span>
              <div style={{ flex: 1, height: 7, borderRadius: 999, background: "var(--surface-inset)", overflow: "hidden" }}>
                <div style={{ height: "100%", width: `${pct}%`, background: c.fg, borderRadius: 999, opacity: v === "UNSCANNED" ? 0.5 : 1 }} />
              </div>
              <span className="tnum" style={{ fontFamily: "var(--mono)", fontSize: 13, fontWeight: 600, width: 18, textAlign: "right" }}>{n}</span>
            </div>
          );
        })}
      </div>
    </Card>
  );
}
const VERDICT_COLOR_LOCAL = {
  REJECT: { fg: "var(--red)" }, CONDITIONAL: { fg: "var(--amber)" },
  PASS: { fg: "var(--green)" }, ERROR: { fg: "var(--slate)" },
  APPROVE: { fg: "var(--green)" }, UNSCANNED: { fg: "var(--slate)" },
};

// ── Discovered via ───────────────────────────────────────────────────────────
function DiscoveredVia({ sources }) {
  const entries = Object.entries(sources).sort((a, b) => b[1] - a[1]);
  const max = Math.max(...entries.map((e) => e[1]));
  return (
    <Card pad="16px 18px 18px">
      <h2 style={{ margin: "0 0 16px", fontSize: 14.5, fontWeight: 700 }}>{t("dash.discoveredVia")}</h2>
      <div style={{ display: "grid", gap: 13 }}>
        {entries.map(([src, n]) => (
          <div key={src} style={{ display: "flex", alignItems: "center", gap: 11 }}>
            <span style={{ fontSize: 12.5, color: "var(--text-2)", width: 116 }}>{MINOS_DATA.SOURCE_LABELS[src] || src}</span>
            <div style={{ flex: 1, height: 7, borderRadius: 999, background: "var(--surface-inset)", overflow: "hidden" }}>
              <div style={{ height: "100%", width: `${(n / max) * 100}%`, background: "var(--accent)", borderRadius: 999, opacity: 0.85 }} />
            </div>
            <span className="tnum" style={{ fontFamily: "var(--mono)", fontSize: 13, fontWeight: 600, width: 18, textAlign: "right" }}>{n}</span>
          </div>
        ))}
      </div>
    </Card>
  );
}

// ── Fleet risk surface (R1–R6, worst per risk) ───────────────────────────────
function FleetRiskSurface({ scores, sessions }) {
  const D = MINOS_DATA;
  const scanned = sessions.length;
  return (
    <Card pad="6px 22px 14px">
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "16px 0 8px" }}>
        <h2 style={{ margin: 0, fontSize: 15, fontWeight: 700, letterSpacing: "-0.01em" }}>{t("dash.riskSurface")}</h2>
        <span style={{ fontSize: 11.5, color: "var(--text-3)", fontFamily: "var(--mono)" }}>{t("dash.riskSurfaceHint", { n: scanned })}</span>
      </div>
      <div>
        {Object.keys(D.RISK_META).map((code, i) => {
          const meta = D.RISK_META[code];
          const sc = scores[code];
          return (
            <div key={code} style={{
              display: "grid", gridTemplateColumns: "44px 1.4fr 1fr 64px 96px", alignItems: "center", gap: 16,
              padding: "13px 0", borderTop: i === 0 ? "1px solid var(--border)" : "1px solid var(--border-faint)",
            }}>
              <span style={{ fontFamily: "var(--mono)", fontWeight: 700, fontSize: 14, color: sc > 0 ? "var(--text)" : "var(--text-faint)" }}>{code}</span>
              <div>
                <div style={{ fontSize: 13.5, fontWeight: 600, color: sc > 0 ? "var(--text)" : "var(--text-2)" }}>{riskName(code, meta.name)}</div>
                <div style={{ fontSize: 11.5, color: "var(--text-faint)" }}>{riskFull(code, meta.full)}</div>
              </div>
              <ScoreBar value={sc} delay={0.05 * i} />
              <span className="tnum" style={{ fontFamily: "var(--mono)", fontSize: 14, fontWeight: 600, color: scoreColor(sc), textAlign: "right" }}>{sc.toFixed(2)}</span>
              <span style={{ textAlign: "right", fontSize: 11.5, color: "var(--text-3)", fontFamily: "var(--mono)" }}>
                {sc >= 0.75 ? "critical" : sc >= 0.4 ? "elevated" : sc > 0 ? "low" : "clean"}
              </span>
            </div>
          );
        })}
      </div>
    </Card>
  );
}

// ── Findings by severity + static/dynamic split ──────────────────────────────
function FindingsBySeverity({ bySeverity, staticN, dynamicN }) {
  const total = Object.values(bySeverity).reduce((a, b) => a + b, 0);
  const max = Math.max(...Object.values(bySeverity));
  const splitTotal = staticN + dynamicN;
  return (
    <Card pad="16px 20px 20px">
      <div style={{ display: "flex", alignItems: "baseline", justifyContent: "space-between", marginBottom: 16 }}>
        <h2 style={{ margin: 0, fontSize: 14.5, fontWeight: 700 }}>{t("dash.bySeverity")}</h2>
        <span className="tnum" style={{ fontFamily: "var(--mono)", fontSize: 12, color: "var(--text-3)" }}>{t("dash.total", { n: total })}</span>
      </div>
      <div style={{ display: "grid", gap: 11 }}>
        {MINOS_DATA.SEVERITY_ORDER.map((lvl) => {
          const n = bySeverity[lvl] || 0;
          const c = SEV_COLOR[lvl];
          return (
            <div key={lvl} style={{ display: "flex", alignItems: "center", gap: 11 }}>
              <span style={{ fontFamily: "var(--mono)", fontSize: 11, fontWeight: 600, color: c.fg, width: 64, textTransform: "uppercase", letterSpacing: "0.03em" }}>{lvl}</span>
              <div style={{ flex: 1, height: 8, borderRadius: 999, background: "var(--surface-inset)", overflow: "hidden" }}>
                <div style={{ height: "100%", width: `${max ? (n / max) * 100 : 0}%`, background: c.fg, borderRadius: 999 }} />
              </div>
              <span className="tnum" style={{ fontFamily: "var(--mono)", fontSize: 12.5, fontWeight: 600, width: 18, textAlign: "right" }}>{n}</span>
            </div>
          );
        })}
      </div>

      {/* static vs dynamic */}
      <div style={{ marginTop: 20, paddingTop: 16, borderTop: "1px solid var(--border-faint)" }}>
        <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 9, fontFamily: "var(--mono)", fontSize: 11 }}>
          <span style={{ color: "var(--blue)", fontWeight: 600 }}>STATIC {staticN}</span>
          <span style={{ color: "var(--orange)", fontWeight: 600 }}>{dynamicN} DYNAMIC</span>
        </div>
        <div style={{ display: "flex", height: 8, borderRadius: 999, overflow: "hidden", gap: 2 }}>
          <div style={{ width: `${(staticN / splitTotal) * 100}%`, background: "var(--blue)", borderRadius: "999px 3px 3px 999px" }} />
          <div style={{ width: `${(dynamicN / splitTotal) * 100}%`, background: "var(--orange)", borderRadius: "3px 999px 999px 3px" }} />
        </div>
      </div>
    </Card>
  );
}

// ── Findings over time (hand-rolled SVG bars) ────────────────────────────────
function FindingsOverTime({ data }) {
  const max = Math.max(...data);
  const W = 320, H = 96, n = data.length;
  const gap = 10;
  const bw = (W - gap * (n - 1)) / n;
  const trend = data[data.length - 1] - data[0];
  return (
    <Card pad="16px 20px 18px">
      <div style={{ display: "flex", alignItems: "baseline", justifyContent: "space-between", marginBottom: 4 }}>
        <h2 style={{ margin: 0, fontSize: 14.5, fontWeight: 700 }}>{t("dash.overTime")}</h2>
        <span style={{ fontFamily: "var(--mono)", fontSize: 11.5, color: trend > 0 ? "var(--red)" : "var(--green)", fontWeight: 600 }}>
          {trend > 0 ? "▲" : "▼"} {Math.abs(trend)} vs 8w ago
        </span>
      </div>
      <div style={{ fontFamily: "var(--mono)", fontSize: 10.5, color: "var(--text-faint)", marginBottom: 14, letterSpacing: "0.04em" }}>NEW FINDINGS / WEEK · LAST 8 WEEKS</div>
      <svg width="100%" viewBox={`0 0 ${W} ${H + 16}`} preserveAspectRatio="none" style={{ display: "block" }}>
        {data.map((v, i) => {
          const h = max ? (v / max) * H : 0;
          const x = i * (bw + gap);
          const last = i === n - 1;
          return (
            <g key={i}>
              <rect x={x} y={0} width={bw} height={H} rx="3" fill="var(--surface-inset)" />
              <rect x={x} y={H - h} width={bw} height={h} rx="3" fill={last ? "var(--accent)" : "var(--border-strong)"} />
              <text x={x + bw / 2} y={H + 13} textAnchor="middle" fontFamily="var(--mono)" fontSize="8.5" fill="var(--text-faint)">{`w${i + 1}`}</text>
            </g>
          );
        })}
      </svg>
    </Card>
  );
}
