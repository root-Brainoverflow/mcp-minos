// report.jsx — the results dashboard (the centerpiece) + fleet Findings explorer.
import React, { useState, useEffect } from "react";
import {
  SEV_COLOR, VERDICT_COLOR, VERDICT_ICON, scoreColor,
  Button, Card, Donut, ScoreBar, Confidence, Segmented,
  SeverityBadge, RiskTag, PhaseTag, VerdictPill, Mono, Logo, Spinner, RefreshButton, Loading,
} from "../components/ui.jsx";
import { ScreenHead } from "../components/common.jsx";
import { MINOS_DATA } from "../data.js";
import { fetchSessionDetail, fetchFindings } from "../api.js";
import { useApi } from "../hooks.js";
import { t, getLang } from "../i18n.js";
import { riskName, riskFull } from "../ruleset_ko.js";
import { localizeFinding } from "../findings_ko.js";
import { koSummary } from "../summary_ko.js";

const SEV_WEIGHT = { CRITICAL: 0.9, HIGH: 0.7, MEDIUM: 0.45, LOW: 0.2, INFO: 0.1 };
const REASONS = {
  REJECT: "Critical findings reachable from tool input. Do not deploy until the flagged sinks are fixed and the server re-scans clean.",
  CONDITIONAL: "No critical issues, but medium-severity signals remain. Ship only behind the noted mitigations and re-scan once resolved.",
  APPROVE: "No blocking findings. The server cleared the pre-deploy gate; keep scanning on each version bump.",
};
function fmtDate(iso) {
  const d = new Date(iso);
  return d.toISOString().slice(0, 10) + " " + d.toISOString().slice(11, 16) + " UTC";
}

// Resolve the opened session to its full, real report detail. The backend's
// /api/sessions/{id} reads the actual results/ dir; if it's unreachable we
// rebuild an equivalent shape from the bundled sample data so the UI still works.
function _shortId(id) {
  const p = (id || "").split("-");
  return p.slice(0, 2).join("-");
}
function buildFallbackDetail(sid) {
  const D = MINOS_DATA;
  const meta = (D.SCAN_SESSIONS || []).find((s) => s.session_id === sid)
    || (D.SCAN_SESSIONS || []).find((s) => s.real)
    || (D.SCAN_SESSIONS || [])[0] || {};
  let findings = (D.FLEET_FINDINGS || []).filter((f) => f.session_id === meta.session_id);
  if (!findings.length) findings = [...(D.STATIC_FINDINGS || []), ...(D.DYNAMIC_FINDINGS || [])];
  let scores = meta.risk_scores;
  if (!scores) {
    scores = { R1: 0, R2: 0, R3: 0, R4: 0, R5: 0, R6: 0 };
    findings.forEach((f) => { scores[f.risk_type] = Math.max(scores[f.risk_type] || 0, SEV_WEIGHT[f.severity] || 0); });
  }
  const headline = D.SESSION && _shortId(D.SESSION.session_id) === meta.session_id;
  const verdict = meta.verdict || "CONDITIONAL";
  return {
    server: meta.server,
    session: {
      session_id: meta.session_id,
      generated: meta.at ? fmtDate(meta.at) : (D.SESSION ? D.SESSION.generated : ""),
      duration_sec: meta.duration_sec || 0,
      verdict,
      overall_score: meta.overall_score || 0,
      tools_tested: meta.tools_tested || 0,
    },
    risk_scores: scores,
    findings,
    events: headline ? (D.EVENTS || []) : [],
    reason: REASONS[verdict] || VERDICT_REASON,
    summary: composeSummary(meta.server, verdict, meta.overall_score || 0, findings, scores, meta.tools_tested || 0),
  };
}

// Client-side mirror of the backend summary composer (offline fallback only).
const _RISK_NAMES = { R1: "Data Access", R2: "Code Execution", R3: "LLM Manipulation", R4: "Behaviour Drift", R5: "Input Validation", R6: "Service Stability" };
const _RISK_CAUSE = {
  R1: "tools can reach unauthorized data or exfiltrate it",
  R2: "tool input can reach code or command execution",
  R3: "tool descriptions or outputs can manipulate the agent",
  R4: "behaviour changes between environments or over time",
  R5: "tool inputs flow unvalidated into dangerous sinks",
  R6: "the server crashes or stalls under input fuzzing",
};
const _RISK_FIX = {
  R1: "scope the data and credentials the tools can touch",
  R2: "sanitize tool input before it reaches exec/eval sinks",
  R3: "strip untrusted instructions from tool text",
  R4: "remove environment- and time-gated branches",
  R5: "validate and bound every tool input",
  R6: "harden the crashing handlers or run behind a restart supervisor",
};
const _VERDICT_PHRASE = { REJECT: "was rejected for deployment", CONDITIONAL: "passed conditionally", APPROVE: "cleared the pre-deploy gate", UNSCANNED: "has not been fully scanned" };

function composeSummary(server, verdict, score, findings, scores, toolsTested) {
  if (getLang() === "ko") {
    return koSummary(server, verdict, score, findings, scores, toolsTested);
  }

  const n = findings.length;
  const present = [...new Set(findings.map((f) => f.risk_type).filter(Boolean))].sort((a, b) => (scores[b] || 0) - (scores[a] || 0));
  const worst = present[0];
  const topSev = MINOS_DATA.SEVERITY_ORDER.find((s) => findings.some((f) => f.severity === s));
  const fixed = (score || 0).toFixed(2);

  const s1 = `${server} ${_VERDICT_PHRASE[verdict] || "was scanned"} with a risk score of ${fixed}.`;
  let s2;
  if (n === 0) {
    s2 = "No findings surfaced across the six risk types (R1–R6).";
  } else {
    const where = present.length === 1 && worst
      ? `${n > 1 ? "all under" : "under"} ${_RISK_NAMES[worst] || worst} (${worst}) — ${_RISK_CAUSE[worst] || ""}`
      : `spanning ${present.slice(0, 3).map((r) => `${_RISK_NAMES[r] || r} (${r})`).join(", ")}`;
    const reach = toolsTested ? `, seen across ${toolsTested} runtime tool${toolsTested !== 1 ? "s" : ""}` : "";
    s2 = `It has ${n} ${topSev ? topSev.toLowerCase() + "-severity " : ""}finding${n > 1 ? "s" : ""} ${where}${reach}.`;
  }
  let s3;
  if (n === 0 || verdict === "APPROVE") s3 = "No blocking issues — keep scanning on each version bump.";
  else if (verdict === "REJECT") s3 = `Do not deploy until you ${_RISK_FIX[worst] || "fix the flagged issues"} and the server re-scans clean.`;
  else s3 = `Ship only behind mitigations — ${_RISK_FIX[worst] || "address the flagged issues"} — then re-scan.`;
  return `${s1} ${s2} ${s3}`;
}

export function ResultsScreen({ heroStyle, onNewScan, session }) {
  const sid = session && session.session_id;
  const [detail, setDetail] = useState(null);
  const [loading, setLoading] = useState(true);
  const [printing, setPrinting] = useState(false);

  useEffect(() => {
    let alive = true;
    setLoading(true);
    fetchSessionDetail(sid).then((d) => {
      if (!alive) return;
      setDetail(d && d.session ? d : buildFallbackDetail(sid));
      setLoading(false);
    });
    return () => { alive = false; };
  }, [sid]);

  // Export to PDF via the browser's print → "Save as PDF". `printing` expands
  // every finding so the PDF is complete; print CSS hides the app chrome.
  // NOTE: this hook must stay ABOVE the early return below — placing it after a
  // conditional return breaks the Rules of Hooks and crashes the whole app.
  const exportPdf = () => setPrinting(true);
  useEffect(() => {
    if (!printing) return undefined;
    const prevTitle = document.title;
    document.title = `minos-report-${(detail && detail.server) || ""}-${sid || ""}`;
    const done = () => { document.title = prevTitle; setPrinting(false); };
    const raf = requestAnimationFrame(() => {
      window.addEventListener("afterprint", done, { once: true });
      window.print();
      // Fallback for browsers that don't fire afterprint.
      setTimeout(() => { window.removeEventListener("afterprint", done); done(); }, 800);
    });
    return () => cancelAnimationFrame(raf);
  }, [printing, sid]);

  if (loading || !detail) {
    return (
      <div className="fade" style={{ maxWidth: "var(--maxw)", margin: "0 auto", padding: "70px 28px", display: "flex", justifyContent: "center" }}>
        <span style={{ display: "inline-flex", alignItems: "center", gap: 10, color: "var(--text-3)", fontFamily: "var(--mono)", fontSize: 13 }}>
          <Spinner size={15} /> loading report…
        </span>
      </div>
    );
  }

  const findings = detail.findings || [];
  const sevCount = {};
  findings.forEach((f) => { sevCount[f.severity] = (sevCount[f.severity] || 0) + 1; });
  const riskCount = { R1: 0, R2: 0, R3: 0, R4: 0, R5: 0, R6: 0 };
  findings.forEach((f) => { if (riskCount[f.risk_type] != null) riskCount[f.risk_type]++; });
  const scores = { R1: 0, R2: 0, R3: 0, R4: 0, R5: 0, R6: 0, ...(detail.risk_scores || {}) };
  const sess = detail.session;
  const reason = t(`reason.${sess.verdict}`);
  const events = detail.events || [];
  const summary = composeSummary(detail.server, sess.verdict, sess.overall_score, findings, scores, sess.tools_tested);

  return (
    <div id="report-print-root" className="fade" style={{ maxWidth: "var(--maxw)", margin: "0 auto", padding: "0 28px 90px" }}>
      <ReportHeader onNewScan={onNewScan} onExport={exportPdf} sess={sess} server={detail.server} />
      {summary && <ReportSummary text={summary} verdict={sess.verdict} />}
      <VerdictHero style={heroStyle} scores={scores} sevCount={sevCount} total={findings.length} sess={sess} reason={reason} />
      <RiskMatrix scores={scores} riskCount={riskCount} />
      <FindingsSection findings={findings} riskCount={riskCount} forceOpen={printing} />
      {events.length > 0 && <EventLog events={events} total={sess.total_events} forceOpen={printing} />}
      <ReportFooter />
    </div>
  );
}

// ── Report header ────────────────────────────────────────────────────────────
function ReportHeader({ onNewScan, onExport, sess, server }) {
  return (
    <div style={{
      display: "flex", justifyContent: "space-between", alignItems: "flex-end",
      gap: 18, padding: "10px 0 22px", flexWrap: "wrap",
    }}>
      <div>
        <div style={{ fontFamily: "var(--mono)", fontSize: 11.5, fontWeight: 600, letterSpacing: "0.08em", color: "var(--text-3)", marginBottom: 11 }}>{t("report.eyebrow")}</div>
        <h1 style={{ margin: 0, fontSize: 27, fontWeight: 700, letterSpacing: "-0.02em" }}>
          <span style={{ fontFamily: "var(--mono)" }}>{server}</span> {t("report.serverSuffix")}
        </h1>
        <div style={{ display: "flex", gap: 16, marginTop: 9, flexWrap: "wrap", fontFamily: "var(--mono)", fontSize: 12, color: "var(--text-3)" }}>
          <span>{sess.session_id}</span>
          <span style={{ color: "var(--border-strong)" }}>·</span>
          <span>{sess.generated}</span>
          <span style={{ color: "var(--border-strong)" }}>·</span>
          <span className="tnum">{sess.duration_sec.toFixed(0)}s</span>
        </div>
      </div>
      <div className="no-print" style={{ display: "flex", gap: 10 }}>
        <Button variant="secondary" size="md" onClick={onExport} icon={<span style={{ fontSize: 13 }}>↓</span>}>{t("common.exportReport")}</Button>
        <Button variant="primary" size="md" onClick={onNewScan}>{t("common.newScan")}</Button>
      </div>
    </div>
  );
}

// ── Plain-language summary (TL;DR) ────────────────────────────────────────────
function ReportSummary({ text, verdict }) {
  const c = VERDICT_COLOR[verdict] || VERDICT_COLOR.CONDITIONAL;
  return (
    <div className="fade" style={{
      display: "flex", gap: 13, padding: "14px 18px", marginBottom: 16,
      background: "var(--surface)", border: "1px solid var(--border)",
      borderLeft: `3px solid ${c.fg}`, borderRadius: "var(--r-lg)", boxShadow: "var(--shadow-sm)",
    }}>
      <span style={{ fontFamily: "var(--mono)", fontSize: 10.5, fontWeight: 700, letterSpacing: "0.08em", color: "var(--text-faint)", paddingTop: 3, flex: "none" }}>{t("report.tldr")}</span>
      <p style={{ margin: 0, fontSize: 14, lineHeight: 1.62, color: "var(--text-2)" }}>{text}</p>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════
// VERDICT HERO — 3 switchable directions
// ═══════════════════════════════════════════════════════════════════════════
const VERDICT_REASON = "Process crashed under input fuzzing and runtime tool discovery never completed (0 tools reached). Ship only behind a supervisor that restarts on crash, and re-scan once the Redis backend is reachable.";

function VerdictHero({ style, scores, sevCount, total, sess, reason }) {
  if (style === "matrix") return <HeroMatrix scores={scores} sevCount={sevCount} total={total} sess={sess} reason={reason} />;
  if (style === "editorial") return <HeroEditorial sevCount={sevCount} total={total} sess={sess} reason={reason} />;
  return <HeroBanner sevCount={sevCount} total={total} sess={sess} reason={reason} />;
}

// Direction A — Decisive banner (default)
function HeroBanner({ sevCount, total, sess, reason }) {
  sess = sess || MINOS_DATA.SESSION;
  reason = reason || VERDICT_REASON;
  const c = VERDICT_COLOR[sess.verdict];
  return (
    <Card pad={0} style={{ overflow: "hidden", marginBottom: 16, borderColor: c.bd }}>
      <div style={{ display: "flex", flexWrap: "wrap" }}>
        {/* left: verdict */}
        <div style={{
          flex: "1 1 360px", padding: "30px 32px", background: c.bg,
          borderRight: "1px solid " + c.bd, position: "relative", overflow: "hidden",
        }}>
          <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 18 }}>
            <span style={{
              width: 34, height: 34, borderRadius: 999, background: c.fg, color: c.bg,
              display: "flex", alignItems: "center", justifyContent: "center", fontSize: 18, fontWeight: 800, flex: "none",
            }}>{VERDICT_ICON[sess.verdict]}</span>
            <span style={{ fontFamily: "var(--mono)", fontSize: 12, fontWeight: 600, letterSpacing: "0.1em", color: c.fg, opacity: 0.8 }}>{t("report.verdict")}</span>
          </div>
          <div style={{ fontSize: 52, fontWeight: 800, letterSpacing: "-0.03em", color: c.fg, lineHeight: 1 }}>
            {sess.verdict}
          </div>
          <p style={{ margin: "16px 0 0", fontSize: 14, lineHeight: 1.55, color: "var(--text-2)", maxWidth: 440 }}>
            {reason}
          </p>
        </div>
        {/* right: score + stats */}
        <div style={{ flex: "1 1 280px", padding: "30px 32px", display: "flex", alignItems: "center", gap: 28 }}>
          <div style={{ position: "relative", flex: "none" }}>
            <Donut value={sess.overall_score} size={128} stroke={11} color={c.fg} />
            <div style={{ position: "absolute", inset: 0, display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center" }}>
              <span className="tnum" style={{ fontSize: 30, fontWeight: 700, letterSpacing: "-0.02em" }}>{sess.overall_score.toFixed(2)}</span>
              <span style={{ fontSize: 10.5, color: "var(--text-3)", fontFamily: "var(--mono)", textTransform: "uppercase", letterSpacing: "0.04em" }}>{t("report.riskScore")}</span>
            </div>
          </div>
          <div style={{ display: "grid", gap: 14, flex: 1 }}>
            <StatLine label={t("report.findings")} value={total} />
            <StatLine label={t("report.highestSeverity")} value={<SeverityBadge level={sevCount.HIGH ? "HIGH" : "MEDIUM"} size="sm" />} raw />
            <StatLine label={t("report.toolsTested")} value={<span><span className="tnum">{sess.tools_tested}</span> <span style={{ color: "var(--text-faint)", fontWeight: 400, fontSize: 12 }}>{t("report.runtime")}</span></span>} raw />
          </div>
        </div>
      </div>
    </Card>
  );
}

// Direction B — Score-matrix led hero
function HeroMatrix({ scores, sevCount, total, sess, reason }) {
  sess = sess || MINOS_DATA.SESSION;
  reason = reason || VERDICT_REASON;
  const c = VERDICT_COLOR[sess.verdict];
  const D = MINOS_DATA;
  return (
    <Card pad="26px 28px" style={{ marginBottom: 16 }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 22, flexWrap: "wrap", gap: 14 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 16 }}>
          <VerdictPill verdict={sess.verdict} size="lg" />
          <span style={{ fontSize: 14, color: "var(--text-2)", maxWidth: 420, lineHeight: 1.5 }}>{reason}</span>
        </div>
        <div style={{ textAlign: "right", flex: "none" }}>
          <div className="tnum" style={{ fontSize: 38, fontWeight: 800, letterSpacing: "-0.03em", color: c.fg, lineHeight: 1 }}>{sess.overall_score.toFixed(2)}</div>
          <div style={{ fontSize: 10.5, color: "var(--text-3)", fontFamily: "var(--mono)", textTransform: "uppercase", letterSpacing: "0.04em" }}>{t("report.overallRisk")}</div>
        </div>
      </div>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(6, 1fr)", gap: 10 }}>
        {Object.keys(D.RISK_META).map((code, i) => {
          const sc = scores[code];
          return (
            <div key={code} style={{ padding: "13px 13px 15px", borderRadius: "var(--r-md)", background: "var(--surface-2)", border: "1px solid var(--border)" }}>
              <div style={{ fontFamily: "var(--mono)", fontWeight: 700, fontSize: 13 }}>{code}</div>
              <div style={{ fontSize: 10.5, color: "var(--text-3)", margin: "2px 0 11px", height: 26, lineHeight: 1.3 }}>{riskName(code, D.RISK_META[code].name)}</div>
              <div className="tnum" style={{ fontSize: 19, fontWeight: 700, color: scoreColor(sc), marginBottom: 7 }}>{sc.toFixed(2)}</div>
              <ScoreBar value={sc} delay={0.1 + i * 0.05} />
            </div>
          );
        })}
      </div>
    </Card>
  );
}

// Direction C — Editorial / centered document
function HeroEditorial({ sevCount, total, sess, reason }) {
  sess = sess || MINOS_DATA.SESSION;
  reason = reason || VERDICT_REASON;
  const c = VERDICT_COLOR[sess.verdict];
  return (
    <Card pad="44px 32px" style={{ marginBottom: 16, textAlign: "center" }}>
      <div style={{ fontFamily: "var(--mono)", fontSize: 11.5, letterSpacing: "0.1em", color: "var(--text-3)", marginBottom: 18 }}>PRE-DEPLOYMENT VERDICT</div>
      <div style={{ display: "inline-flex", alignItems: "center", gap: 16, marginBottom: 10 }}>
        <span style={{ width: 14, height: 14, borderRadius: 999, background: c.fg }} />
        <span style={{ fontSize: 46, fontWeight: 800, letterSpacing: "-0.03em", color: c.fg, lineHeight: 1 }}>{sess.verdict}</span>
        <span style={{ width: 14, height: 14, borderRadius: 999, background: c.fg }} />
      </div>
      <p style={{ margin: "0 auto", maxWidth: 540, fontSize: 14.5, lineHeight: 1.6, color: "var(--text-2)" }}>{reason}</p>
      <div style={{ display: "flex", justifyContent: "center", gap: 0, marginTop: 28, borderTop: "1px solid var(--border)", paddingTop: 22 }}>
        <CenterStat label="Risk score" value={sess.overall_score.toFixed(2)} color={c.fg} />
        <CenterStat label="Findings" value={total} border />
        <CenterStat label="High sev" value={sevCount.HIGH || 0} border />
        <CenterStat label="Duration" value={sess.duration_sec.toFixed(0) + "s"} border />
      </div>
    </Card>
  );
}
function CenterStat({ label, value, color, border }) {
  return (
    <div style={{ padding: "0 30px", borderLeft: border ? "1px solid var(--border)" : "none" }}>
      <div className="tnum" style={{ fontSize: 28, fontWeight: 700, letterSpacing: "-0.02em", color: color || "var(--text)" }}>{value}</div>
      <div style={{ fontSize: 11, color: "var(--text-3)", fontFamily: "var(--mono)", textTransform: "uppercase", letterSpacing: "0.04em", marginTop: 3 }}>{label}</div>
    </div>
  );
}

function StatLine({ label, value, raw }) {
  return (
    <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 12, borderBottom: "1px solid var(--border-faint)", paddingBottom: 12 }}>
      <span style={{ fontSize: 12.5, color: "var(--text-3)" }}>{label}</span>
      {raw ? value : <span className="tnum" style={{ fontSize: 15, fontWeight: 700 }}>{value}</span>}
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════
// RISK MATRIX (R1–R6 rows)
// ═══════════════════════════════════════════════════════════════════════════
function RiskMatrix({ scores, riskCount }) {
  const D = MINOS_DATA;
  return (
    <Card pad="6px 22px 14px" style={{ marginBottom: 16 }}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "16px 0 8px" }}>
        <h2 style={{ margin: 0, fontSize: 15, fontWeight: 700, letterSpacing: "-0.01em" }}>{t("report.riskSurface")}</h2>
        <span style={{ fontSize: 12, color: "var(--text-3)", fontFamily: "var(--mono)" }}>{t("report.riskSurfaceHint")}</span>
      </div>
      <div>
        {Object.keys(D.RISK_META).map((code, i) => {
          const meta = D.RISK_META[code];
          const sc = scores[code];
          const cnt = riskCount[code];
          return (
            <div key={code} style={{
              display: "grid", gridTemplateColumns: "44px 1.4fr 1fr 64px 70px", alignItems: "center", gap: 16,
              padding: "13px 0", borderTop: i === 0 ? "1px solid var(--border)" : "1px solid var(--border-faint)",
            }}>
              <span style={{ fontFamily: "var(--mono)", fontWeight: 700, fontSize: 14, color: sc > 0 ? "var(--text)" : "var(--text-faint)" }}>{code}</span>
              <div>
                <div style={{ fontSize: 13.5, fontWeight: 600, color: sc > 0 ? "var(--text)" : "var(--text-2)" }}>{riskName(code, meta.name)}</div>
                <div style={{ fontSize: 11.5, color: "var(--text-faint)" }}>{riskFull(code, meta.full)}</div>
              </div>
              <ScoreBar value={sc} delay={0.05 * i} />
              <span className="tnum" style={{ fontFamily: "var(--mono)", fontSize: 14, fontWeight: 600, color: scoreColor(sc), textAlign: "right" }}>{sc.toFixed(2)}</span>
              <span style={{ textAlign: "right", fontSize: 12.5, color: cnt ? "var(--text-2)" : "var(--text-faint)", fontFamily: "var(--mono)" }}>
                {cnt ? (cnt > 1 ? t("report.findingCountPlural", { n: cnt }) : t("report.findingCount", { n: cnt })) : t("common.clean")}
              </span>
            </div>
          );
        })}
      </div>
    </Card>
  );
}

// ═══════════════════════════════════════════════════════════════════════════
// FINDINGS
// ═══════════════════════════════════════════════════════════════════════════
function FindingsSection({ findings, riskCount, forceOpen }) {
  const [phase, setPhase] = useState("all");
  const [risk, setRisk] = useState("all");
  const [sev, setSev] = useState("all");

  const bySeverity = (a, b) => MINOS_DATA.SEVERITY_ORDER.indexOf(a.severity) - MINOS_DATA.SEVERITY_ORDER.indexOf(b.severity);
  // When printing, ignore the on-screen filters so the PDF holds every finding.
  const filtered = forceOpen
    ? [...findings].sort(bySeverity)
    : findings
        .filter((f) => phase === "all" || f.phase === phase)
        .filter((f) => risk === "all" || f.risk_type === risk)
        .filter((f) => sev === "all" || f.severity === sev)
        .sort(bySeverity);

  const staticN = findings.filter((f) => f.phase === "static").length;
  const dynN = findings.filter((f) => f.phase === "dynamic").length;
  const risksPresent = ["R1", "R2", "R3", "R4", "R5", "R6"].filter((r) => riskCount[r] > 0);

  return (
    <div style={{ marginBottom: 16 }}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", margin: "26px 2px 16px", flexWrap: "wrap", gap: 12 }}>
        <h2 style={{ margin: 0, fontSize: 17, fontWeight: 700, letterSpacing: "-0.01em" }}>
          {t("report.findingsTitle")} <span style={{ color: "var(--text-faint)", fontWeight: 500 }}>{findings.length}</span>
        </h2>
        <span className="no-print">
          <Segmented size="sm" value={phase} onChange={setPhase} options={[
            { value: "all", label: t("report.phase.all"), count: findings.length },
            { value: "static", label: t("report.phase.static"), count: staticN },
            { value: "dynamic", label: t("report.phase.dynamic"), count: dynN },
          ]} />
        </span>
      </div>

      {/* filters */}
      <div className="no-print" style={{ display: "flex", gap: 18, alignItems: "center", marginBottom: 16, flexWrap: "wrap" }}>
        <FilterGroup label={t("report.filter.risk")}>
          <Chip active={risk === "all"} onClick={() => setRisk("all")}>{t("report.phase.all")}</Chip>
          {risksPresent.map((r) => (
            <Chip key={r} active={risk === r} onClick={() => setRisk(r)} mono>{r}</Chip>
          ))}
        </FilterGroup>
        <span style={{ width: 1, height: 22, background: "var(--border)" }} />
        <FilterGroup label={t("report.filter.severity")}>
          <Chip active={sev === "all"} onClick={() => setSev("all")}>{t("report.phase.all")}</Chip>
          {MINOS_DATA.SEVERITY_ORDER.filter((s) => findings.some((f) => f.severity === s)).map((s) => (
            <Chip key={s} active={sev === s} onClick={() => setSev(s)} dot={SEV_COLOR[s].fg}>{s[0] + s.slice(1).toLowerCase()}</Chip>
          ))}
        </FilterGroup>
      </div>

      <div style={{ display: "grid", gap: 10 }}>
        {filtered.length === 0 && (
          <Card pad="28px" style={{ textAlign: "center", color: "var(--text-3)", fontSize: 13.5 }}>{t("report.noFindings")}</Card>
        )}
        {filtered.map((f) => <FindingCard key={f.finding_id} f={f} forceOpen={forceOpen} />)}
      </div>
    </div>
  );
}

function FilterGroup({ label, children }) {
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 9 }}>
      <span style={{ fontSize: 11, fontFamily: "var(--mono)", color: "var(--text-faint)", textTransform: "uppercase", letterSpacing: "0.04em" }}>{label}</span>
      <div style={{ display: "flex", gap: 6 }}>{children}</div>
    </div>
  );
}
function Chip({ children, active, onClick, mono, dot }) {
  return (
    <button onClick={onClick} className="focusable" style={{
      display: "inline-flex", alignItems: "center", gap: 6, padding: "4px 11px", borderRadius: 999,
      fontSize: 12.5, fontWeight: active ? 600 : 500, fontFamily: mono ? "var(--mono)" : "var(--font)",
      color: active ? "#fbfbfa" : "var(--text-2)",
      background: active ? "var(--accent)" : "var(--surface)",
      border: `1px solid ${active ? "var(--accent)" : "var(--border-strong)"}`,
      transition: "all 0.12s ease",
    }}>
      {dot && <span style={{ width: 7, height: 7, borderRadius: 999, background: active ? "#fff" : dot }} />}
      {children}
    </button>
  );
}

function FindingCard({ f, forceOpen }) {
  const [open, setOpen] = useState(false);
  const isOpen = open || forceOpen;
  const c = SEV_COLOR[f.severity];
  const loc = localizeFinding(f);
  return (
    <Card pad={0} style={{ overflow: "hidden", borderLeft: `3px solid ${c.fg}` }}>
      <div onClick={() => setOpen(!open)} style={{
        display: "flex", alignItems: "flex-start", gap: 14, padding: "15px 18px", cursor: "pointer",
      }}>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 9, marginBottom: 7, flexWrap: "wrap" }}>
            <SeverityBadge level={f.severity} size="sm" />
            <RiskTag code={f.risk_type} withName />
            <PhaseTag phase={f.phase} />
            {f.server && (
              <span style={{ fontFamily: "var(--mono)", fontSize: 11, fontWeight: 600, color: "var(--text-2)", background: "var(--surface-inset)", border: "1px solid var(--border)", padding: "1px 7px", borderRadius: 5 }}>{f.server}</span>
            )}
            {f.tool_name && (
              <span style={{ fontFamily: "var(--mono)", fontSize: 11.5, color: "var(--text-3)" }}>
                tool <b style={{ color: "var(--text-2)" }}>{f.tool_name}</b>
              </span>
            )}
          </div>
          <div style={{ fontSize: 14.5, fontWeight: 600, letterSpacing: "-0.01em", lineHeight: 1.4 }}>{loc.title}</div>
          {!isOpen && <div style={{ fontSize: 12.8, color: "var(--text-3)", marginTop: 5, lineHeight: 1.5, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{loc.description}</div>}
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 16, flex: "none" }}>
          <Confidence value={f.confidence} />
          <span className="no-print" style={{ fontSize: 13, color: "var(--text-faint)", transform: isOpen ? "rotate(90deg)" : "none", transition: "transform 0.15s ease" }}>›</span>
        </div>
      </div>

      {isOpen && (
        <div className="fade" style={{ padding: "4px 18px 20px", borderTop: "1px solid var(--border-faint)" }}>
          <p style={{ fontSize: 13.5, lineHeight: 1.62, color: "var(--text-2)", margin: "16px 0 18px" }}>{loc.description}</p>

          <div style={{ display: "grid", gap: 16 }}>
            {f.location && <DetailBlock label={t("report.dLocation")}><code style={{ fontFamily: "var(--mono)", fontSize: 12.5, color: "var(--text)" }}>{f.location}</code></DetailBlock>}
            {f.evidence && <DetailBlock label={t("report.dEvidence")}><Mono>{f.evidence}</Mono></DetailBlock>}
            {f.reproduction && (
              <DetailBlock label={t("report.dRepro")}>
                <Mono copyable style={{ background: "var(--text)", color: "#e9e9e6", border: "1px solid var(--text)" }}>
                  <span style={{ color: "#8a897f" }}>$ </span>{loc.reproduction}
                </Mono>
              </DetailBlock>
            )}
            {f.related_events && f.related_events.length > 0 && (
              <DetailBlock label={t("report.dRelated", { n: f.related_events.length })}>
                <div style={{ display: "flex", flexWrap: "wrap", gap: 7 }}>
                  {f.related_events.map((e) => (
                    <a key={e} href="#event-log" style={{
                      fontFamily: "var(--mono)", fontSize: 11.5, color: "var(--blue)", textDecoration: "none",
                      background: "var(--blue-bg)", border: "1px solid var(--blue-border)", padding: "3px 9px", borderRadius: 6,
                    }}>{e}</a>
                  ))}
                </div>
              </DetailBlock>
            )}
            <div style={{ display: "flex", gap: 28, flexWrap: "wrap", paddingTop: 4 }}>
              <DetailInline label={t("report.dScanner")} value={f.scanner} mono />
              <DetailInline label={t("report.dFindingId")} value={f.finding_id} mono />
              {f.tags && f.tags.length > 0 && (
                <div>
                  <div style={{ fontSize: 11, color: "var(--text-faint)", fontFamily: "var(--mono)", textTransform: "uppercase", letterSpacing: "0.04em", marginBottom: 5 }}>{t("report.dTags")}</div>
                  <div style={{ display: "flex", gap: 5 }}>
                    {f.tags.map((t) => <span key={t} style={{ fontFamily: "var(--mono)", fontSize: 11, color: "var(--text-3)", background: "var(--surface-inset)", padding: "2px 7px", borderRadius: 5, border: "1px solid var(--border)" }}>{t}</span>)}
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </Card>
  );
}
function DetailBlock({ label, children }) {
  return (
    <div>
      <div style={{ fontSize: 11, color: "var(--text-faint)", fontFamily: "var(--mono)", textTransform: "uppercase", letterSpacing: "0.04em", marginBottom: 7 }}>{label}</div>
      {children}
    </div>
  );
}
function DetailInline({ label, value, mono }) {
  return (
    <div>
      <div style={{ fontSize: 11, color: "var(--text-faint)", fontFamily: "var(--mono)", textTransform: "uppercase", letterSpacing: "0.04em", marginBottom: 5 }}>{label}</div>
      <div style={{ fontSize: 12.5, fontFamily: mono ? "var(--mono)" : "var(--font)", color: "var(--text-2)" }}>{value}</div>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════
// EVENT LOG
// ═══════════════════════════════════════════════════════════════════════════
function EventLog({ events = [], total, forceOpen }) {
  const [open, setOpen] = useState(false);
  const isOpen = open || forceOpen;
  const capped = total && total > events.length;
  const typeColor = {
    server_crash: "var(--red)", sequence_timeout: "var(--amber)", mcp_request: "var(--text-3)",
  };
  return (
    <Card pad={0} id="event-log" style={{ overflow: "hidden", scrollMarginTop: 20 }}>
      <div onClick={() => setOpen(!open)} style={{
        display: "flex", alignItems: "center", justifyContent: "space-between", padding: "16px 22px", cursor: "pointer",
      }}>
        <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
          <h2 style={{ margin: 0, fontSize: 15, fontWeight: 700 }}>{t("report.rawLog")}</h2>
          <span style={{ fontFamily: "var(--mono)", fontSize: 12, color: "var(--text-3)" }}>events.jsonl · {capped ? `latest ${events.length} of ${total}` : `${events.length}`} records</span>
        </div>
        <span className="no-print" style={{ fontSize: 14, color: "var(--text-faint)", transform: isOpen ? "rotate(90deg)" : "none", transition: "transform 0.15s ease" }}>›</span>
      </div>
      {isOpen && (
        <div className="fade scroll mn-eventlog" style={{ borderTop: "1px solid var(--border)", maxHeight: 380, overflowY: "auto" }}>
          <div style={{
            display: "grid", gridTemplateColumns: "84px 150px 80px 1fr", gap: 12, padding: "9px 22px",
            position: "sticky", top: 0, background: "var(--surface-2)", borderBottom: "1px solid var(--border)",
            fontFamily: "var(--mono)", fontSize: 10.5, fontWeight: 600, letterSpacing: "0.04em", color: "var(--text-faint)", textTransform: "uppercase", zIndex: 1,
          }}>
            <span>Time</span><span>Type</span><span>Source</span><span>Data</span>
          </div>
          {events.map((e, i) => (
            <div key={i} style={{
              display: "grid", gridTemplateColumns: "84px 150px 80px 1fr", gap: 12, padding: "9px 22px",
              borderBottom: i === events.length - 1 ? "none" : "1px solid var(--border-faint)",
              fontFamily: "var(--mono)", fontSize: 11.5, alignItems: "center",
            }}>
              <span className="tnum" style={{ color: "var(--text-faint)" }}>{e.ts}</span>
              <span style={{ color: typeColor[e.type] || "var(--text-2)", fontWeight: e.type === "server_crash" ? 600 : 500 }}>{e.type}</span>
              <span style={{ color: "var(--text-3)" }}>{e.source}</span>
              <span style={{ color: "var(--text-2)", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>
                {Object.entries(e.data).map(([k, v]) => `${k}=${v}`).join("  ")}
                {e.variation_tag && <span style={{ color: "var(--blue)" }}>  ·{e.variation_tag}</span>}
              </span>
            </div>
          ))}
        </div>
      )}
    </Card>
  );
}

function ReportFooter() {
  return (
    <div style={{ display: "flex", alignItems: "center", justifyContent: "center", gap: 8, marginTop: 30, color: "var(--text-faint)", fontSize: 12, fontFamily: "var(--mono)" }}>
      <Logo size={16} />
      <span>{t("report.generatedBy")}</span>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════
// FINDINGS — fleet-wide explorer (sidebar → Findings)
// ═══════════════════════════════════════════════════════════════════
export function FindingsScreen() {
  const { data, loading, error, reload } = useApi(fetchFindings);
  const all = data || [];
  const [server, setServer] = useState("all");
  const [risk, setRisk] = useState("all");
  const [sev, setSev] = useState("all");
  const [phase, setPhase] = useState("all");
  const initial = loading && !data;

  const servers = [...new Set(all.map((f) => f.server))];
  const filtered = all
    .filter((f) => server === "all" || f.server === server)
    .filter((f) => risk === "all" || f.risk_type === risk)
    .filter((f) => sev === "all" || f.severity === sev)
    .filter((f) => phase === "all" || f.phase === phase)
    .sort((a, b) => MINOS_DATA.SEVERITY_ORDER.indexOf(a.severity) - MINOS_DATA.SEVERITY_ORDER.indexOf(b.severity));

  const staticN = all.filter((f) => f.phase === "static").length;
  const dynN = all.filter((f) => f.phase === "dynamic").length;
  const risksPresent = ["R1", "R2", "R3", "R4", "R5", "R6"].filter((r) => all.some((f) => f.risk_type === r));
  const sevTotals = MINOS_DATA.SEVERITY_ORDER.reduce((a, s) => { a[s] = all.filter((f) => f.severity === s).length; return a; }, {});

  if (error) {
    return (
      <div className="fade-up" style={{ maxWidth: "var(--maxw)", margin: "0 auto", padding: "0 28px 80px" }}>
        <ScreenHead eyebrow={t("findings.eyebrow")} title={t("findings.title")} sub={t("findings.sub")} />
        <ErrorState onRetry={reload} />
      </div>
    );
  }
  if (initial) {
    return (
      <div className="fade-up" style={{ maxWidth: "var(--maxw)", margin: "0 auto", padding: "0 28px 80px" }}>
        <ScreenHead eyebrow={t("findings.eyebrow")} title={t("findings.title")} sub={t("findings.sub")} />
        <Card pad={0}><Loading label={t("findings.loading")} /></Card>
      </div>
    );
  }

  return (
    <div className="fade-up" style={{ maxWidth: "var(--maxw)", margin: "0 auto", padding: "0 28px 80px" }}>
      <ScreenHead eyebrow={t("findings.eyebrow")} title={t("findings.title")} sub={t("findings.sub")} />

      {/* severity summary strip */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(5, 1fr)", gap: 12, marginBottom: 22 }}>
        {MINOS_DATA.SEVERITY_ORDER.map((lvl) => {
          const c = SEV_COLOR[lvl];
          return (
            <Card key={lvl} pad="13px 15px">
              <div style={{ display: "flex", alignItems: "center", gap: 7, marginBottom: 8 }}>
                <span style={{ width: 8, height: 8, borderRadius: 999, background: c.fg }} />
                <span style={{ fontFamily: "var(--mono)", fontSize: 10.5, fontWeight: 600, color: c.fg, textTransform: "uppercase", letterSpacing: "0.03em" }}>{lvl}</span>
              </div>
              <div className="tnum" style={{ fontSize: 24, fontWeight: 700, letterSpacing: "-0.02em" }}>{sevTotals[lvl]}</div>
            </Card>
          );
        })}
      </div>

      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", margin: "0 2px 16px", flexWrap: "wrap", gap: 12 }}>
        <h2 style={{ margin: 0, fontSize: 17, fontWeight: 700, letterSpacing: "-0.01em" }}>
          {t("findings.all")} <span style={{ color: "var(--text-faint)", fontWeight: 500 }}>{filtered.length}</span>
        </h2>
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <Segmented size="sm" value={phase} onChange={setPhase} options={[
            { value: "all", label: t("report.phase.all"), count: all.length },
            { value: "static", label: t("report.phase.static"), count: staticN },
            { value: "dynamic", label: t("report.phase.dynamic"), count: dynN },
          ]} />
          <RefreshButton onClick={reload} loading={loading} title="Reload findings from results/" />
        </div>
      </div>

      {/* filters */}
      <div style={{ display: "flex", gap: 18, alignItems: "center", marginBottom: 16, flexWrap: "wrap" }}>
        <FilterGroup label={t("report.filter.server")}>
          <Chip active={server === "all"} onClick={() => setServer("all")}>{t("report.phase.all")}</Chip>
          {servers.map((s) => <Chip key={s} active={server === s} onClick={() => setServer(s)} mono>{s}</Chip>)}
        </FilterGroup>
        <span style={{ width: 1, height: 22, background: "var(--border)" }} />
        <FilterGroup label={t("report.filter.risk")}>
          <Chip active={risk === "all"} onClick={() => setRisk("all")}>{t("report.phase.all")}</Chip>
          {risksPresent.map((r) => <Chip key={r} active={risk === r} onClick={() => setRisk(r)} mono>{r}</Chip>)}
        </FilterGroup>
        <span style={{ width: 1, height: 22, background: "var(--border)" }} />
        <FilterGroup label={t("report.filter.severity")}>
          <Chip active={sev === "all"} onClick={() => setSev("all")}>{t("report.phase.all")}</Chip>
          {MINOS_DATA.SEVERITY_ORDER.filter((s) => all.some((f) => f.severity === s)).map((s) => (
            <Chip key={s} active={sev === s} onClick={() => setSev(s)} dot={SEV_COLOR[s].fg}>{s[0] + s.slice(1).toLowerCase()}</Chip>
          ))}
        </FilterGroup>
      </div>

      {/* grouped by server */}
      {filtered.length === 0 ? (
        <Card pad="28px" style={{ textAlign: "center", color: "var(--text-3)", fontSize: 13.5 }}>{t("report.noFindings")}</Card>
      ) : (
        <div style={{ display: "grid", gap: 24 }}>
          {groupByServer(filtered).map(([srv, items]) => {
            const sevCounts = MINOS_DATA.SEVERITY_ORDER
              .map((s) => [s, items.filter((f) => f.severity === s).length])
              .filter(([, n]) => n > 0);
            return (
              <div key={srv}>
                {/* server group header */}
                <div style={{ display: "flex", alignItems: "center", gap: 11, margin: "0 2px 11px", flexWrap: "wrap" }}>
                  <span style={{
                    width: 26, height: 26, borderRadius: 7, flex: "none", background: "var(--surface-inset)",
                    border: "1px solid var(--border)", display: "flex", alignItems: "center", justifyContent: "center",
                    fontFamily: "var(--mono)", fontSize: 12, fontWeight: 700, color: "var(--text-2)",
                  }}>{(srv || "?")[0].toUpperCase()}</span>
                  <span style={{ fontFamily: "var(--mono)", fontSize: 14, fontWeight: 700 }}>{srv}</span>
                  <span style={{ fontFamily: "var(--mono)", fontSize: 12, color: "var(--text-faint)" }}>
                    {items.length > 1 ? t("report.findingCountPlural", { n: items.length }) : t("report.findingCount", { n: items.length })}
                  </span>
                  <span style={{ flex: 1 }} />
                  <span style={{ display: "flex", gap: 10 }}>
                    {sevCounts.map(([s, n]) => (
                      <span key={s} style={{ display: "inline-flex", alignItems: "center", gap: 5, fontFamily: "var(--mono)", fontSize: 11.5, color: "var(--text-3)" }}>
                        <span style={{ width: 7, height: 7, borderRadius: 999, background: SEV_COLOR[s].fg }} />{n}
                      </span>
                    ))}
                  </span>
                </div>
                <div style={{ display: "grid", gap: 10 }}>
                  {items.map((f) => <FindingCard key={f.finding_id} f={f} />)}
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

// Group findings by server; order groups by worst severity, then count.
function groupByServer(findings) {
  const by = {};
  findings.forEach((f) => { (by[f.server] = by[f.server] || []).push(f); });
  const worst = (list) => Math.min(...list.map((x) => MINOS_DATA.SEVERITY_ORDER.indexOf(x.severity)));
  return Object.entries(by).sort((a, b) => {
    const wa = worst(a[1]); const wb = worst(b[1]);
    return wa !== wb ? wa - wb : b[1].length - a[1].length;
  });
}
