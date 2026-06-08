// App.jsx — shell, navigation state machine, top bar.
//
// The design's live "Tweaks" panel (a design-tool artifact) is dropped; its
// final chosen defaults are baked in as constants below.
import React, { useState, useEffect, useRef } from "react";
import { Sidebar, SettingsScreen, ActiveScanIdle, StaticScanScreen, ResultsListScreen } from "./screens/sidebar.jsx";
import { DashboardScreen } from "./screens/dashboard.jsx";
import { DiscoverScreen, ConfigureScreen, ProgressScreen, ActiveScansList } from "./screens/scanflow.jsx";
import { ResultsScreen, FindingsScreen } from "./screens/report.jsx";
import { LoginScreen } from "./screens/login.jsx";
import { fetchHealth, createScan, connectScanStream } from "./api.js";
import { t, getLang, setLang } from "./i18n.js";

// ── Baked design defaults (were the "Tweaks" panel controls) ────────────────
const HERO_STYLE = "banner";     // verdict hero: banner | matrix | editorial
const ACCENT = "#1a1a18";        // ink accent
const DENSITY = "regular";       // compact | regular | comfy
const LOGIN_STYLE = "split";     // split | centered

function readAuth() {
  try { return JSON.parse(localStorage.getItem("minos_auth") || "null"); } catch (e) { return null; }
}
function roleFromEmail(email) {
  return /^admin@/i.test((email || "").trim()) ? "admin" : "dev";
}

export default function App() {
  // First visit defaults to a signed-in admin so the app is reviewable; sign-out persists.
  const initialAuth = readAuth() || { signedIn: true, email: "admin@brainoverflow.kr", method: "password", role: "admin" };
  const [auth, setAuth] = useState(initialAuth);
  const [stage, setStage] = useState(initialAuth.signedIn ? "dashboard" : "login");
  const [server, setServer] = useState(null);
  const [session, setSession] = useState(null);
  const [scanFlow, setScanFlow] = useState(false); // in the live configure→scan→report flow
  const [health, setHealth] = useState(null);
  const [lang, setLangState] = useState(getLang());
  const changeLang = (l) => { setLang(l); setLangState(l); };
  // Concurrent scans live here (not in ProgressScreen). App owns each scan's SSE
  // stream so background scans keep progressing/completing while another (or
  // none) is on screen. scan = { key, id, startedAt, server, etaSec, error,
  // status: "running"|"done"|"error", sessionId, lines }
  const [scans, setScans] = useState([]);
  const [activeScanKey, setActiveScanKey] = useState(null); // which scan's detail is shown
  const streamsRef = useRef(new Map()); // scan.key -> close()
  const keyRef = useRef(0);

  const runningScans = scans.filter((s) => s.status === "running");
  const scanning = runningScans.length > 0;
  const activeScan = scans.find((s) => s.key === activeScanKey) || null;
  // The scan whose detail is on screen: an explicitly picked one, or — when only
  // one is running and none picked — that single runner. null → idle/list.
  const viewedScan = activeScan || (runningScans.length === 1 ? runningScans[0] : null);
  const patchScan = (key, patch) =>
    setScans((prev) => prev.map((s) => (s.key === key ? { ...s, ...(typeof patch === "function" ? patch(s) : patch) } : s)));

  useEffect(() => {
    document.documentElement.setAttribute("data-density", DENSITY);
  }, []);

  // Korean reads best when lines break at word boundaries (어절), not between
  // syllables. Setting <html lang> drives the `html[lang="ko"]` CSS rule in
  // theme.css (word-break: keep-all), which applies from first paint.
  useEffect(() => {
    document.documentElement.lang = lang;
  }, [lang]);

  useEffect(() => {
    let alive = true;
    fetchHealth().then((h) => { if (alive) setHealth(h); });
    return () => { alive = false; };
  }, []);

  // One SSE stream per running scan, owned by App so background scans keep
  // streaming + completing regardless of which (if any) is on screen.
  useEffect(() => {
    scans.forEach((s) => {
      if (!s.id || s.status !== "running" || streamsRef.current.has(s.key)) return;
      const close = connectScanStream(s.id, {
        onLine: (line) => patchScan(s.key, (cur) => ({ lines: [...cur.lines, line] })),
        onDone: ({ status, session_id }) => {
          patchScan(s.key, {
            status: status === "done" && session_id ? "done" : "error",
            sessionId: session_id || null,
          });
          const c = streamsRef.current.get(s.key);
          if (c) { c(); streamsRef.current.delete(s.key); }
        },
        onError: (err) => patchScan(s.key, { error: err.message || "Lost connection" }),
      });
      streamsRef.current.set(s.key, close);
    });
  }, [scans]);

  // Close every stream when the app unmounts.
  const streams = streamsRef.current;
  useEffect(() => () => { streams.forEach((c) => c()); streams.clear(); }, [streams]);

  // When the scan being VIEWED finishes with a session, go to its report
  // (matches the single-scan UX). Background scans never trigger navigation.
  useEffect(() => {
    if (stage !== "progress" || !viewedScan) return undefined;
    if (viewedScan.status === "done" && viewedScan.sessionId) {
      const sid = viewedScan.sessionId;
      const tid = setTimeout(() => { setSession({ session_id: sid }); setScanFlow(true); go("report"); }, 900);
      return () => clearTimeout(tid);
    }
    return undefined;
  }, [stage, viewedScan?.key, viewedScan?.status, viewedScan?.sessionId]);

  const go = (s) => { window.scrollTo({ top: 0 }); setStage(s); };

  const selectServer = (s) => { setServer(s); setScanFlow(true); go("configure"); };

  // Start a scan; append it (concurrency-safe) and open its detail. Other scans
  // keep running — the backend + App's per-scan SSE stream handle them.
  const launch = (profile, docker, timeout) => {
    const srv = { ...server, profile, docker };
    setServer(srv);
    const key = `sc${(keyRef.current += 1)}`;
    setScans((prev) => [...prev, {
      key, id: null, startedAt: Date.now(), server: srv,
      etaSec: null, error: null, status: "running", sessionId: null, lines: [],
    }]);
    setActiveScanKey(key);
    setScanFlow(true);
    go("progress");
    createScan({ name: srv.name, command: srv.command, args: srv.args, profile, docker, timeout })
      .then((res) => patchScan(key, { id: res.scan_id, etaSec: res.eta_sec }))
      .catch((e) => patchScan(key, { error: e.message || "Failed to start scan", status: "error" }));
  };

  // Drop a scan from the list (close its stream).
  const dropScan = (key) => {
    const close = streamsRef.current.get(key);
    if (close) { close(); streamsRef.current.delete(key); }
    setScans((prev) => prev.filter((s) => s.key !== key));
    setActiveScanKey((k) => (k === key ? null : k));
  };

  // open a session's full report (from the results list or a dashboard row) — not the scan flow
  const openReport = (s) => { setSession(s); setScanFlow(false); go("report"); };

  // Sidebar navigation — flat, independent destinations.
  const navigate = (id) => {
    setScanFlow(false);
    if (id === "discover") { setServer(null); go("discover"); }
    else if (id === "dashboard") { setServer(null); go("dashboard"); }
    else if (id === "progress") { setActiveScanKey(null); go("progress"); } // list when >1
    else go(id);
  };

  const signOut = () => {
    const a = { signedIn: false };
    setAuth(a); localStorage.setItem("minos_auth", JSON.stringify(a));
    setServer(null); setSession(null);
    streamsRef.current.forEach((c) => c()); streamsRef.current.clear();
    setScans([]); setActiveScanKey(null);
    go("login");
  };
  const signIn = (method, email, keep, role) => {
    const a = { signedIn: true, email: email || "admin@brainoverflow.kr", method, role: role || roleFromEmail(email) };
    setAuth(a);
    if (keep === false) localStorage.removeItem("minos_auth");
    else localStorage.setItem("minos_auth", JSON.stringify(a));
    go("dashboard");
  };

  const goDiscover = () => { setServer(null); go("discover"); };

  // Active-scan view: idle (none) / detail (one picked or a single runner) /
  // list (several running, none picked).
  function renderProgress() {
    if (scans.length === 0) return <ActiveScanIdle onPick={goDiscover} />;
    const viewing = viewedScan;
    if (viewing) {
      return (
        <ProgressScreen
          scan={viewing}
          onBack={() => { dropScan(viewing.key); if (scans.length <= 1) goDiscover(); }}
          onViewResults={() => { setActiveScanKey(null); go("results"); }}
          onBackToList={runningScans.length > 1 ? () => setActiveScanKey(null) : undefined}
        />
      );
    }
    if (runningScans.length >= 1) return <ActiveScansList scans={runningScans} onOpen={setActiveScanKey} />;
    return <ActiveScanIdle onPick={goDiscover} />;
  }

  // Login is a full-screen gate — no sidebar / topbar chrome.
  if (stage === "login") {
    return (
      <div style={{ "--accent": ACCENT, minHeight: "100vh" }}>
        <LoginScreen layout={LOGIN_STYLE} onSignIn={signIn} />
      </div>
    );
  }

  return (
    <div style={{ "--accent": ACCENT, minHeight: "100vh", display: "flex", alignItems: "flex-start" }}>
      <Sidebar stage={stage} scanning={scanning} runningCount={runningScans.length} onNavigate={navigate} onSignOut={signOut} account={auth} health={health} />

      <div style={{ flex: 1, minWidth: 0, display: "flex", flexDirection: "column", minHeight: "100vh" }}>
        <TopBar stage={stage} server={server} scanning={scanning} account={auth} scanFlow={scanFlow} onStep={go} />

        <main style={{ flex: 1, paddingTop: 30 }}>
          {stage === "dashboard" && <DashboardScreen onDiscover={() => { setServer(null); go("discover"); }} onOpenSession={openReport} onSelectServer={selectServer} />}
          {stage === "discover" && <DiscoverScreen onSelect={selectServer} />}
          {stage === "static" && <StaticScanScreen />}
          {stage === "configure" && server && <ConfigureScreen server={server} onBack={() => go("discover")} onLaunch={launch} />}
          {stage === "progress" && renderProgress()}
          {stage === "results" && <ResultsListScreen onOpen={openReport} />}
          {stage === "report" && <ResultsScreen heroStyle={HERO_STYLE} session={session} onNewScan={() => { setServer(null); go("dashboard"); }} />}
          {stage === "findings" && <FindingsScreen />}
          {stage === "settings" && <SettingsScreen onSignOut={signOut} account={auth} lang={lang} onSetLang={changeLang} />}
        </main>
      </div>
    </div>
  );
}

// ── Top bar ──────────────────────────────────────────────────────────────────

// The live scan flow — its step sequence shows in the top bar while a scan runs.
const SCAN_STEPS = [
  { id: "discover", key: "step.discover" },
  { id: "configure", key: "step.configure" },
  { id: "progress", key: "step.scan" },
  { id: "report", key: "step.report" },
];

function TopBar({ stage, server, scanning, account, scanFlow, onStep }) {
  const devAccount = stage === "settings" && account && account.role !== "admin";
  const section = devAccount ? t("section.account") : t(`section.${stage}`);
  const showServer = server && stage === "configure";
  // Show the step sequence during configure / progress, and on the report that
  // immediately follows a scan (not when browsing an old report from the list).
  const stepIdx = SCAN_STEPS.findIndex((s) => s.id === stage);
  const showSteps = stage === "configure" || stage === "progress" || (stage === "report" && scanFlow);
  return (
    <header style={{
      position: "sticky", top: 0, zIndex: 50, background: "rgba(246,246,245,0.82)",
      backdropFilter: "blur(12px)", borderBottom: "1px solid var(--border)",
    }}>
      <div style={{
        maxWidth: "var(--maxw)", margin: "0 auto", padding: "0 28px", height: 58,
        display: "flex", alignItems: "center", justifyContent: "space-between", gap: 18,
      }}>
        {/* breadcrumb */}
        <div style={{ display: "flex", alignItems: "center", gap: 9, fontFamily: "var(--mono)", fontSize: 12, minWidth: 0 }}>
          <span style={{ color: "var(--text-faint)" }}>minos</span>
          <span style={{ color: "var(--text-faint)" }}>/</span>
          <span style={{ color: "var(--text-2)", fontWeight: 600 }}>{section}</span>
          {showServer && (
            <React.Fragment>
              <span style={{ color: "var(--text-faint)" }}>/</span>
              <span style={{ color: "var(--text)", fontWeight: 600 }}>{server.name}</span>
            </React.Fragment>
          )}
        </div>

        {showSteps && (
          <div style={{ display: "flex", alignItems: "center", gap: 4 }}>
            {SCAN_STEPS.map((s, i) => {
              const done = i < stepIdx;
              const active = i === stepIdx;
              const clickable = done && onStep;
              return (
                <React.Fragment key={s.id}>
                  {i > 0 && <span style={{ width: 16, height: 1, background: done || active ? "var(--border-strong)" : "var(--border)" }} />}
                  <button
                    onClick={clickable ? () => onStep(s.id) : undefined}
                    style={{
                      display: "inline-flex", alignItems: "center", gap: 7, padding: "5px 10px", borderRadius: 999,
                      background: active ? "var(--surface)" : "transparent",
                      border: active ? "1px solid var(--border-strong)" : "1px solid transparent",
                      boxShadow: active ? "var(--shadow-sm)" : "none",
                      cursor: clickable ? "pointer" : "default",
                    }}>
                    <span style={{
                      width: 17, height: 17, borderRadius: 999, flex: "none", fontSize: 10, fontWeight: 700,
                      display: "flex", alignItems: "center", justifyContent: "center", fontFamily: "var(--mono)",
                      background: done ? "var(--green)" : active ? "var(--accent)" : "var(--surface-inset)",
                      color: done || active ? "#fbfbfa" : "var(--text-faint)",
                      border: done || active ? "none" : "1px solid var(--border-strong)",
                    }}>{done ? "✓" : i + 1}</span>
                    <span style={{ fontSize: 12.5, fontWeight: active ? 600 : 500, color: active ? "var(--text)" : done ? "var(--text-2)" : "var(--text-faint)" }}>{t(s.key)}</span>
                  </button>
                </React.Fragment>
              );
            })}
          </div>
        )}

        <div style={{ display: "flex", alignItems: "center", gap: 12, minWidth: 90, justifyContent: "flex-end" }}>
          {scanning && stage === "progress"
            ? <span style={{ fontFamily: "var(--mono)", fontSize: 12, color: "var(--orange)", display: "flex", alignItems: "center", gap: 7 }}>
                <span style={{ width: 6, height: 6, borderRadius: 999, background: "var(--orange)", animation: "mn-pulse 1.2s infinite" }} />{t("topbar.scanning")}
              </span>
            : showServer
            ? <span style={{ fontFamily: "var(--mono)", fontSize: 12, color: "var(--text-3)", display: "flex", alignItems: "center", gap: 7 }}>
                <span style={{ width: 6, height: 6, borderRadius: 999, background: "var(--green)" }} />{server.name}
              </span>
            : <span style={{ fontSize: 12.5, color: "var(--text-faint)" }}>{t("common.preDeployGate")}</span>}
        </div>
      </div>
    </header>
  );
}
