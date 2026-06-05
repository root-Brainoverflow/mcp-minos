// sidebar.jsx — left navigation rail, Settings, Static-scan ruleset,
// Scan-results list, and the active-scan idle state.
import React, { useState } from "react";
import { Logo, Card, Button, VerdictPill, ScoreBar, scoreColor, RefreshButton, Loading, ErrorState } from "../components/ui.jsx";
import { ScreenHead, SectionLabel } from "../components/common.jsx";
import { MINOS_DATA } from "../data.js";
import { fetchSessions, fetchRuleset } from "../api.js";
import { useApi } from "../hooks.js";
import { t } from "../i18n.js";
import { riskName, scannerName, scannerDesc, packSummary, ruleDesc, confLabel } from "../ruleset_ko.js";

// ── Account roles ────────────────────────────────────────────────────────────
const ROLE_META = {
  admin: { label: "Admin", desc: "Full access — manages workspace settings, scan defaults and members.",
    badge: { fg: "#b07d12", bg: "var(--amber-bg)", bd: "var(--amber-border)" }, grad: "linear-gradient(135deg, #b07d12, #8a6a2e)" },
  dev: { label: "Developer", desc: "Can run scans and read reports. Workspace settings are managed by admins.",
    badge: { fg: "var(--slate)", bg: "var(--slate-bg)", bd: "var(--slate-border)" }, grad: "linear-gradient(135deg, #57564f, #3f3e39)" },
};
function roleOf(account) { return (account && account.role) || "admin"; }
function handleOf(account) { return ((account && account.email) || "admin@brainoverflow.kr").split("@")[0]; }

// ── Nav icons (minimal line glyphs, on-brand) ───────────────────────────────
function IconOverview({ s = 18, c = "currentColor" }) {
  return (
    <svg width={s} height={s} viewBox="0 0 24 24" fill="none" stroke={c} strokeWidth="1.7" strokeLinejoin="round">
      <rect x="3.2" y="3.2" width="7.4" height="7.4" rx="1.6" />
      <rect x="13.4" y="3.2" width="7.4" height="7.4" rx="1.6" />
      <rect x="3.2" y="13.4" width="7.4" height="7.4" rx="1.6" />
      <rect x="13.4" y="13.4" width="7.4" height="7.4" rx="1.6" />
    </svg>
  );
}
function IconServers({ s = 18, c = "currentColor" }) {
  return (
    <svg width={s} height={s} viewBox="0 0 24 24" fill="none" stroke={c} strokeWidth="1.7" strokeLinejoin="round">
      <rect x="3.2" y="4" width="17.6" height="6" rx="1.8" />
      <rect x="3.2" y="14" width="17.6" height="6" rx="1.8" />
      <circle cx="7" cy="7" r="0.95" fill={c} stroke="none" />
      <circle cx="7" cy="17" r="0.95" fill={c} stroke="none" />
    </svg>
  );
}
function IconScan({ s = 18, c = "currentColor" }) {
  return (
    <svg width={s} height={s} viewBox="0 0 24 24" fill="none" stroke={c} strokeWidth="1.7">
      <circle cx="12" cy="12" r="8.3" />
      <circle cx="12" cy="12" r="2.5" fill={c} stroke="none" />
    </svg>
  );
}
function IconResults({ s = 18, c = "currentColor" }) {
  return (
    <svg width={s} height={s} viewBox="0 0 24 24" fill="none" stroke={c} strokeWidth="1.7" strokeLinejoin="round" strokeLinecap="round">
      <path d="M6 3.6h7.6l4.4 4.4V20.4H6z" />
      <path d="M9.4 13.2l2 2 3.6-3.9" />
    </svg>
  );
}
function IconSettings({ s = 18, c = "currentColor" }) {
  return (
    <svg width={s} height={s} viewBox="0 0 24 24" fill="none" stroke={c} strokeWidth="1.7" strokeLinecap="round">
      <line x1="4" y1="7" x2="20" y2="7" />
      <line x1="4" y1="12" x2="20" y2="12" />
      <line x1="4" y1="17" x2="20" y2="17" />
      <circle cx="9" cy="7" r="2.15" fill="var(--surface)" />
      <circle cx="15" cy="12" r="2.15" fill="var(--surface)" />
      <circle cx="8" cy="17" r="2.15" fill="var(--surface)" />
    </svg>
  );
}
function IconRules({ s = 18, c = "currentColor" }) {
  return (
    <svg width={s} height={s} viewBox="0 0 24 24" fill="none" stroke={c} strokeWidth="1.7" strokeLinejoin="round" strokeLinecap="round">
      <path d="M5 3.6h9l5 5V20.4H5z" />
      <path d="M13.6 3.8V8.4H18.4" />
      <line x1="8.2" y1="13" x2="15.2" y2="13" />
      <line x1="8.2" y1="16.4" x2="13" y2="16.4" />
    </svg>
  );
}
function IconFindings({ s = 18, c = "currentColor" }) {
  return (
    <svg width={s} height={s} viewBox="0 0 24 24" fill="none" stroke={c} strokeWidth="1.7" strokeLinejoin="round" strokeLinecap="round">
      <path d="M12 3.4l8 3.1v5c0 5-3.4 7.7-8 9.1-4.6-1.4-8-4.1-8-9.1v-5z" />
      <line x1="12" y1="9" x2="12" y2="13" />
      <circle cx="12" cy="16.1" r="0.95" fill={c} stroke="none" />
    </svg>
  );
}

// ── Nav model ───────────────────────────────────────────────────────────────
const NAV_ITEMS = [
  { id: "dashboard", label: "Overview",      icon: IconOverview, stages: ["dashboard"] },
  { id: "discover",  label: "MCP servers",   icon: IconServers,  stages: ["discover", "configure"] },
  { id: "static",    label: "Static scan",   icon: IconRules,    stages: ["static"] },
  { id: "progress",  label: "Active scan",   icon: IconScan,     stages: ["progress"] },
  { id: "results",   label: "Scan results",  icon: IconResults,  stages: ["results", "report"] },
  { id: "findings",  label: "Findings",      icon: IconFindings, stages: ["findings"] },
  { id: "settings",  label: "Settings",      icon: IconSettings, stages: ["settings"] },
];

function NavItem({ item, active, live, onClick }) {
  const [hover, setHover] = useState(false);
  const Icon = item.icon;
  return (
    <button onClick={onClick} onMouseEnter={() => setHover(true)} onMouseLeave={() => setHover(false)} className="focusable"
      style={{
        position: "relative", display: "flex", alignItems: "center", gap: 11, width: "100%", textAlign: "left",
        padding: "9px 11px", borderRadius: 8, cursor: "pointer",
        background: active ? "var(--surface)" : hover ? "var(--surface-2)" : "transparent",
        border: active ? "1px solid var(--border)" : "1px solid transparent",
        boxShadow: active ? "var(--shadow-sm)" : "none",
        color: active ? "var(--text)" : "var(--text-2)",
        transition: "background 0.13s ease, color 0.13s ease",
      }}>
      <span style={{ flex: "none", display: "inline-flex", color: active ? "#b07d12" : "var(--text-3)" }}>
        <Icon s={18} c="currentColor" />
      </span>
      <span style={{ fontSize: 13.5, fontWeight: active ? 600 : 500, letterSpacing: "-0.005em" }}>{t(`nav.${item.id}`)}</span>
      {live && (
        <span style={{ marginLeft: "auto", display: "inline-flex", alignItems: "center", gap: 6 }}>
          <span style={{ fontFamily: "var(--mono)", fontSize: 9.5, fontWeight: 600, color: "var(--orange)", letterSpacing: "0.04em" }}>{t("nav.live")}</span>
          <span style={{ width: 7, height: 7, borderRadius: 999, background: "var(--orange)", animation: "mn-pulse 1.2s infinite" }} />
        </span>
      )}
    </button>
  );
}

export function Sidebar({ stage, scanning, onNavigate, onSignOut, account, health }) {
  const role = roleOf(account);
  const rm = ROLE_META[role];
  const handle = handleOf(account);
  // Developers don't see workspace Settings in the nav.
  const items = NAV_ITEMS.filter((it) => it.id !== "settings" || role === "admin");
  return (
    <aside style={{
      width: 246, flex: "none", alignSelf: "flex-start", position: "sticky", top: 0, height: "100vh",
      background: "var(--surface)", borderRight: "1px solid var(--border)",
      display: "flex", flexDirection: "column", zIndex: 60,
    }}>
      {/* brand */}
      <div style={{ padding: "18px 20px 16px", borderBottom: "1px solid var(--border-faint)", display: "flex", alignItems: "center", justifyContent: "space-between" }}>
        <button onClick={() => onNavigate("dashboard")} className="focusable" style={{ background: "none", border: "none", padding: 0, cursor: "pointer" }}>
          <Logo size={22} />
        </button>
        <span style={{ fontFamily: "var(--mono)", fontSize: 10.5, color: "var(--text-faint)", border: "1px solid var(--border)", padding: "2px 6px", borderRadius: 5 }}>v0.1</span>
      </div>

      {/* nav */}
      <nav style={{ padding: "16px 12px 10px", display: "grid", gap: 3, flex: 1, alignContent: "start" }}>
        <div style={{ fontFamily: "var(--mono)", fontSize: 10, fontWeight: 600, letterSpacing: "0.1em", color: "var(--text-faint)", padding: "2px 11px 8px" }}>{t("nav.NAVIGATE")}</div>
        {items.map((item) => (
          <NavItem key={item.id} item={item}
            active={item.stages.includes(stage)}
            live={item.id === "progress" && scanning}
            onClick={() => onNavigate(item.id)} />
        ))}
      </nav>

      {/* engine status — dynamic-analysis dependencies */}
      <div style={{ padding: "12px 14px 6px", display: "grid", gap: 8, borderTop: "1px solid var(--border-faint)" }}>
        <StatusLine label="Docker" state={health ? health.docker : "running"} />
        <StatusLine label="Semgrep" state={health ? health.semgrep : "ready"} />
      </div>

      {/* account / logout */}
      <div style={{ padding: "10px 12px 12px" }}>
        <div style={{
          display: "flex", alignItems: "center", gap: 10, width: "100%",
          padding: "9px 10px", borderRadius: 9,
          background: "var(--surface-2)", border: "1px solid var(--border)",
        }}>
          <button onClick={() => onNavigate("settings")} className="focusable" title="Account" style={{
            display: "flex", alignItems: "center", gap: 10, flex: 1, minWidth: 0, textAlign: "left",
            background: "none", border: "none", padding: 0, cursor: "pointer",
          }}>
            <span style={{
              width: 28, height: 28, borderRadius: 999, flex: "none",
              background: rm.grad, color: "#fff",
              display: "flex", alignItems: "center", justifyContent: "center", fontSize: 12, fontWeight: 700,
              fontFamily: "var(--mono)",
            }}>{handle[0].toUpperCase()}</span>
            <div style={{ minWidth: 0, flex: 1 }}>
              <div style={{ fontSize: 12.5, fontWeight: 600, color: "var(--text)", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>{handle}@brainoverflow</div>
              <div style={{ display: "flex", alignItems: "center", gap: 5, marginTop: 2 }}>
                <span style={{ width: 6, height: 6, borderRadius: 999, background: rm.badge.fg }} />
                <span style={{ fontSize: 10.5, color: "var(--text-3)", fontFamily: "var(--mono)", fontWeight: 600 }}>{t(`role.${role}`)}</span>
              </div>
            </div>
          </button>
          <button onClick={onSignOut} className="focusable" title="Sign out" style={{
            flex: "none", width: 28, height: 28, borderRadius: 7, display: "flex", alignItems: "center", justifyContent: "center",
            color: "var(--text-faint)", background: "none", border: "none", cursor: "pointer",
          }}>
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
              <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4" />
              <polyline points="15 17 20 12 15 7" />
              <line x1="20" y1="12" x2="9" y2="12" />
            </svg>
          </button>
        </div>
      </div>
    </aside>
  );
}

function StatusLine({ label, state }) {
  const ok = state === "running" || state === "ready";
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 9, padding: "0 4px" }}>
      <span style={{ width: 7, height: 7, borderRadius: 999, flex: "none", background: ok ? "var(--green)" : "var(--amber)" }} />
      <span style={{ fontSize: 12, fontWeight: 600, color: "var(--text-2)" }}>{label}</span>
      <span style={{ marginLeft: "auto", fontFamily: "var(--mono)", fontSize: 11, color: ok ? "var(--green)" : "var(--amber)" }}>{t(`health.${state}`)}</span>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════
// ACTIVE-SCAN IDLE STATE
// ═══════════════════════════════════════════════════════════════════════════
export function ActiveScanIdle({ onPick }) {
  return (
    <div className="fade-up" style={{ maxWidth: "var(--maxw)", margin: "0 auto", padding: "0 28px 80px" }}>
      <ScreenHead eyebrow={t("idle.eyebrow")} title={t("idle.title")} sub={t("idle.sub")} />
      <Card pad="40px 24px" style={{ display: "flex", flexDirection: "column", alignItems: "center", textAlign: "center", gap: 16 }}>
        <span style={{
          width: 52, height: 52, borderRadius: 999, background: "var(--surface-inset)", border: "1px solid var(--border)",
          display: "flex", alignItems: "center", justifyContent: "center", color: "var(--text-faint)",
        }}>
          <IconScan s={24} c="currentColor" />
        </span>
        <div>
          <div style={{ fontSize: 15.5, fontWeight: 600 }}>{t("idle.idle")}</div>
          <div style={{ fontSize: 13, color: "var(--text-3)", marginTop: 4, maxWidth: 360, lineHeight: 1.5 }}>
            {t("idle.desc")}
          </div>
        </div>
        <Button variant="primary" size="md" onClick={onPick} icon={<span style={{ fontSize: 13 }}>▶</span>}>{t("idle.choose")}</Button>
      </Card>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════
// SETTINGS
// ═══════════════════════════════════════════════════════════════════════════
function SettingRow({ label, sub, value, onChange, disabled }) {
  return (
    <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 20, padding: "15px 0", borderTop: "1px solid var(--border-faint)", opacity: disabled ? 0.55 : 1 }}>
      <div>
        <div style={{ fontWeight: 600, fontSize: 13.5 }}>{label}</div>
        {sub && <div style={{ fontSize: 12.5, color: "var(--text-3)", marginTop: 3, lineHeight: 1.5, maxWidth: 520 }}>{sub}</div>}
      </div>
      <button onClick={() => !disabled && onChange(!value)} disabled={disabled} className="focusable" style={{
        width: 42, height: 24, borderRadius: 999, flex: "none", position: "relative", border: "none",
        background: value && !disabled ? "var(--accent)" : "var(--border-strong)",
        transition: "background 0.16s ease", cursor: disabled ? "not-allowed" : "pointer",
      }}>
        <span style={{ position: "absolute", top: 3, left: value ? 21 : 3, width: 18, height: 18, borderRadius: 999, background: "#fff", boxShadow: "var(--shadow-sm)", transition: "left 0.16s cubic-bezier(.3,.7,.3,1)" }} />
      </button>
    </div>
  );
}

export function SettingsScreen({ onSignOut, account, lang, onSetLang }) {
  const role = roleOf(account);
  const rm = ROLE_META[role];
  const isAdmin = role === "admin";
  const handle = handleOf(account);
  const [docker, setDocker] = useState(true);
  const [pin, setPin] = useState(false);
  const [notify, setNotify] = useState(true);
  return (
    <div className="fade-up" style={{ maxWidth: "var(--maxw)", margin: "0 auto", padding: "0 28px 80px" }}>
      <ScreenHead eyebrow={isAdmin ? t("settings.eyebrowAdmin") : t("settings.eyebrowDev")}
        title={isAdmin ? t("settings.titleAdmin") : t("settings.titleDev")}
        sub={isAdmin ? t("settings.subAdmin") : t("settings.subDev")} />

      {/* Language — available to everyone */}
      <SectionLabel>{t("settings.language")}</SectionLabel>
      <Card pad="18px 22px" style={{ marginBottom: 26 }}>
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 16, flexWrap: "wrap" }}>
          <div style={{ fontSize: 13, color: "var(--text-2)", lineHeight: 1.55, maxWidth: 480 }}>
            {t("settings.languageSub")}
          </div>
          <div style={{ display: "inline-flex", background: "var(--surface-inset)", borderRadius: 9, padding: 3, border: "1px solid var(--border)", gap: 2 }}>
            {[{ id: "en", label: "English" }, { id: "ko", label: "한국어" }].map((o) => {
              const on = lang === o.id;
              return (
                <button key={o.id} onClick={() => onSetLang(o.id)} className="focusable" style={{
                  padding: "7px 16px", fontSize: 13, fontWeight: on ? 600 : 500,
                  color: on ? "var(--text)" : "var(--text-3)",
                  background: on ? "var(--surface)" : "transparent",
                  border: on ? "1px solid var(--border)" : "1px solid transparent",
                  borderRadius: 7, boxShadow: on ? "var(--shadow-sm)" : "none", cursor: "pointer",
                }}>{o.label}</button>
              );
            })}
          </div>
        </div>
      </Card>

      {/* Account */}
      <SectionLabel>{t("settings.account")}</SectionLabel>
      <Card pad="20px 22px" style={{ marginBottom: 26 }}>
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 20, flexWrap: "wrap" }}>
          <div style={{ display: "flex", alignItems: "center", gap: 15 }}>
            <span style={{
              width: 46, height: 46, borderRadius: 999, flex: "none",
              background: rm.grad, color: "#fff",
              display: "flex", alignItems: "center", justifyContent: "center",
              fontSize: 19, fontWeight: 700, fontFamily: "var(--mono)",
            }}>{handle[0].toUpperCase()}</span>
            <div>
              <div style={{ display: "flex", alignItems: "center", gap: 9 }}>
                <span style={{ fontSize: 15, fontWeight: 600, fontFamily: "var(--mono)" }}>{handle}@brainoverflow.kr</span>
                <span style={{ fontFamily: "var(--mono)", fontSize: 10.5, fontWeight: 600, letterSpacing: "0.04em", color: rm.badge.fg, background: rm.badge.bg, border: `1px solid ${rm.badge.bd}`, padding: "2px 8px", borderRadius: 6, textTransform: "uppercase" }}>{t(`role.${role}`)}</span>
              </div>
              <div style={{ fontSize: 13, color: "var(--text-3)", marginTop: 4, lineHeight: 1.5, maxWidth: 460 }}>{t(`role.${role}Desc`)}</div>
            </div>
          </div>
          <Button variant="secondary" size="md" onClick={onSignOut}>{t("settings.signOut")}</Button>
        </div>
      </Card>

      {/* Members — admin only */}
      {isAdmin && (
        <React.Fragment>
          <SectionLabel>{t("settings.members")}</SectionLabel>
          <Card pad={0} style={{ marginBottom: 26, overflow: "hidden" }}>
            {[
              { h: "admin", r: "admin" },
              { h: "dev", r: "dev" },
            ].map((m, i) => {
              const mm = ROLE_META[m.r];
              return (
                <div key={m.h} style={{ display: "flex", alignItems: "center", gap: 13, padding: "13px 20px", borderTop: i === 0 ? "none" : "1px solid var(--border-faint)" }}>
                  <span style={{ width: 30, height: 30, borderRadius: 999, flex: "none", background: mm.grad, color: "#fff", display: "flex", alignItems: "center", justifyContent: "center", fontSize: 12.5, fontWeight: 700, fontFamily: "var(--mono)" }}>{m.h[0].toUpperCase()}</span>
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ fontFamily: "var(--mono)", fontSize: 13.5, fontWeight: 600 }}>{m.h}@brainoverflow.kr</div>
                    <div style={{ fontSize: 11.5, color: "var(--text-faint)" }}>{m.h === handle ? t("settings.you") : t("settings.active")}</div>
                  </div>
                  <span style={{ fontFamily: "var(--mono)", fontSize: 10.5, fontWeight: 600, letterSpacing: "0.04em", color: mm.badge.fg, background: mm.badge.bg, border: `1px solid ${mm.badge.bd}`, padding: "2px 8px", borderRadius: 6, textTransform: "uppercase" }}>{t(`role.${m.r}`)}</span>
                </div>
              );
            })}
          </Card>
        </React.Fragment>
      )}

      {/* Scan defaults */}
      <SectionLabel>{t("settings.scanDefaults")} {!isAdmin && <LockTag />}</SectionLabel>
      <Card pad="4px 22px" style={{ marginBottom: 26 }}>
        <SettingRow label={t("settings.docker")} sub={t("settings.dockerSub")} value={docker} onChange={setDocker} disabled={!isAdmin} />
        <SettingRow label={t("settings.pin")} sub={t("settings.pinSub")} value={pin} onChange={setPin} disabled={!isAdmin} />
        <SettingRow label={t("settings.notify")} sub={t("settings.notifySub")} value={notify} onChange={setNotify} disabled={!isAdmin} />
      </Card>
      {!isAdmin && (
        <div style={{ display: "flex", alignItems: "center", gap: 9, margin: "-14px 2px 26px", fontSize: 12.5, color: "var(--text-3)" }}>
          <span style={{ color: "var(--text-faint)" }}>🔒</span>
          {t("settings.lockedNote")}
        </div>
      )}

      {/* Appearance */}
      <SectionLabel>{t("settings.appearance")}</SectionLabel>
      <Card pad="18px 22px">
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 16, flexWrap: "wrap" }}>
          <div style={{ fontSize: 13, color: "var(--text-2)", lineHeight: 1.55, maxWidth: 520 }}>
            {t("settings.appearanceNote")}
          </div>
          <span style={{ fontFamily: "var(--mono)", fontSize: 11.5, color: "var(--text-faint)" }}>Theme · Accent · Density</span>
        </div>
      </Card>
    </div>
  );
}

function LockTag() {
  return (
    <span style={{ fontFamily: "var(--mono)", fontSize: 10, fontWeight: 600, letterSpacing: "0.04em", color: "var(--text-faint)", background: "var(--surface-inset)", border: "1px solid var(--border)", padding: "1px 7px", borderRadius: 5, marginLeft: 8, textTransform: "none" }}>{t("settings.adminOnly")}</span>
  );
}

// ═══════════════════════════════════════════════════════════════════════════
// STATIC SCAN — the registered ruleset
// ═══════════════════════════════════════════════════════════════════════════
const LEVEL_COLOR = {
  ERROR: { fg: "var(--red)", bg: "var(--red-bg)", bd: "var(--red-border)" },
  WARNING: { fg: "var(--amber)", bg: "var(--amber-bg)", bd: "var(--amber-border)" },
  INFO: { fg: "var(--slate)", bg: "var(--slate-bg)", bd: "var(--slate-border)" },
};
const CONF_COLOR = { high: "var(--red)", medium: "var(--amber)", med: "var(--amber)", low: "var(--text-3)" };

export function StaticScanScreen() {
  const { data, loading, error, reload } = useApi(fetchRuleset);
  const [active, setActive] = useState("all");
  const RS = data || { packs: [], scanners: [] };
  const RM = MINOS_DATA.RISK_META;
  const totalRules = RS.packs.reduce((a, p) => a + p.rules.length, 0);
  const packs = active === "all" ? RS.packs : RS.packs.filter((p) => p.risk === active);
  const risks = [...new Set(RS.packs.map((p) => p.risk))];

  const head = (
    <ScreenHead eyebrow={t("static.eyebrow")} title={t("static.title")} sub={t("static.sub")} />
  );
  if (error) {
    return (
      <div className="fade-up" style={{ maxWidth: "var(--maxw)", margin: "0 auto", padding: "0 28px 80px" }}>
        {head}<ErrorState onRetry={reload} />
      </div>
    );
  }
  if (loading && !data) {
    return (
      <div className="fade-up" style={{ maxWidth: "var(--maxw)", margin: "0 auto", padding: "0 28px 80px" }}>
        {head}<Card pad={0}><Loading label={t("static.loading")} /></Card>
      </div>
    );
  }

  return (
    <div className="fade-up" style={{ maxWidth: "var(--maxw)", margin: "0 auto", padding: "0 28px 80px" }}>
      {head}

      {/* scanner families */}
      <SectionLabel>{t("static.families")}</SectionLabel>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(300px, 1fr))", gap: 12, marginBottom: 28 }}>
        {RS.scanners.map((sc) => (
          <Card key={sc.id} pad="15px 16px">
            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 8, marginBottom: 8 }}>
              <span style={{ fontSize: 13.5, fontWeight: 600 }}>{scannerName(sc.id, sc.name)}</span>
              <span style={{ fontFamily: "var(--mono)", fontSize: 10, fontWeight: 600, letterSpacing: "0.04em", color: "var(--text-faint)", background: "var(--surface-inset)", border: "1px solid var(--border)", padding: "2px 7px", borderRadius: 5, textTransform: "uppercase" }}>{sc.engine}</span>
            </div>
            <div style={{ fontSize: 12, color: "var(--text-3)", lineHeight: 1.5 }}>{scannerDesc(sc.id, sc.desc)}</div>
          </Card>
        ))}
      </div>

      {/* semgrep packs */}
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", margin: "0 2px 14px", flexWrap: "wrap", gap: 10 }}>
        <SectionLabel>{t("static.packs")}</SectionLabel>
        <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
          <span style={{ fontFamily: "var(--mono)", fontSize: 11.5, color: "var(--text-3)" }}>{t("static.rulesPacks", { rules: totalRules, packs: RS.packs.length })}</span>
          <RefreshButton onClick={reload} loading={loading} label={t("common.reload")} title="Re-parse static/patterns/*.yaml" />
        </div>
      </div>

      {/* risk filter */}
      <div style={{ display: "flex", gap: 6, marginBottom: 16, flexWrap: "wrap" }}>
        <RuleChip active={active === "all"} onClick={() => setActive("all")}>All</RuleChip>
        {risks.map((r) => (
          <RuleChip key={r} active={active === r} onClick={() => setActive(r)} mono>{r} · {riskName(r, RM[r] ? RM[r].name : r)}</RuleChip>
        ))}
      </div>

      <div style={{ display: "grid", gap: 14 }}>
        {packs.map((pack) => <RulePack key={pack.file} pack={pack} meta={RM[pack.risk] || { name: pack.risk }} />)}
      </div>
    </div>
  );
}

function RuleChip({ children, active, onClick, mono }) {
  return (
    <button onClick={onClick} className="focusable" style={{
      padding: "5px 12px", borderRadius: 999, fontSize: 12.5, fontWeight: active ? 600 : 500,
      fontFamily: mono ? "var(--mono)" : "var(--font)", whiteSpace: "nowrap",
      color: active ? "#fbfbfa" : "var(--text-2)", cursor: "pointer",
      background: active ? "var(--accent)" : "var(--surface)",
      border: `1px solid ${active ? "var(--accent)" : "var(--border-strong)"}`, transition: "all 0.12s ease",
    }}>{children}</button>
  );
}

function RulePack({ pack, meta }) {
  return (
    <Card pad={0} style={{ overflow: "hidden" }}>
      <div style={{ display: "flex", alignItems: "center", gap: 13, padding: "15px 18px", borderBottom: "1px solid var(--border)", background: "var(--surface-2)" }}>
        <span style={{ fontFamily: "var(--mono)", fontWeight: 700, fontSize: 15, color: "var(--text)" }}>{pack.risk}</span>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 9, flexWrap: "wrap" }}>
            <span style={{ fontSize: 14, fontWeight: 600 }}>{riskName(pack.risk, meta.name)}</span>
            {pack.taint && <span style={{ fontFamily: "var(--mono)", fontSize: 10, fontWeight: 600, color: "var(--blue)", background: "var(--blue-bg)", border: "1px solid var(--blue-border)", padding: "1px 7px", borderRadius: 5, letterSpacing: "0.03em" }}>{t("static.taintMode")}</span>}
            <span style={{ fontFamily: "var(--mono)", fontSize: 11, color: "var(--text-faint)" }}>{pack.file}</span>
          </div>
          {pack.summary && <div style={{ fontSize: 12, color: "var(--text-3)", marginTop: 3, lineHeight: 1.5 }}>{packSummary(pack.file, pack.summary)}</div>}
        </div>
        <span style={{ flex: "none", fontFamily: "var(--mono)", fontSize: 11.5, color: "var(--text-3)" }}>{t("static.nRules", { n: pack.rules.length })}</span>
      </div>
      <div>
        {pack.rules.map((rule, i) => {
          const lc = LEVEL_COLOR[rule.level] || LEVEL_COLOR.INFO;
          return (
            <div key={rule.id} style={{
              display: "grid", gridTemplateColumns: "minmax(0,1.5fr) 96px 90px 78px", gap: 14, alignItems: "center",
              padding: "12px 18px", borderTop: i === 0 ? "none" : "1px solid var(--border-faint)",
            }}>
              <div style={{ minWidth: 0 }}>
                <code style={{ fontFamily: "var(--mono)", fontSize: 12, color: "var(--text)", fontWeight: 600 }}>{rule.id}</code>
                <div style={{ fontSize: 12.3, color: "var(--text-3)", marginTop: 3, lineHeight: 1.45 }}>{ruleDesc(rule.id, rule.desc)}</div>
              </div>
              <span style={{ fontFamily: "var(--mono)", fontSize: 11.5, color: "var(--text-3)" }}>{rule.lang}</span>
              <span style={{
                justifySelf: "start", fontFamily: "var(--mono)", fontSize: 10.5, fontWeight: 600, letterSpacing: "0.03em",
                color: lc.fg, background: lc.bg, border: `1px solid ${lc.bd}`, padding: "2px 8px", borderRadius: 5,
              }}>{rule.level}</span>
              <span style={{ justifySelf: "end", fontFamily: "var(--mono)", fontSize: 11.5, color: CONF_COLOR[rule.confidence] || "var(--text-3)" }}>{confLabel(rule.confidence)}</span>
            </div>
          );
        })}
      </div>
    </Card>
  );
}

// ═══════════════════════════════════════════════════════════════════════════
// SCAN RESULTS — list of past sessions (click → report detail)
// ═══════════════════════════════════════════════════════════════════════════
function rt(iso) {
  const days = Math.round((Date.now() - new Date(iso).getTime()) / 86400000);
  if (days <= 0) return "today";
  if (days === 1) return "yesterday";
  if (days < 7) return `${days}d ago`;
  if (days < 30) return `${Math.round(days / 7)}w ago`;
  return `${Math.round(days / 30)}mo ago`;
}

export function ResultsListScreen({ onOpen }) {
  const { data, loading, error, reload } = useApi(fetchSessions);
  const sessions = data || [];
  const [verdict, setVerdict] = useState("all");
  const filtered = verdict === "all" ? sessions : sessions.filter((s) => s.verdict === verdict);
  const counts = sessions.reduce((a, s) => { a[s.verdict] = (a[s.verdict] || 0) + 1; return a; }, {});
  const initial = loading && !data;

  return (
    <div className="fade-up" style={{ maxWidth: "var(--maxw)", margin: "0 auto", padding: "0 28px 80px" }}>
      <ScreenHead eyebrow={t("results.eyebrow")} title={t("results.title")} sub={t("results.sub")} />

      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 12, marginBottom: 16, flexWrap: "wrap" }}>
        <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
          <RuleChip active={verdict === "all"} onClick={() => setVerdict("all")}>{t("results.all")} <span style={{ opacity: 0.6 }}>{sessions.length}</span></RuleChip>
          {["APPROVE", "CONDITIONAL", "REJECT"].map((v) => (
            <RuleChip key={v} active={verdict === v} onClick={() => setVerdict(v)} mono>{v} <span style={{ opacity: 0.6 }}>{counts[v] || 0}</span></RuleChip>
          ))}
        </div>
        <RefreshButton onClick={reload} loading={loading} title="Reload sessions from results/" />
      </div>

      {error ? (
        <ErrorState onRetry={reload} />
      ) : initial ? (
        <Card pad={0}><Loading label={t("results.readingResults")} /></Card>
      ) : (
        <Card pad={0} style={{ overflow: "hidden" }}>
          <div style={{
            display: "grid", gridTemplateColumns: "1.5fr 1fr 150px 1fr 90px", gap: 14,
            padding: "10px 18px", borderBottom: "1px solid var(--border)", background: "var(--surface-2)",
            fontFamily: "var(--mono)", fontSize: 10, fontWeight: 600, letterSpacing: "0.05em", color: "var(--text-faint)", textTransform: "uppercase",
          }}>
            <span>{t("results.col.server")}</span><span>{t("results.col.verdict")}</span><span>{t("results.col.risk")}</span><span>{t("results.col.findings")}</span><span style={{ textAlign: "right" }}>{t("results.col.when")}</span>
          </div>
          {filtered.length === 0 && (
            <div style={{ padding: "28px", textAlign: "center", color: "var(--text-3)", fontSize: 13.5 }}>
              {t("results.empty")}
            </div>
          )}
          {filtered.map((s, i) => <ResultRow key={s.session_id} s={s} last={i === filtered.length - 1} onClick={() => onOpen(s)} />)}
        </Card>
      )}
    </div>
  );
}

function ResultRow({ s, last, onClick }) {
  const [hover, setHover] = useState(false);
  return (
    <div onClick={onClick} onMouseEnter={() => setHover(true)} onMouseLeave={() => setHover(false)}
      style={{
        display: "grid", gridTemplateColumns: "1.5fr 1fr 150px 1fr 90px", gap: 14, alignItems: "center",
        padding: "13px 18px", borderBottom: last ? "none" : "1px solid var(--border-faint)",
        cursor: "pointer", background: hover ? "var(--surface-2)" : "transparent", transition: "background 0.12s ease",
      }}>
      <div style={{ minWidth: 0 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 7 }}>
          <span style={{ fontFamily: "var(--mono)", fontSize: 13.5, fontWeight: 600 }}>{s.server}</span>
          {s.real && <span title="real session — read from results/ on disk" style={{ fontFamily: "var(--mono)", fontSize: 9, color: "var(--green)", background: "var(--green-bg)", border: "1px solid var(--green-border)", padding: "0 5px", borderRadius: 4, letterSpacing: "0.03em" }}>REAL</span>}
        </div>
        <div style={{ fontFamily: "var(--mono)", fontSize: 10.5, color: "var(--text-faint)", marginTop: 2 }}>{s.session_id}</div>
      </div>
      <div><VerdictPill verdict={s.verdict} /></div>
      <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
        <div style={{ flex: 1, minWidth: 28 }}><ScoreBar value={s.overall_score} animate={false} /></div>
        <span className="tnum" style={{ fontFamily: "var(--mono)", fontSize: 11.5, fontWeight: 600, color: scoreColor(s.overall_score) }}>{s.overall_score.toFixed(2)}</span>
      </div>
      <div style={{ fontSize: 12.5, color: "var(--text-2)" }}>
        <span className="tnum" style={{ fontWeight: 600 }}>{s.findings}</span>
        <span style={{ color: "var(--text-faint)" }}> · {s.static_n}s / {s.dynamic_n}d</span>
      </div>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "flex-end", gap: 6 }}>
        <span style={{ fontFamily: "var(--mono)", fontSize: 11.5, color: "var(--text-3)" }}>{rt(s.at)}</span>
        <span style={{ fontSize: 14, color: "var(--text-3)", opacity: hover ? 1 : 0.35, transform: hover ? "translateX(2px)" : "none", transition: "all 0.14s ease" }}>→</span>
      </div>
    </div>
  );
}
