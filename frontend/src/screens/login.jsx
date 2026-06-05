// login.jsx — the sign-in gate. Full-screen, no sidebar/topbar.
// Simulated client-side auth: email/password + GitHub/Google (simulated OAuth),
// forgot-password and request-access flows. No real backend (by design).
import React, { useState } from "react";
import { Button, Spinner, Logo, Card } from "../components/ui.jsx";
import { t } from "../i18n.js";

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const ROLE_FROM = (email) => /^admin@/i.test((email || "").trim()) ? "admin" : "dev";
const DEMO_ACCOUNTS = [
  { role: "admin", label: "Admin", email: "admin@brainoverflow.kr" },
  { role: "dev", label: "Developer", email: "dev@brainoverflow.kr" },
];

// ── Field ────────────────────────────────────────────────────────────────────
function Field({ label, type = "text", value, onChange, placeholder, autoComplete, right, id, error, onEnter }) {
  const [focus, setFocus] = useState(false);
  return (
    <label htmlFor={id} style={{ display: "block" }}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 7 }}>
        <span style={{ fontSize: 12.5, fontWeight: 600, color: error ? "var(--red)" : "var(--text-2)" }}>{label}</span>
        {right}
      </div>
      <input
        id={id} type={type} value={value} placeholder={placeholder} autoComplete={autoComplete}
        onChange={(e) => onChange(e.target.value)}
        onKeyDown={(e) => { if (e.key === "Enter" && onEnter) onEnter(e); }}
        onFocus={() => setFocus(true)} onBlur={() => setFocus(false)}
        style={{
          width: "100%", boxSizing: "border-box", padding: "11px 13px", fontSize: 14, fontFamily: "var(--font)",
          color: "var(--text)", background: "var(--surface)", borderRadius: 9,
          border: `1px solid ${error ? "var(--red)" : focus ? "var(--accent)" : "var(--border-strong)"}`,
          boxShadow: focus && !error ? "0 0 0 3px color-mix(in srgb, var(--accent) 16%, transparent)" : error ? "0 0 0 3px color-mix(in srgb, var(--red) 14%, transparent)" : "none",
          outline: "none", transition: "border-color 0.13s ease, box-shadow 0.13s ease",
        }}
      />
      {error && <div style={{ fontSize: 11.5, color: "var(--red)", marginTop: 6 }}>{error}</div>}
    </label>
  );
}

// ── SSO / OAuth buttons ──────────────────────────────────────────────────────
function OAuthButton({ icon, children, onClick, loading, disabled }) {
  const [h, setH] = useState(false);
  return (
    <button onClick={onClick} disabled={disabled} onMouseEnter={() => setH(true)} onMouseLeave={() => setH(false)} className="focusable"
      style={{
        display: "flex", alignItems: "center", justifyContent: "center", gap: 9, width: "100%",
        padding: "10px 14px", fontSize: 13.5, fontWeight: 600, fontFamily: "var(--font)", color: "var(--text)",
        background: h && !disabled ? "var(--surface-2)" : "var(--surface)", border: "1px solid var(--border-strong)",
        borderRadius: 9, cursor: disabled ? "not-allowed" : "pointer", opacity: disabled && !loading ? 0.5 : 1,
        transition: "background 0.12s ease",
      }}>
      {loading ? <Spinner size={15} /> : icon}{loading ? "Connecting…" : children}
    </button>
  );
}
function GitHubIcon() {
  return (
    <svg width="17" height="17" viewBox="0 0 24 24" fill="var(--text)" aria-hidden="true">
      <path d="M12 1.5C6.2 1.5 1.5 6.2 1.5 12c0 4.65 3.0 8.6 7.2 9.98.53.1.72-.23.72-.5v-1.96c-2.93.64-3.55-1.26-3.55-1.26-.48-1.22-1.17-1.55-1.17-1.55-.96-.65.07-.64.07-.64 1.06.08 1.62 1.09 1.62 1.09.94 1.62 2.47 1.15 3.07.88.1-.68.37-1.15.67-1.41-2.34-.27-4.8-1.17-4.8-5.2 0-1.15.41-2.09 1.09-2.83-.11-.27-.47-1.34.1-2.8 0 0 .89-.28 2.9 1.08a10.1 10.1 0 0 1 5.28 0c2.01-1.36 2.9-1.08 2.9-1.08.57 1.46.21 2.53.1 2.8.68.74 1.09 1.68 1.09 2.83 0 4.04-2.46 4.93-4.81 5.19.38.33.71.97.71 1.96v2.9c0 .28.19.61.73.5A10.52 10.52 0 0 0 22.5 12C22.5 6.2 17.8 1.5 12 1.5z" />
    </svg>
  );
}
function GoogleIcon() {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" aria-hidden="true">
      <path fill="#4285F4" d="M23.5 12.27c0-.79-.07-1.54-.2-2.27H12v4.51h6.47a5.53 5.53 0 0 1-2.4 3.63v3h3.87c2.26-2.09 3.56-5.17 3.56-8.87z" />
      <path fill="#34A853" d="M12 24c3.24 0 5.95-1.08 7.94-2.91l-3.87-3c-1.08.72-2.45 1.15-4.07 1.15-3.13 0-5.78-2.11-6.73-4.96H1.27v3.09A12 12 0 0 0 12 24z" />
      <path fill="#FBBC05" d="M5.27 14.28a7.2 7.2 0 0 1 0-4.56V6.63H1.27a12 12 0 0 0 0 10.74l4-3.09z" />
      <path fill="#EA4335" d="M12 4.75c1.77 0 3.35.61 4.6 1.8l3.43-3.43C17.95 1.18 15.24 0 12 0A12 12 0 0 0 1.27 6.63l4 3.09C6.22 6.86 8.87 4.75 12 4.75z" />
    </svg>
  );
}

// ── Workspace chip ───────────────────────────────────────────────────────────
function WorkspaceChip() {
  return (
    <div style={{ display: "inline-flex", alignItems: "center", gap: 8, padding: "4px 10px 4px 8px", borderRadius: 999, background: "var(--surface-2)", border: "1px solid var(--border)", marginBottom: 14 }}>
      <span style={{ width: 18, height: 18, borderRadius: 999, background: "linear-gradient(135deg, #b07d12, #8a6a2e)", color: "#fff", display: "flex", alignItems: "center", justifyContent: "center", fontFamily: "var(--mono)", fontSize: 10, fontWeight: 700 }}>b</span>
      <span style={{ fontFamily: "var(--mono)", fontSize: 12, color: "var(--text-2)", fontWeight: 600 }}>brainoverflow</span>
    </div>
  );
}

// ── Auth card (the full right-column content; mode-driven) ───────────────────
function AuthCard({ onSignIn, center }) {
  const [mode, setMode] = useState("signin"); // signin | forgot | request | sent | requested
  const [email, setEmail] = useState("dev@brainoverflow.kr");
  const [pw, setPw] = useState("minos-demo");
  const [name, setName] = useState("");
  const [show, setShow] = useState(false);
  const [keep, setKeep] = useState(true);
  const [err, setErr] = useState({});
  const [loading, setLoading] = useState(false);
  const [oauth, setOauth] = useState(null); // 'github' | 'google'

  const busy = loading || !!oauth;
  const align = center ? "center" : "left";

  const reset = (m) => { setErr({}); setMode(m); };

  const submitSignIn = () => {
    const e = {};
    if (!EMAIL_RE.test(email.trim())) e.email = "Enter a valid email address.";
    if (pw.length < 6) e.pw = "Password must be at least 6 characters.";
    setErr(e);
    if (Object.keys(e).length) return;
    setLoading(true);
    setTimeout(() => { setLoading(false); onSignIn("password", email.trim(), keep, ROLE_FROM(email)); }, 850);
  };

  const startOauth = (provider) => {
    if (busy) return;
    setErr({}); setOauth(provider);
    setTimeout(() => { setOauth(null); onSignIn(provider, email.trim(), keep, ROLE_FROM(email)); }, 1100);
  };

  const submitForgot = () => {
    if (!EMAIL_RE.test(email.trim())) { setErr({ email: "Enter a valid email address." }); return; }
    setErr({}); setLoading(true);
    setTimeout(() => { setLoading(false); setMode("sent"); }, 700);
  };

  const submitRequest = () => {
    const e = {};
    if (!name.trim()) e.name = "Enter your name.";
    if (!EMAIL_RE.test(email.trim())) e.email = "Enter a valid work email.";
    setErr(e);
    if (Object.keys(e).length) return;
    setLoading(true);
    setTimeout(() => { setLoading(false); setMode("requested"); }, 750);
  };

  // ── Confirmation states ──
  if (mode === "sent" || mode === "requested") {
    const isReset = mode === "sent";
    return (
      <div style={{ width: "100%", maxWidth: 372, textAlign: align }}>
        <WorkspaceChip />
        <div style={{ display: "flex", justifyContent: center ? "center" : "flex-start", marginBottom: 16 }}>
          <span style={{ width: 46, height: 46, borderRadius: 999, background: "var(--green-bg)", border: "1px solid var(--green-border)", color: "var(--green)", display: "flex", alignItems: "center", justifyContent: "center", fontSize: 22, fontWeight: 800 }}>✓</span>
        </div>
        <h1 style={{ margin: 0, fontSize: 22, fontWeight: 700, letterSpacing: "-0.02em" }}>{isReset ? t("login.checkInbox") : t("login.requestReceived")}</h1>
        <p style={{ margin: "9px 0 22px", fontSize: 13.5, color: "var(--text-3)", lineHeight: 1.55 }}>
          {isReset
            ? <>We sent a password reset link to <b style={{ color: "var(--text-2)", fontFamily: "var(--mono)" }}>{email.trim()}</b>. The link expires in 30 minutes.</>
            : <>Thanks — your access request for <b style={{ color: "var(--text-2)", fontFamily: "var(--mono)" }}>{email.trim()}</b> is in. A workspace admin will review it shortly.</>}
        </p>
        <Button variant="secondary" size="md" onClick={() => reset("signin")} style={{ width: "100%", justifyContent: "center", padding: "11px" }}>{t("login.backToSignInBtn")}</Button>
      </div>
    );
  }

  // ── Forgot password ──
  if (mode === "forgot") {
    return (
      <div style={{ width: "100%", maxWidth: 372, textAlign: align }}>
        <WorkspaceChip />
        <h1 style={{ margin: 0, fontSize: 23, fontWeight: 700, letterSpacing: "-0.02em" }}>{t("login.resetTitle")}</h1>
        <p style={{ margin: "8px 0 22px", fontSize: 13.5, color: "var(--text-3)", lineHeight: 1.5 }}>
          {t("login.resetSub")}
        </p>
        <div style={{ display: "grid", gap: 15, textAlign: "left" }}>
          <Field id="femail" label={t("login.email")} type="email" value={email} onChange={setEmail} placeholder="you@company.com" autoComplete="email" error={err.email} onEnter={submitForgot} />
          <Button variant="primary" size="md" onClick={submitForgot} disabled={loading} style={{ width: "100%", justifyContent: "center", padding: "11px", fontSize: 14 }}>
            {loading ? <Spinner size={15} color="#fff" /> : t("login.sendReset")}
          </Button>
          <button type="button" onClick={() => reset("signin")} style={{ background: "none", border: "none", cursor: "pointer", fontSize: 12.5, color: "var(--text-3)", fontWeight: 600, justifySelf: center ? "center" : "start" }}>{t("login.backToSignIn")}</button>
        </div>
      </div>
    );
  }

  // ── Request access ──
  if (mode === "request") {
    return (
      <div style={{ width: "100%", maxWidth: 372, textAlign: align }}>
        <WorkspaceChip />
        <h1 style={{ margin: 0, fontSize: 23, fontWeight: 700, letterSpacing: "-0.02em" }}>{t("login.requestTitle")}</h1>
        <p style={{ margin: "8px 0 22px", fontSize: 13.5, color: "var(--text-3)", lineHeight: 1.5 }}>
          Ask a workspace admin to add you to <b style={{ color: "var(--text-2)" }}>brainoverflow</b>.
        </p>
        <div style={{ display: "grid", gap: 15, textAlign: "left" }}>
          <Field id="rname" label={t("login.fullName")} value={name} onChange={setName} placeholder="Ada Lovelace" autoComplete="name" error={err.name} />
          <Field id="remail" label={t("login.workEmail")} type="email" value={email} onChange={setEmail} placeholder="you@company.com" autoComplete="email" error={err.email} onEnter={submitRequest} />
          <Button variant="primary" size="md" onClick={submitRequest} disabled={loading} style={{ width: "100%", justifyContent: "center", padding: "11px", fontSize: 14 }}>
            {loading ? <Spinner size={15} color="#fff" /> : t("login.requestAccess")}
          </Button>
          <button type="button" onClick={() => reset("signin")} style={{ background: "none", border: "none", cursor: "pointer", fontSize: 12.5, color: "var(--text-3)", fontWeight: 600, justifySelf: center ? "center" : "start" }}>{t("login.backToSignIn")}</button>
        </div>
      </div>
    );
  }

  // ── Sign in (default) ──
  return (
    <div style={{ width: "100%", maxWidth: 372 }}>
      <div style={{ textAlign: align }}>
        <WorkspaceChip />
        <h1 style={{ margin: 0, fontSize: 23, fontWeight: 700, letterSpacing: "-0.02em" }}>{t("login.signInTitle")}</h1>
        <p style={{ margin: "8px 0 0", fontSize: 13.5, color: "var(--text-3)", lineHeight: 1.5 }}>
          {t("login.signInSub")}
        </p>
      </div>

      <div style={{ display: "grid", gap: 15, marginTop: 24, textAlign: "left" }}>
        {/* demo account switcher */}
        <div>
          <div style={{ fontSize: 11.5, fontWeight: 600, color: "var(--text-3)", marginBottom: 7, fontFamily: "var(--mono)", letterSpacing: "0.03em", textTransform: "uppercase" }}>{t("login.signInAs")}</div>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8 }}>
            {DEMO_ACCOUNTS.map((a) => {
              const active = ROLE_FROM(email) === a.role;
              return (
                <button key={a.role} type="button" onClick={() => { setEmail(a.email); setPw("minos-demo"); setErr({}); }}
                  style={{
                    display: "flex", flexDirection: "column", alignItems: "flex-start", gap: 2, padding: "9px 12px", borderRadius: 9,
                    cursor: "pointer", textAlign: "left",
                    background: active ? "var(--surface-2)" : "var(--surface)",
                    border: `1px solid ${active ? "var(--accent)" : "var(--border-strong)"}`,
                    boxShadow: active ? "0 0 0 3px color-mix(in srgb, var(--accent) 14%, transparent)" : "none",
                    transition: "all 0.12s ease",
                  }}>
                  <span style={{ fontSize: 13, fontWeight: 600, color: "var(--text)" }}>{a.label}</span>
                  <span style={{ fontFamily: "var(--mono)", fontSize: 10.5, color: "var(--text-faint)" }}>{a.role === "admin" ? t("login.fullAccess") : t("login.restricted")}</span>
                </button>
              );
            })}
          </div>
        </div>

        <Field id="email" label={t("login.email")} type="email" value={email} onChange={setEmail} placeholder="you@company.com" autoComplete="email" error={err.email} onEnter={submitSignIn} />
        <Field id="pw" label={t("login.password")} type={show ? "text" : "password"} value={pw} onChange={setPw} placeholder="••••••••" autoComplete="current-password" error={err.pw} onEnter={submitSignIn}
          right={<button type="button" onClick={() => setShow(!show)} style={{ fontFamily: "var(--mono)", fontSize: 11, color: "var(--text-3)", background: "none", border: "none", cursor: "pointer", padding: 0 }}>{show ? t("login.hide") : t("login.show")}</button>} />

        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginTop: -2 }}>
          <label style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 12.5, color: "var(--text-2)", cursor: "pointer", whiteSpace: "nowrap" }}>
            <input type="checkbox" checked={keep} onChange={(e) => setKeep(e.target.checked)} style={{ accentColor: "var(--accent)", width: 15, height: 15 }} />
            {t("login.keep")}
          </label>
          <button type="button" onClick={() => reset("forgot")} style={{ fontSize: 12.5, color: "var(--accent)", background: "none", border: "none", cursor: "pointer", fontWeight: 600, padding: 0 }}>{t("login.forgot")}</button>
        </div>

        <Button variant="primary" size="md" onClick={submitSignIn} disabled={busy} style={{ width: "100%", justifyContent: "center", padding: "11px", fontSize: 14 }}>
          {loading ? <Spinner size={15} color="#fff" /> : t("login.signIn")}
        </Button>

        <div style={{ display: "flex", alignItems: "center", gap: 12, margin: "2px 0" }}>
          <span style={{ flex: 1, height: 1, background: "var(--border)" }} />
          <span style={{ fontFamily: "var(--mono)", fontSize: 10.5, color: "var(--text-faint)", letterSpacing: "0.04em", whiteSpace: "nowrap" }}>{t("login.orContinue")}</span>
          <span style={{ flex: 1, height: 1, background: "var(--border)" }} />
        </div>

        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
          <OAuthButton icon={<GitHubIcon />} onClick={() => startOauth("github")} loading={oauth === "github"} disabled={busy && oauth !== "github"}>GitHub</OAuthButton>
          <OAuthButton icon={<GoogleIcon />} onClick={() => startOauth("google")} loading={oauth === "google"} disabled={busy && oauth !== "google"}>Google</OAuthButton>
        </div>

        <div style={{ textAlign: "center", fontSize: 12.5, color: "var(--text-3)", marginTop: 4 }}>
          {t("login.newTo")} <button type="button" onClick={() => reset("request")} style={{ color: "var(--accent)", background: "none", border: "none", cursor: "pointer", fontWeight: 600, padding: 0, fontSize: 12.5, whiteSpace: "nowrap" }}>{t("login.requestAccess")}</button>
        </div>
      </div>
    </div>
  );
}

// ── Brand panel (split layout left side) ─────────────────────────────────────
function BrandPanel() {
  return (
    <div style={{
      position: "relative", overflow: "hidden", background: "#1b1a17", color: "#e9e8e3",
      padding: "48px 52px", display: "flex", flexDirection: "column", justifyContent: "space-between",
    }}>
      <svg viewBox="0 0 48 48" aria-hidden="true" style={{ position: "absolute", right: -90, bottom: -90, width: 460, height: 460, opacity: 0.07 }}>
        <path d="M42 6 H6 V42 H42 V12 H12 V36 H36 V18 H18 V30 H30 V24" stroke="#e9e8e3" strokeWidth="2.6" fill="none" strokeLinejoin="round" strokeLinecap="round" />
      </svg>

      <div style={{ position: "relative", display: "flex", alignItems: "center", gap: 11 }}>
        <svg width="30" height="30" viewBox="0 0 48 48" fill="none" aria-hidden="true">
          <path d="M42 6 H6 V42 H42 V12 H12 V36 H36 V18 H18 V30 H30 V24" stroke="#f4f3ee" strokeWidth="4.2" strokeLinejoin="round" strokeLinecap="round" />
          <circle cx="24" cy="24" r="3.6" fill="#d39a25" />
        </svg>
        <span style={{ fontSize: 17, letterSpacing: "-0.02em", display: "inline-flex", alignItems: "baseline" }}>
          <span style={{ fontWeight: 600, color: "#a8a69d" }}>mcp</span>
          <span style={{ fontWeight: 700, color: "#d39a25", padding: "0 0.05em" }}>·</span>
          <span style={{ fontWeight: 800, color: "#f4f3ee" }}>minos</span>
        </span>
      </div>

      <div style={{ position: "relative", maxWidth: 380 }}>
        <h2 style={{ margin: 0, fontSize: 28, fontWeight: 700, letterSpacing: "-0.025em", lineHeight: 1.2, color: "#f4f3ee" }}>
          {t("login.brandTitle")}
        </h2>
        <p style={{ margin: "16px 0 0", fontSize: 14, lineHeight: 1.6, color: "#b7b5ab" }}>
          {t("login.brandSub")}
        </p>
        <div style={{ display: "grid", gap: 11, marginTop: 26 }}>
          {[t("login.feature1"), t("login.feature2"), t("login.feature3")].map((f) => (
            <div key={f} style={{ display: "flex", alignItems: "center", gap: 10, fontSize: 13, color: "#cfcdc3" }}>
              <span style={{ width: 16, height: 16, borderRadius: 999, flex: "none", background: "rgba(211,154,37,0.18)", color: "#d39a25", display: "flex", alignItems: "center", justifyContent: "center", fontSize: 10, fontWeight: 700 }}>✓</span>
              {f}
            </div>
          ))}
        </div>
      </div>

      <div style={{ position: "relative", fontFamily: "var(--mono)", fontSize: 11, color: "#76746b", letterSpacing: "0.03em" }}>
        v0.1 · local-first · SOC 2 in progress
      </div>
    </div>
  );
}

// ── Login screen ─────────────────────────────────────────────────────────────
export function LoginScreen({ onSignIn, layout = "split" }) {
  if (layout === "centered") {
    return (
      <div style={{ minHeight: "100vh", background: "var(--bg)", display: "flex", alignItems: "center", justifyContent: "center", padding: "40px 20px" }}>
        <svg viewBox="0 0 48 48" aria-hidden="true" style={{ position: "fixed", left: "50%", top: "50%", transform: "translate(-50%,-50%)", width: 620, height: 620, opacity: 0.04, pointerEvents: "none" }}>
          <path d="M42 6 H6 V42 H42 V12 H12 V36 H36 V18 H18 V30 H30 V24" stroke="var(--text)" strokeWidth="2" fill="none" strokeLinejoin="round" strokeLinecap="round" />
        </svg>
        <div className="fade-up" style={{ position: "relative", width: "100%", maxWidth: 416 }}>
          <Card pad="36px 38px 32px" style={{ boxShadow: "var(--shadow-lg)" }}>
            <div style={{ display: "flex", justifyContent: "center", marginBottom: 20 }}><Logo size={26} /></div>
            <div style={{ display: "flex", justifyContent: "center" }}><AuthCard onSignIn={onSignIn} center /></div>
          </Card>
        </div>
      </div>
    );
  }
  return (
    <div className="login-split" style={{ minHeight: "100vh", display: "grid", gridTemplateColumns: "1.05fr 1fr", background: "var(--bg)" }}>
      <BrandPanel />
      <div style={{ display: "flex", alignItems: "center", justifyContent: "center", padding: "48px 28px" }}>
        <div className="fade-up" style={{ width: "100%", maxWidth: 372 }}>
          <div className="login-mobile-logo" style={{ display: "none", marginBottom: 24 }}><Logo size={24} /></div>
          <AuthCard onSignIn={onSignIn} />
        </div>
      </div>
    </div>
  );
}
