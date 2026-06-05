// ui.jsx — shared primitives for the mcp-minos frontend.
import React, { useState } from "react";
import { MINOS_DATA } from "../data.js";
import { riskName } from "../ruleset_ko.js";
import { t } from "../i18n.js";

// ── Color maps ─────────────────────────────────────────────────────────────
export const SEV_COLOR = {
  CRITICAL: { fg: "var(--red)",    bg: "var(--red-bg)",    bd: "var(--red-border)" },
  HIGH:     { fg: "var(--orange)", bg: "var(--orange-bg)", bd: "var(--orange-border)" },
  MEDIUM:   { fg: "var(--amber)",  bg: "var(--amber-bg)",  bd: "var(--amber-border)" },
  LOW:      { fg: "var(--blue)",   bg: "var(--blue-bg)",   bd: "var(--blue-border)" },
  INFO:     { fg: "var(--slate)",  bg: "var(--slate-bg)",  bd: "var(--slate-border)" },
};
export const VERDICT_COLOR = {
  REJECT:      { fg: "var(--red)",   bg: "var(--red-bg)",   bd: "var(--red-border)" },
  CONDITIONAL: { fg: "var(--amber)", bg: "var(--amber-bg)", bd: "var(--amber-border)" },
  APPROVE:     { fg: "var(--green)", bg: "var(--green-bg)", bd: "var(--green-border)" },
  UNSCANNED:   { fg: "var(--slate)", bg: "var(--slate-bg)", bd: "var(--slate-border)" },
};
export const VERDICT_ICON = { REJECT: "✕", CONDITIONAL: "!", APPROVE: "✓", UNSCANNED: "·" };

export function scoreColor(s) {
  if (s >= 0.75) return "var(--red)";
  if (s >= 0.4) return "var(--amber)";
  if (s > 0) return "var(--blue)";
  return "var(--green)";
}

// ── Logo ───────────────────────────────────────────────────────────────────
// The labyrinth coil + gold core. minos → the labyrinth of King Minos: a gate
// built to contain what's dangerous. The core dot speaks the verdict palette.
const MINOS_COIL = "M42 6 H6 V42 H42 V12 H12 V36 H36 V18 H18 V30 H30 V24";

export function LogoMark({ size = 26, stroke = "var(--text)", dot = "#b07d12", sw = 4.2 }) {
  return (
    <svg width={size} height={size} viewBox="0 0 48 48" fill="none" style={{ flex: "none" }} aria-hidden="true">
      <path d={MINOS_COIL} stroke={stroke} strokeWidth={sw} strokeLinejoin="round" strokeLinecap="round" />
      <circle cx="24" cy="24" r="3.6" fill={dot} />
    </svg>
  );
}

export function Logo({ size = 26 }) {
  const markSize = Math.round(size * 0.92);
  return (
    <span style={{ display: "inline-flex", alignItems: "center", gap: size * 0.36 }}>
      <LogoMark size={markSize} />
      <span style={{ fontSize: size * 0.62, letterSpacing: "-0.03em", lineHeight: 1, display: "inline-flex", alignItems: "baseline" }}>
        <span style={{ fontWeight: 600, color: "var(--text-3)" }}>mcp</span>
        <span style={{ fontWeight: 700, color: "#b07d12", padding: "0 0.05em" }}>·</span>
        <span style={{ fontWeight: 800, color: "var(--text)" }}>minos</span>
      </span>
    </span>
  );
}

// ── Badges ─────────────────────────────────────────────────────────────────
export function SeverityBadge({ level, size = "md" }) {
  const c = SEV_COLOR[level] || SEV_COLOR.INFO;
  const pad = size === "sm" ? "1px 7px" : "3px 9px";
  const fs = size === "sm" ? 11 : 11.5;
  return (
    <span style={{
      display: "inline-flex", alignItems: "center", gap: 5, padding: pad,
      borderRadius: 999, background: c.bg, color: c.fg, border: `1px solid ${c.bd}`,
      fontSize: fs, fontWeight: 600, letterSpacing: "0.02em", lineHeight: 1.4,
      fontFamily: "var(--mono)", textTransform: "uppercase",
    }}>
      <span style={{ width: 6, height: 6, borderRadius: 999, background: c.fg, flex: "none" }} />
      {level}
    </span>
  );
}

export function RiskTag({ code, withName = false }) {
  const meta = MINOS_DATA.RISK_META[code];
  return (
    <span style={{
      display: "inline-flex", alignItems: "center", gap: 6, padding: "2px 8px",
      borderRadius: 6, background: "var(--surface-inset)", border: "1px solid var(--border)",
      fontFamily: "var(--mono)", fontSize: 11.5, fontWeight: 600, color: "var(--text-2)",
    }}>
      <b style={{ color: "var(--text)" }}>{code}</b>
      {withName && meta && <span style={{ color: "var(--text-3)", fontWeight: 500 }}>{riskName(code, meta.name)}</span>}
    </span>
  );
}

export function PhaseTag({ phase }) {
  const map = {
    static: { label: t("report.phase.static"), c: "var(--blue)", bg: "var(--blue-bg)", bd: "var(--blue-border)" },
    dynamic: { label: t("report.phase.dynamic"), c: "var(--orange)", bg: "var(--orange-bg)", bd: "var(--orange-border)" },
  };
  const m = map[phase] || map.static;
  return (
    <span style={{
      fontFamily: "var(--mono)", fontSize: 10, fontWeight: 600, letterSpacing: "0.06em",
      color: m.c, background: m.bg, border: `1px solid ${m.bd}`, padding: "2px 6px",
      borderRadius: 5,
    }}>{m.label}</span>
  );
}

export function VerdictPill({ verdict, size = "md" }) {
  const c = VERDICT_COLOR[verdict] || VERDICT_COLOR.CONDITIONAL;
  const big = size === "lg";
  return (
    <span style={{
      display: "inline-flex", alignItems: "center", gap: 7,
      padding: big ? "6px 14px" : "3px 10px", borderRadius: 999,
      background: c.bg, color: c.fg, border: `1px solid ${c.bd}`,
      fontWeight: 700, fontSize: big ? 14 : 12, letterSpacing: "0.02em",
    }}>
      <span style={{
        width: big ? 18 : 14, height: big ? 18 : 14, borderRadius: 999, background: c.fg,
        color: c.bg, display: "inline-flex", alignItems: "center", justifyContent: "center",
        fontSize: big ? 11 : 9, fontWeight: 800, flex: "none",
      }}>{VERDICT_ICON[verdict]}</span>
      {verdict}
    </span>
  );
}

// ── Buttons ────────────────────────────────────────────────────────────────
export function Button({ children, variant = "primary", size = "md", onClick, disabled, style, icon, title }) {
  const sizes = {
    sm: { p: "6px 11px", fs: 12.5 },
    md: { p: "9px 16px", fs: 13.5 },
    lg: { p: "12px 22px", fs: 14.5 },
  }[size];
  const variants = {
    primary: { background: "var(--accent)", color: "#fbfbfa", border: "1px solid var(--accent)" },
    secondary: { background: "var(--surface)", color: "var(--text)", border: "1px solid var(--border-strong)" },
    ghost: { background: "transparent", color: "var(--text-2)", border: "1px solid transparent" },
    danger: { background: "var(--red)", color: "#fff", border: "1px solid var(--red)" },
  }[variant];
  const [hover, setHover] = useState(false);
  return (
    <button
      className="focusable"
      onClick={disabled ? undefined : onClick}
      onMouseEnter={() => setHover(true)}
      onMouseLeave={() => setHover(false)}
      disabled={disabled}
      title={title}
      style={{
        display: "inline-flex", alignItems: "center", justifyContent: "center", gap: 8,
        padding: sizes.p, fontSize: sizes.fs, fontWeight: 600, borderRadius: var_r(variant),
        transition: "all 0.14s ease", opacity: disabled ? 0.45 : 1,
        cursor: disabled ? "not-allowed" : "pointer",
        boxShadow: variant === "primary" || variant === "danger" ? "var(--shadow-sm)" : "none",
        filter: hover && !disabled ? "brightness(1.08)" : "none",
        transform: hover && !disabled ? "translateY(-1px)" : "none",
        ...variants, ...style,
      }}>
      {icon}{children}
    </button>
  );
}
function var_r() { return "8px"; }

// ── Card ───────────────────────────────────────────────────────────────────
export function Card({ children, style, pad = 0, hover, onClick, className, id }) {
  const [h, setH] = useState(false);
  return (
    <div
      id={id}
      className={("mn-card " + (className || "")).trim()}
      onClick={onClick}
      onMouseEnter={hover ? () => setH(true) : undefined}
      onMouseLeave={hover ? () => setH(false) : undefined}
      style={{
        background: "var(--surface)", border: "1px solid var(--border)",
        borderRadius: "var(--r-lg)", boxShadow: h ? "var(--shadow-md)" : "var(--shadow-sm)",
        transition: "box-shadow 0.16s ease, border-color 0.16s ease, transform 0.16s ease",
        transform: h ? "translateY(-2px)" : "none",
        borderColor: h ? "var(--border-strong)" : "var(--border)",
        cursor: onClick ? "pointer" : "default", padding: pad, ...style,
      }}>
      {children}
    </div>
  );
}

// ── Score bar ──────────────────────────────────────────────────────────────
export function ScoreBar({ value, height = 6, animate = true, delay = 0 }) {
  const c = scoreColor(value);
  return (
    <div style={{ height, borderRadius: 999, background: "var(--surface-inset)", overflow: "hidden", width: "100%" }}>
      <div style={{
        height: "100%", width: `${Math.max(value * 100, value > 0 ? 4 : 0)}%`,
        background: c, borderRadius: 999, transformOrigin: "left",
        animation: animate ? `mn-bar 0.7s cubic-bezier(.3,.7,.3,1) ${delay}s` : "none",
      }} />
    </div>
  );
}

// ── Confidence meter ───────────────────────────────────────────────────────
export function Confidence({ value }) {
  const pct = Math.round(value * 100);
  return (
    <span style={{ display: "inline-flex", alignItems: "center", gap: 7 }}>
      <span style={{ display: "inline-flex", gap: 2 }}>
        {[0, 1, 2, 3, 4].map((i) => (
          <span key={i} style={{
            width: 4, height: 11, borderRadius: 1,
            background: i < Math.round(value * 5) ? "var(--text-2)" : "var(--border-strong)",
          }} />
        ))}
      </span>
      <span className="tnum" style={{ fontFamily: "var(--mono)", fontSize: 11.5, color: "var(--text-3)" }}>{pct}%</span>
    </span>
  );
}

// ── Segmented control ──────────────────────────────────────────────────────
export function Segmented({ options, value, onChange, size = "md" }) {
  const pad = size === "sm" ? "5px 10px" : "7px 14px";
  const fs = size === "sm" ? 12 : 13;
  return (
    <div style={{
      display: "inline-flex", background: "var(--surface-inset)", borderRadius: 9,
      padding: 3, border: "1px solid var(--border)", gap: 2,
    }}>
      {options.map((o) => {
        const val = typeof o === "string" ? o : o.value;
        const label = typeof o === "string" ? o : o.label;
        const count = typeof o === "object" ? o.count : undefined;
        const active = val === value;
        return (
          <button key={val} onClick={() => onChange(val)} className="focusable" style={{
            padding: pad, fontSize: fs, fontWeight: active ? 600 : 500,
            color: active ? "var(--text)" : "var(--text-3)",
            background: active ? "var(--surface)" : "transparent",
            border: active ? "1px solid var(--border)" : "1px solid transparent",
            borderRadius: 7, boxShadow: active ? "var(--shadow-sm)" : "none",
            transition: "all 0.13s ease", display: "inline-flex", alignItems: "center", gap: 7,
          }}>
            {label}
            {count !== undefined && (
              <span className="tnum" style={{
                fontFamily: "var(--mono)", fontSize: 11, fontWeight: 600,
                color: active ? "var(--text-2)" : "var(--text-faint)",
                background: active ? "var(--surface-inset)" : "transparent",
                padding: "0px 5px", borderRadius: 5, minWidth: 16, textAlign: "center",
              }}>{count}</span>
            )}
          </button>
        );
      })}
    </div>
  );
}

// ── Donut (mini) ───────────────────────────────────────────────────────────
export function Donut({ value, size = 132, stroke = 11, color }) {
  const r = (size - stroke) / 2;
  const circ = 2 * Math.PI * r;
  const c = color || scoreColor(value);
  return (
    <svg width={size} height={size} style={{ transform: "rotate(-90deg)" }}>
      <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="var(--surface-inset)" strokeWidth={stroke} />
      <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke={c} strokeWidth={stroke}
        strokeLinecap="round" strokeDasharray={circ}
        strokeDashoffset={circ * (1 - value)}
        style={{ transition: "stroke-dashoffset 1s cubic-bezier(.3,.7,.3,1)" }} />
    </svg>
  );
}

// ── Code / mono block ──────────────────────────────────────────────────────
export function Mono({ children, style, copyable }) {
  const [copied, setCopied] = useState(false);
  const copy = () => {
    navigator.clipboard?.writeText(typeof children === "string" ? children : "").then(() => {
      setCopied(true); setTimeout(() => setCopied(false), 1200);
    });
  };
  return (
    <div style={{ position: "relative" }}>
      <div className="scroll" style={{
        fontFamily: "var(--mono)", fontSize: 12.5, lineHeight: 1.7, color: "var(--text-2)",
        background: "var(--surface-inset)", border: "1px solid var(--border)",
        borderRadius: "var(--r-md)", padding: "11px 13px", overflowX: "auto",
        whiteSpace: "pre", ...style,
      }}>{children}</div>
      {copyable && (
        <button onClick={copy} className="focusable" style={{
          position: "absolute", top: 8, right: 8, fontFamily: "var(--mono)", fontSize: 11,
          padding: "3px 8px", borderRadius: 6, border: "1px solid var(--border-strong)",
          background: "var(--surface)", color: copied ? "var(--green)" : "var(--text-3)",
        }}>{copied ? "copied" : "copy"}</button>
      )}
    </div>
  );
}

// ── Spinner ────────────────────────────────────────────────────────────────
export function Spinner({ size = 15, color = "var(--text-3)" }) {
  return (
    <span style={{
      width: size, height: size, borderRadius: 999, border: `2px solid var(--border-strong)`,
      borderTopColor: color, display: "inline-block", animation: "mn-spin 0.7s linear infinite",
      flex: "none",
    }} />
  );
}

// ── Refresh button ───────────────────────────────────────────────────────────
export function RefreshButton({ onClick, loading, label = "Refresh", title = "Refresh from backend", size = "md", style }) {
  const [hover, setHover] = useState(false);
  const sz = size === "lg" ? { p: "9px 16px", fs: 14, icon: 16 } : { p: "6px 11px", fs: 12.5, icon: 14 };
  const [spinning, setSpinning] = useState(false);
  const timerRef = React.useRef(null);

  const SPIN_TURN_MS = 700; // one rotation
  const SPIN_TURNS = 2;     // spin exactly two full turns on click

  const handleClick = () => {
    // Spin a fixed two rotations so the motion reads clearly even on fast
    // (~20 ms) responses.
    if (timerRef.current) clearTimeout(timerRef.current);
    setSpinning(true);
    timerRef.current = setTimeout(() => setSpinning(false), SPIN_TURN_MS * SPIN_TURNS);
    onClick?.();
  };

  // Manual click → exactly two turns; a slower in-flight load keeps spinning.
  const anim = spinning
    ? `mn-spin ${SPIN_TURN_MS}ms linear ${SPIN_TURNS}`
    : loading
    ? "mn-spin 0.6s linear infinite"
    : "none";

  return (
    <button
      type="button" onClick={handleClick} className="focusable" title={title}
      onMouseEnter={() => setHover(true)} onMouseLeave={() => setHover(false)}
      style={{
        display: "inline-flex", alignItems: "center", gap: 7, padding: sz.p, fontSize: sz.fs,
        fontWeight: 600, fontFamily: "var(--font)", color: "var(--text-2)",
        background: hover ? "var(--surface-2)" : "var(--surface)",
        border: "1px solid var(--border-strong)", borderRadius: 8,
        cursor: "pointer", transition: "background 0.13s ease", ...style,
      }}>
      <svg width={sz.icon} height={sz.icon} viewBox="0 0 24 24" fill="none" stroke="currentColor"
        strokeWidth="2.1" strokeLinecap="round" strokeLinejoin="round"
        style={{ animation: anim }}>
        <path d="M21 12a9 9 0 1 1-2.64-6.36" />
        <polyline points="21 3 21 9 15 9" />
      </svg>
      {label}
    </button>
  );
}

// ── Loading placeholder ──────────────────────────────────────────────────────
export function Loading({ label = "loading…" }) {
  return (
    <div className="fade" style={{
      display: "flex", justifyContent: "center", alignItems: "center", gap: 10,
      padding: "56px 0", color: "var(--text-3)", fontFamily: "var(--mono)", fontSize: 13,
    }}>
      <Spinner size={15} /> {label}
    </div>
  );
}

// ── Error / offline state ────────────────────────────────────────────────────
export function ErrorState({ onRetry, label = "Couldn't reach the backend" }) {
  return (
    <Card pad="36px 24px" style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 14, textAlign: "center" }}>
      <span style={{
        width: 46, height: 46, borderRadius: 999, background: "var(--red-bg)", border: "1px solid var(--red-border)",
        color: "var(--red)", display: "flex", alignItems: "center", justifyContent: "center", fontSize: 22, fontWeight: 800,
      }}>!</span>
      <div>
        <div style={{ fontSize: 15, fontWeight: 600 }}>{label}</div>
        <div style={{ fontSize: 13, color: "var(--text-3)", marginTop: 5, maxWidth: 440, lineHeight: 1.55 }}>
          The API at <code style={{ fontFamily: "var(--mono)" }}>/api</code> didn't respond. Make sure it's running —
          {" "}<code style={{ fontFamily: "var(--mono)" }}>cd backend &amp;&amp; minos-api</code> (port 8000) — then retry.
        </div>
      </div>
      <RefreshButton onClick={onRetry} label="Retry" />
    </Card>
  );
}
