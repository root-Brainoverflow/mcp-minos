// common.jsx — small layout primitives shared across screens.
import React from "react";

export function ScreenHead({ eyebrow, title, sub, subMaxWidth = 640 }) {
  return (
    <div style={{ padding: "10px 0 26px" }}>
      {eyebrow && <div style={{ fontFamily: "var(--mono)", fontSize: 11.5, fontWeight: 600, letterSpacing: "0.08em", color: "var(--text-3)", marginBottom: 12 }}>{eyebrow}</div>}
      <h1 style={{ margin: 0, fontSize: 28, fontWeight: 700, letterSpacing: "-0.02em", lineHeight: 1.15 }}>{title}</h1>
      {sub && <p style={{ margin: "10px 0 0", fontSize: 14.5, color: "var(--text-2)", lineHeight: 1.55, maxWidth: subMaxWidth }}>{sub}</p>}
    </div>
  );
}

export function SectionLabel({ children }) {
  return <div style={{ fontSize: 12, fontWeight: 600, letterSpacing: "0.04em", color: "var(--text-3)", textTransform: "uppercase", marginBottom: 12, fontFamily: "var(--mono)" }}>{children}</div>;
}

export function Meta({ label, value }) {
  return (
    <div>
      <div style={{ fontSize: 11, color: "var(--text-faint)", fontFamily: "var(--mono)", marginBottom: 3, textTransform: "uppercase", letterSpacing: "0.04em" }}>{label}</div>
      <div style={{ fontSize: 13.5, fontWeight: 500, color: "var(--text-2)" }}>{value}</div>
    </div>
  );
}
