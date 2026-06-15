// settings.js — persisted workspace scan defaults (localStorage-backed).
//
// Shared by the Settings screen (edits) and the Configure screen (reads the
// docker default) so the toggles actually drive behaviour.

const KEY = "minos_settings";

const DEFAULTS = {
  docker: true,   // run scans in the Docker sandbox by default
  pin: false,     // require version-pinned manifests (advisory flag)
  notify: true,   // desktop notification on REJECT verdict
};

export function getSettings() {
  try {
    const raw = JSON.parse(localStorage.getItem(KEY) || "null");
    return { ...DEFAULTS, ...(raw || {}) };
  } catch {
    return { ...DEFAULTS };
  }
}

export function setSettings(patch) {
  const next = { ...getSettings(), ...patch };
  try { localStorage.setItem(KEY, JSON.stringify(next)); } catch { /* ignore */ }
  return next;
}

/** Fire a desktop notification for a REJECT verdict (if enabled + permitted). */
export function notifyReject(serverName) {
  if (!getSettings().notify) return;
  if (typeof Notification === "undefined") return;
  const show = () => {
    try {
      new Notification("mcp-minos — REJECT", {
        body: `${serverName || "server"} failed the pre-deploy gate.`,
      });
    } catch { /* notification construction can throw on some platforms */ }
  };
  if (Notification.permission === "granted") show();
  else if (Notification.permission !== "denied") {
    Notification.requestPermission().then((p) => { if (p === "granted") show(); });
  }
}
