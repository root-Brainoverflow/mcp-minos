// main.jsx — entrypoint. Hydrate the data model from the backend (best-effort),
// then render. If the backend is down we render on the bundled sample data.
import React from "react";
import { createRoot } from "react-dom/client";
import App from "./App.jsx";
import { hydrate } from "./api.js";
import "./theme.css";

const root = createRoot(document.getElementById("root"));

// Render immediately — don't block first paint on the backend. Each screen
// fetches its own endpoint (with retry) on mount. hydrate() runs in the
// background only to refresh static lookups (RISK_META, labels) when the
// backend is up; the bundled sample covers them otherwise.
hydrate();
root.render(<App />);
