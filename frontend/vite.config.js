import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// During `vite dev`, proxy /api to the backend so the frontend can call the
// FastAPI read-API without CORS. In production (Docker), nginx proxies /api
// instead — see frontend/nginx.conf. Override the dev target with
// VITE_API_PROXY (e.g. http://127.0.0.1:8000).
//
// Default target uses 127.0.0.1 (NOT localhost): on dual-stack hosts Node
// resolves `localhost` to IPv6 `::1` first, but the backend (minos-api) binds
// IPv4 `127.0.0.1` only — so a `localhost` target makes every proxied request
// attempt `::1:8000` first, get ECONNREFUSED, then fall back. During any brief
// backend blip that surfaces as proxy errors / an infinite-loading frontend.
// Pinning to 127.0.0.1 hits the bound interface directly.
export default defineConfig(({ mode }) => {
  const proxyTarget = process.env.VITE_API_PROXY || "http://127.0.0.1:8000";
  return {
    plugins: [react()],
    server: {
      port: 5173,
      proxy: {
        "/api": { target: proxyTarget, changeOrigin: true },
      },
    },
    preview: { port: 4173 },
    build: { outDir: "dist", sourcemap: mode !== "production" },
  };
});
