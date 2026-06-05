import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// During `vite dev`, proxy /api to the backend so the frontend can call the
// FastAPI read-API without CORS. In production (Docker), nginx proxies /api
// instead — see frontend/nginx.conf. Override the dev target with
// VITE_API_PROXY (e.g. http://localhost:8000).
export default defineConfig(({ mode }) => {
  const proxyTarget = process.env.VITE_API_PROXY || "http://localhost:8000";
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
