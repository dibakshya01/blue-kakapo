import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Built assets are served by the FastAPI control plane from web/dist. During `npm run dev`, API calls
// and the WebSocket are proxied to the local control plane on :8713.
export default defineConfig({
  plugins: [react()],
  base: "/",
  build: { outDir: "dist", emptyOutDir: true },
  server: {
    port: 5173,
    proxy: {
      "/api": { target: "http://127.0.0.1:8713", changeOrigin: true, ws: true },
    },
  },
});
