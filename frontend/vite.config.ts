import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// In dev, the UI talks to the FastAPI service on :8000 through the same /api prefix used in production.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/api": {
        target: process.env.VMDR_API_URL ?? "http://localhost:8000",
        changeOrigin: true,
      },
    },
  },
});
