import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    host: "0.0.0.0",
    // Proxy all /api/* calls to Flask — eliminates CORS in dev
    proxy: {
      "/api": {
        target: "http://127.0.0.1:5000",
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/api/, ""),
      },
      "/auth": {
        target: "http://127.0.0.1:5000",
        changeOrigin: true,
      },
    },
  },
});
