import { defineConfig, loadEnv } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, ".", "");
  const proxyTarget = env.VITE_API_PROXY_TARGET;
  const proxy = proxyTarget
    ? {
        "/api": {
          target: proxyTarget,
          changeOrigin: true,
        },
      }
    : undefined;

  return {
    plugins: [react()],
    server: { proxy },
    preview: { proxy },
  };
});
