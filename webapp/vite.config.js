import { defineConfig, loadEnv } from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';

// The dev server proxies /api to the FastAPI backend, so the browser talks to one
// origin and the backend needs no CORS configuration. Override the target with
// VITE_API_TARGET (e.g. VITE_API_TARGET=http://192.168.1.10:8000 npm run dev).
export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), '');
  const target = env.VITE_API_TARGET || 'http://localhost:8000';
  return {
    plugins: [react(), tailwindcss()],
    server: { port: 5173, proxy: { '/api': { target, changeOrigin: true } } },
    preview: { port: 4173, proxy: { '/api': { target, changeOrigin: true } } },
  };
});
