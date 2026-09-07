import { defineConfig, loadEnv } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), '');
  const backendTarget = env.VITE_API_PROXY_TARGET || 'http://127.0.0.1:8000';
  const proxyConfig = {
    target: backendTarget,
    changeOrigin: true
  };

  return {
    plugins: [react()],
    server: {
      proxy: {
        '/api': proxyConfig,
        '/demo': proxyConfig,
        '/gateway': proxyConfig,
        '/agent': proxyConfig,
        '/agent-runtime': proxyConfig,
        '/approval': proxyConfig,
        '/audit': proxyConfig,
        '/runtime': proxyConfig,
        '/security-overview': proxyConfig,
        '/benchmark-dashboard': proxyConfig,
        '/tool-proxy': proxyConfig,
        '/external-agent': proxyConfig,
        '/test-results': proxyConfig,
        '/sandbox-docker': proxyConfig,
        '/sandbox-native': proxyConfig
      }
    }
  };
});
