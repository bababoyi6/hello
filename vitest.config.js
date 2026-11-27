import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vitest/config';

export default defineConfig({
  resolve: {
    alias: { 'cloudflare:sockets': fileURLToPath(new URL('./scripts/node-sockets.mjs', import.meta.url)) },
  },
  test: {
    include: ['tests/*.test.js'],
    exclude: ['tests/*.workers.test.js'],
    setupFiles: ['./scripts/node-sockets.mjs'],
  },
});
