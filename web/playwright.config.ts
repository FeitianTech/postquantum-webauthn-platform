import { defineConfig, devices } from '@playwright/test';

// Browser tests: Chromium, with its virtual authenticator (the DevTools
// WebAuthn domain) standing in for a security key, against Flask serving both
// the current UI at / and the built export at /beta. Build first:
// `npm run build && npm run e2e`.
const PORT = Number(process.env.E2E_PORT ?? 5151);

export default defineConfig({
  testDir: './e2e',
  // One Flask for the run; the tests are independent but share its stores.
  workers: 1,
  forbidOnly: Boolean(process.env.CI),
  retries: 0,
  reporter: process.env.CI ? [['list'], ['html', { open: 'never' }]] : [['list']],
  globalSetup: './e2e/global-setup.ts',
  use: {
    // localhost, never 127.0.0.1: WebAuthn (and fido2's origin check) accept
    // plain http only on localhost.
    baseURL: `http://localhost:${PORT}`,
    trace: 'retain-on-failure',
  },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
  webServer: {
    command: 'node e2e/serve-flask.mjs',
    url: `http://127.0.0.1:${PORT}/health`,
    env: { E2E_PORT: String(PORT) },
    reuseExistingServer: false,
    timeout: 60_000,
    gracefulShutdown: { signal: 'SIGTERM', timeout: 10_000 },
    stdout: 'pipe',
    stderr: 'pipe',
  },
});
