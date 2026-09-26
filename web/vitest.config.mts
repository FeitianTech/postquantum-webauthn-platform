import { fileURLToPath } from 'node:url';

import react from '@vitejs/plugin-react';
import { defineConfig } from 'vitest/config';

const here = (path: string) => fileURLToPath(new URL(path, import.meta.url));

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: [
      { find: '@legacy-tests', replacement: here('../tests/frontend') },
      // The MDS fixture snapshot (tests/fixtures/mds): real server answers to render.
      { find: '@test-fixtures', replacement: here('../tests/fixtures') },
      { find: '@legacy', replacement: here('../frontend/static/scripts') },
      { find: '@', replacement: here('./src') },
      // next/font only runs inside Next's compiler; tests get the class names.
      { find: /^geist\/font\/(sans|mono)$/, replacement: here('./src/test/geist-stub.ts') },
    ],
  },
  server: { fs: { allow: [here('..')] } },
  test: {
    environment: 'jsdom',
    environmentOptions: { jsdom: { url: 'http://localhost/beta' } },
    globals: true,
    setupFiles: ['./src/test/setup.ts'],
    include: ['src/**/*.test.{ts,tsx}', 'scripts/**/*.test.ts'],
    // Cloud Build runs pytest, the root vitest and this suite at once on one
    // two-vCPU machine, where this suite takes about ten times as long as on
    // GitHub's runner (measured 2026-09-26: 388 s against 40 s). Vitest's default
    // five seconds a test failed the MDS dialog's tests there, and only there.
    // A test that hangs still fails, after thirty seconds.
    testTimeout: 30_000,
    coverage: {
      provider: 'v8',
      reportsDirectory: './coverage',
      reporter: ['text', 'json-summary'],
      include: ['src/**/*.{ts,tsx}', 'scripts/**/*.mjs'],
      // Pages only compose components (the design page is a gallery); the
      // components and hooks they use carry the tests.
      exclude: ['src/**/*.test.{ts,tsx}', 'src/test/**', 'src/pages/**'],
      // A floor, not a target: set just under what was measured on 2026-09-25
      // (97.82 statements / 93.63 branches / 96.89 functions / 99.09 lines), so
      // a real regression fails the run. Raise them as coverage rises; never
      // lower them to go green.
      thresholds: {
        statements: 97,
        branches: 92,
        functions: 96,
        lines: 98,
      },
    },
  },
});
