import { fileURLToPath } from 'node:url';

import react from '@vitejs/plugin-react';
import { defineConfig } from 'vitest/config';

const here = (path: string) => fileURLToPath(new URL(path, import.meta.url));

// Every line, branch and function.
const FULL = { statements: 100, branches: 100, functions: 100, lines: 100 };

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: [
      // The MDS fixture snapshot (tests/fixtures/mds): real server answers to render.
      { find: '@test-fixtures', replacement: here('../tests/fixtures') },
      { find: '@', replacement: here('./src') },
    ],
  },
  // Tests read the fixtures and the characterization goldens under ../tests.
  server: { fs: { allow: [here('..')] } },
  test: {
    environment: 'jsdom',
    environmentOptions: { jsdom: { url: 'http://localhost/' } },
    // Each project sets its own files and setup: arrays set here would be joined
    // with a project's rather than replaced by them.
    projects: [
      {
        extends: true,
        test: {
          name: 'components',
          include: ['src/**/*.test.{ts,tsx}', 'scripts/**/*.test.ts'],
          globals: true,
          setupFiles: ['./src/test/setup.ts'],
          // Cloud Build runs pytest and this suite at once on one two-vCPU
          // machine, where the components' tests take about ten times as long as
          // on GitHub's runner (measured 2026-09-26: 388 s against 40 s). Vitest's
          // default five seconds a test failed the MDS dialog's tests there, and
          // only there; under that load reproduced locally (2026-09-27) the
          // longest test, the MDS certificate page's walk through, took 30 s. A
          // test that hangs still fails, after sixty.
          testTimeout: 60_000,
        },
      },
      {
        extends: true,
        test: {
          // The DOM-free logic in src/logic, each module's tests beside it, over
          // a fresh storage, fetch mock and document for every test.
          name: 'logic',
          include: ['src/logic/**/*.test.js'],
          setupFiles: ['./src/test/logic/setup.js'],
          // Under the same load the heaviest of these (the MDS explorer's) passed
          // five seconds; one that hangs fails after thirty.
          testTimeout: 30_000,
        },
      },
    ],
    coverage: {
      provider: 'v8',
      reportsDirectory: './coverage',
      reporter: ['text', 'json-summary'],
      include: ['src/**/*.{ts,tsx}', 'src/logic/**/*.js', 'scripts/**/*.mjs'],
      // Pages only compose components; the components and hooks they use carry
      // the tests.
      exclude: ['src/**/*.test.{ts,tsx}', 'src/**/*.test.js', 'src/test/**', 'src/pages/**'],
      thresholds: {
        // A floor, not a target: set just under what was measured on 2026-10-01
        // (99.51 statements / 98.32 branches / 99.38 functions / 99.85 lines), so
        // a real regression fails the run. Raise them as coverage rises; never
        // lower them to go green.
        statements: 99,
        branches: 98,
        functions: 99,
        lines: 99.5,
        // The logic modules: every line and branch of each.
        'src/logic/**/*.js': FULL,
      },
    },
  },
});
