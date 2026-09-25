import { fileURLToPath } from 'node:url';

import react from '@vitejs/plugin-react';
import { defineConfig } from 'vitest/config';

const here = (path: string) => fileURLToPath(new URL(path, import.meta.url));

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: [
      { find: '@legacy-tests', replacement: here('../tests/frontend') },
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
