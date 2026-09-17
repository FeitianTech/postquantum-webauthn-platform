import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    environment: 'jsdom',
    environmentOptions: {
      jsdom: {
        url: 'http://localhost/',
      },
    },
    setupFiles: ['./tests/frontend/setup.js'],
    include: ['tests/frontend/**/*.test.js'],
    coverage: {
      provider: 'v8',
      all: true,
      reportsDirectory: './coverage/frontend',
      reporter: ['text', 'json-summary', 'html'],
      include: [
        'frontend/static/**/*.js',
      ],
      exclude: [
        'tests/frontend/**',
        'frontend/static/scripts/shared/storage/local.js',
        'frontend/static/scripts/decoder/codec.js',
        'frontend/static/scripts/decoder/codec/**',
      ],
      // A floor, not a target. Set just under the numbers measured on
      // 2026-09-17 (82.59 statements / 66.46 branches / 91.33 functions /
      // 82.71 lines) so a real regression fails the run but ordinary churn
      // does not. Raise these when coverage rises; never lower them to go green.
      thresholds: {
        statements: 82,
        branches: 66,
        functions: 91,
        lines: 82,
      },
    },
  },
});
