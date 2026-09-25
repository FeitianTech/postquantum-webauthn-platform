import { defineConfig } from 'vitest/config';

const FULL = { statements: 100, branches: 100, functions: 100, lines: 100 };

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
        // The Codec's logic, which the new UI in web/ imports: every line and branch.
        'frontend/static/scripts/decoder/codec/{constants,labels,request,result,values}.js': FULL,
        'frontend/static/scripts/decoder/codec/encoding/{can-encode,format,summary}.js': FULL,
      },
    },
  },
});
