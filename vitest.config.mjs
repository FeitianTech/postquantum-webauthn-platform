import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    environment: 'jsdom',
    environmentOptions: {
      jsdom: {
        url: 'http://localhost/',
      },
    },
    setupFiles: ['./frontend/tests/setup.js'],
    include: ['frontend/tests/**/*.test.js'],
    coverage: {
      provider: 'v8',
      all: true,
      reportsDirectory: './coverage/frontend',
      reporter: ['text', 'json-summary', 'html'],
      include: [
        'frontend/static/**/*.js',
      ],
      exclude: [
        'frontend/tests/**',
      ],
    },
  },
});
