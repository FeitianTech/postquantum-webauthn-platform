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
        'frontend/static/scripts/advanced/mds.js',
        'frontend/static/scripts/advanced/credential-display.js',
        'frontend/static/scripts/shared/storage/local.js',
        'frontend/static/scripts/advanced/json-editor.js',
        'frontend/static/scripts/decoder/codec.js',
        'frontend/static/scripts/decoder/codec/**',
      ],
    },
  },
});
