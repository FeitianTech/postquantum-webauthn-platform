// The new UI, exported as static files that Flask serves at /beta (see
// docs/UI_MIGRATION.md). Production never runs Node: `next build` writes out/.
import { fileURLToPath } from 'node:url';

import { PHASE_DEVELOPMENT_SERVER } from 'next/constants.js';

import { developmentHeaders } from './scripts/dev-csp.mjs';

export default function nextConfig(phase) {
  const developing = phase === PHASE_DEVELOPMENT_SERVER;
  return {
    basePath: '/beta',
    // The dev server serves the pages itself; everything else is the export.
    ...(developing ? {} : { output: 'export' }),
    reactStrictMode: true,
    poweredByHeader: false,
    // The logic modules still live in frontend/static/scripts until the cutover;
    // they are imported from there, never copied.
    experimental: { externalDir: true },
    // The repository is the workspace: web/ imports from ../frontend.
    outputFileTracingRoot: fileURLToPath(new URL('..', import.meta.url)),
    // Tests and fixtures are type-checked by `npm run typecheck`; the build only
    // checks what it ships, so the image does not need the test fixtures.
    typescript: { tsconfigPath: 'tsconfig.build.json' },
    eslint: { ignoreDuringBuilds: true },
    ...(developing
      ? {
          // `npm run dev` beside a local Flask: the API answers from Flask.
          async rewrites() {
            const flask = process.env.FLASK_URL ?? 'http://localhost:8000';
            return [{ source: '/api/:path*', destination: `${flask}/api/:path*`, basePath: false }];
          },
          // Flask's CSP, so a violation shows while developing (scripts/dev-csp.mjs).
          // Flask sends it with the export; headers() does not apply to one.
          async headers() {
            return [{ source: '/:path*', headers: developmentHeaders() }];
          },
        }
      : {}),
  };
}
