// The site's UI, exported as static files that Flask serves at / (see
// docs/DESIGN.md). Production never runs Node: `next build` writes out/.
import { PHASE_DEVELOPMENT_SERVER } from 'next/constants.js';

import { developmentHeaders } from './scripts/dev-csp.mjs';

export default function nextConfig(phase) {
  const developing = phase === PHASE_DEVELOPMENT_SERVER;
  return {
    // The dev server serves the pages itself; everything else is the export.
    ...(developing ? {} : { output: 'export' }),
    reactStrictMode: true,
    poweredByHeader: false,
    // Tests and fixtures are type-checked by `npm run typecheck`; the build only
    // checks what it ships, so the image does not need the test fixtures.
    typescript: { tsconfigPath: 'tsconfig.build.json' },
    eslint: { ignoreDuringBuilds: true },
    ...(developing
      ? {
          // `npm run dev` beside a local Flask: the API answers from Flask (Next
          // matches /api itself, not under a base path: scripts/dev-csp.test.ts).
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
