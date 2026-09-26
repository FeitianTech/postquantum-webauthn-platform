// @vitest-environment node
// next.config.mjs finds the repository from its own file: URL, which needs Node's URL.
import { PHASE_DEVELOPMENT_SERVER, PHASE_PRODUCTION_BUILD } from 'next/constants.js';

import nextConfig from '../next.config.mjs';

import {
  DEV_ALLOWANCES,
  FLASK_POLICY,
  FLASK_REPORT_ONLY_POLICY,
  FLASK_REPORTING_ENDPOINTS,
  developmentHeaders,
  developmentPolicy,
} from './dev-csp.mjs';

const directives = (policy: string) => new Map(policy.split('; ').map((entry) => [entry.split(' ')[0], entry]));

describe('the dev server\'s Content Security Policy', () => {
  it('is Flask\'s, with only the two allowances the dev server needs, each with its reason', () => {
    const dev = directives(developmentPolicy());
    const flask = directives(FLASK_POLICY.join('; '));
    for (const [name, entry] of flask) {
      if (name !== 'script-src') expect(dev.get(name)).toBe(entry);
    }
    expect(dev.get('script-src')).toBe("script-src 'self' 'unsafe-eval'");
    expect(dev.get('style-src-elem')).toBe("style-src-elem 'self' https://fonts.googleapis.com 'unsafe-inline'");
    expect([...dev.keys()].filter((name) => !flask.has(name))).toEqual(['style-src-elem']);
    expect(DEV_ALLOWANCES.map(({ directive, add }) => `${directive} ${add}`)).toEqual([
      "script-src 'unsafe-eval'",
      "style-src-elem 'unsafe-inline'",
    ]);
    for (const allowance of DEV_ALLOWANCES) expect(allowance.reason.length).toBeGreaterThan(40);
  });

  it('still refuses inline scripts and style attributes', () => {
    const dev = directives(developmentPolicy());
    expect(dev.get('script-src')).not.toContain("'unsafe-inline'");
    expect(dev.get('style-src')).not.toContain("'unsafe-inline'");
    expect(dev.has('style-src-attr')).toBe(false);
  });

  it('sends the policy, the Trusted Types report-only policy and where reports go', () => {
    expect(developmentHeaders()).toEqual([
      { key: 'Content-Security-Policy', value: developmentPolicy() },
      { key: 'Content-Security-Policy-Report-Only', value: FLASK_REPORT_ONLY_POLICY.join('; ') },
      { key: 'Reporting-Endpoints', value: FLASK_REPORTING_ENDPOINTS },
    ]);
  });

  it('is sent by `next dev` for every path, and not configured for the export', async () => {
    const dev = nextConfig(PHASE_DEVELOPMENT_SERVER);
    expect(await dev.headers!()).toEqual([{ source: '/:path*', headers: developmentHeaders() }]);
    expect(await dev.rewrites!()).toEqual([
      { source: '/api/:path*', destination: 'http://localhost:8000/api/:path*', basePath: false },
    ]);
    const build = nextConfig(PHASE_PRODUCTION_BUILD);
    expect(build.output).toBe('export');
    expect(build).not.toHaveProperty('headers');
  });
});
