// What `npm run dev` sends, so a Content Security Policy violation shows while
// developing, in the console and in Flask's log (reports reach /api/csp-report
// through the dev server's /api rewrite), and not only in the export scan
// (check-export-csp.mjs).
//
// Flask's default policies (server/app/config/security_headers.py), copied here
// as data; tests/app/tooling/test_web_dev_csp.py fails when the two differ.
export const FLASK_POLICY = [
  "default-src 'self'",
  "base-uri 'self'",
  "object-src 'none'",
  "frame-ancestors 'none'",
  "frame-src 'none'",
  "form-action 'self'",
  "img-src 'self' data:",
  "font-src 'self' https://fonts.gstatic.com",
  "style-src 'self' https://fonts.googleapis.com",
  "script-src 'self'",
  "connect-src 'self'",
  "manifest-src 'self'",
  "worker-src 'self'",
  "report-uri /api/csp-report",
  "report-to csp"
];

export const FLASK_REPORT_ONLY_POLICY = [
  "require-trusted-types-for 'script'",
  "report-uri /api/csp-report",
  "report-to csp"
];

export const FLASK_REPORTING_ENDPOINTS = 'csp="/api/csp-report"';

// What the dev server itself needs on top of Flask's policy, and nothing else:
// an inline script, a style attribute and a resource from another origin are
// refused and reported as they are in production. The export needs neither.
export const DEV_ALLOWANCES = [
  {
    directive: 'script-src',
    add: "'unsafe-eval'",
    reason:
      "Next's dev server bundles modules with eval-source-map and puts back any other devtool; " +
      'web/src may not call eval itself (test_web_source_rules.py).',
  },
  {
    directive: 'style-src-elem',
    add: "'unsafe-inline'",
    reason:
      'In development the CSS arrives as <style> elements (next-style-loader, and the style that hides the page ' +
      'until it loads); style-src-attr still falls back to style-src, so a style attribute is refused.',
  },
];

/** Flask's enforced policy with the dev server's allowances, as one header value. */
export function developmentPolicy() {
  const policy = FLASK_POLICY.map((entry) => entry.split(' '));
  for (const { directive, add } of DEV_ALLOWANCES) {
    const own = policy.find(([name]) => name === directive);
    if (own) {
      own.push(add);
      continue;
    }
    // A -elem directive takes over from its parent for elements, so it starts
    // from the parent's sources.
    const parent = policy.findIndex(([name]) => name === directive.replace(/-elem$/, ''));
    policy.splice(parent + 1, 0, [directive, ...policy[parent].slice(1), add]);
  }
  return policy.map((entry) => entry.join(' ')).join('; ');
}

/** The headers `next dev` sends with every page and asset under /beta. */
export function developmentHeaders() {
  return [
    { key: 'Content-Security-Policy', value: developmentPolicy() },
    { key: 'Content-Security-Policy-Report-Only', value: FLASK_REPORT_ONLY_POLICY.join('; ') },
    { key: 'Reporting-Endpoints', value: FLASK_REPORTING_ENDPOINTS },
  ];
}
