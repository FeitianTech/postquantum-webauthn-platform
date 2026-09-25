import { test as base, expect } from '@playwright/test';

type Watch = {
  /** Lets a test accept a problem it expects, by its text. */
  allow: (pattern: RegExp) => void;
};

// Every test fails on a console error, an uncaught page error, a Content
// Security Policy or Trusted Types violation, or a report sent to
// /api/csp-report: the pages must run clean under the strict policy.
export const test = base.extend<{ watch: Watch }>({
  watch: [
    async ({ page }, use) => {
      const problems: string[] = [];
      const allowed: RegExp[] = [];
      page.on('console', (message) => {
        const text = message.text();
        if (message.type() === 'error' || /Content Security Policy|Trusted Type/i.test(text)) {
          problems.push(`console ${message.type()}: ${text} (${message.location().url})`);
        }
      });
      page.on('pageerror', (error) => problems.push(`page error: ${error.message}`));
      page.on('request', (request) => {
        if (request.url().includes('/api/csp-report')) problems.push(`CSP report sent: ${request.postData() ?? ''}`);
      });
      await page.addInitScript(() => {
        document.addEventListener('securitypolicyviolation', (event) => {
          console.error(`securitypolicyviolation: ${event.effectiveDirective} blocked ${event.blockedURI}`);
        });
      });

      await use({ allow: (pattern) => allowed.push(pattern) });

      const unexpected = problems.filter((problem) => !allowed.some((pattern) => pattern.test(problem)));
      expect(unexpected, 'console errors, page errors or CSP violations').toEqual([]);
    },
    { auto: true },
  ],
});

export { expect };
