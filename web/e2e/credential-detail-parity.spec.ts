import { readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';

import { betaLevel, betaSubViews, expectedFor, keep, legacyDetail, legacySubViews, openCurrent, report } from './credential-views';
import { expect, test } from './fixtures';
import { readShownText } from './parity';
import { addVirtualAuthenticator } from './virtual-authenticator';

// What a saved credential's details and its registration show in the current UI
// at / (the modal, its registration view, the second modal for a certificate or
// the authenticator data) and in /beta (the dialog's levels), for the same
// stored records and for an advanced credential registered at /: word for word
// per section (layout, separators and controls' own labels set aside:
// parity.ts), and each certificate's and the authenticator data's text equal.
// Every difference must be one listed below, with its reason.

const repo = resolve(import.meta.dirname, '..', '..');

// registration-detail-decodes: ES256, EdDSA, ML-DSA-65 and a packed one with a
// certificate, as the server registered them.
const REGISTERED = JSON.parse(
  readFileSync(join(repo, 'tests', 'app', 'characterization', 'golden', 'routes', 'registration-detail-decodes.json'), 'utf8'),
)
  .requests.filter((entry: { request: string }) => entry.request.includes('/register/complete'))
  .map((entry: { body: { storedCredential: Record<string, unknown> } }) => entry.body.storedCredential);

const RECORDS = ['es256', 'eddsa', 'mldsa65', 'x5c'].map((name, index) => ({
  ...REGISTERED[index],
  type: 'simple',
  userName: `${name}@example.com`,
  email: `${name}@example.com`,
})) as Record<string, unknown>[];

test.describe('a saved credential\'s details in / and in /beta', () => {
  for (const record of RECORDS) {
    const name = record.userName as string;
    test(`show the same words, section by section, and the same certificates and authenticator data: ${name}`, async ({ page }) => {
      await openCurrent(page);
      await keep(page, RECORDS);
      await page.reload();
      await expect(page.locator('body')).toHaveClass(/app-loaded/);
      const legacy = await legacyDetail(page, name);
      const legacySubs = await legacySubViews(page, '#modalBody');

      await page.goto('/beta#simple');
      await page.goto(`/beta#simple/credential/id:${record.credentialIdBase64Url}`);
      const detail = await betaLevel(page, 'detail', 'h4');
      await page.getByRole('dialog').getByRole('button', { name: 'Show registration details' }).click();
      const registration = await betaLevel(page, 'registration', 'h4, [data-parity-heading]');
      const betaSubs = await betaSubViews(page);

      expect(report(legacy, [...detail, ...registration], expectedFor(name))).toEqual([]);
      expect(legacy.map((section) => section.heading)).toEqual(
        [...detail, ...registration].map((section) => section.heading).filter((heading) => heading && heading !== 'Registration Details'),
      );
      expect(betaSubs).toEqual(legacySubs);
    });
  }

  test('an advanced registration\'s result at / shows the words its registration level shows in /beta', async ({ page }) => {
    await addVirtualAuthenticator(page);
    await openCurrent(page);
    await page.locator('[data-action="switch-tab"][data-tab="advanced"]').first().click();
    await page.locator('[data-action="advanced-register"]').click();
    await expect(page.locator('#registrationResultModal')).toBeVisible();
    const legacy = await readShownText(page.locator('#registrationResultBody'), 'h3, h4');
    const legacySubs = await legacySubViews(page, '#registrationResultBody');

    await page.goto('/beta#simple');
    const key = await page.locator('li[data-credential-key]').first().getAttribute('data-credential-key');
    await page.goto(`/beta#simple/credential/${encodeURIComponent(key!).replace(/%3A/gi, ':')}/registration`);
    const beta = await betaLevel(page, 'registration', 'h4, [data-parity-heading]');
    const betaSubs = await betaSubViews(page);

    expect(report(legacy, beta, [])).toEqual([]);
    expect(legacy.map((section) => section.heading)).toEqual(beta.map((section) => section.heading));
    expect(betaSubs).toEqual(legacySubs);
  });
});
