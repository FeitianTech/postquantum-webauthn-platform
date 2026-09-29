import { readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';

import type { Page } from '@playwright/test';

import { expect, test } from './fixtures';
import { type ExpectedDifference, type ShownSection, compareShownText, describeDifferences, readShownText } from './recorded-words';
import { recorded } from './recorded';

// What an MDS entry's page, one of its certificates and its raw view show, over the
// fixture snapshot serve-flask.mjs serves (tests/fixtures/mds), against their
// recording (recorded.ts): each page's text word for word, section by section
// (layout, separators and controls' own labels set aside: recorded-words.ts), and
// the raw view's text exactly. Every difference must be one listed below, with its
// reason.

const repo = resolve(import.meta.dirname, '..', '..');
const UPLOAD = join(repo, 'tests', 'fixtures', 'mds', 'custom-metadata.json');

const ENTRIES = [
  { label: 'a FIDO2 entry with getInfo and a status history', name: 'Fixture Security Key L1', entryId: 'aaguid:f1d0f1d0-0000-4000-8000-000000000001' },
  { label: 'user-verification descriptors', name: 'Fixture Key With Every User Verification Method', entryId: 'aaguid:f1d0f1d0-0000-4000-8000-000000000007' },
  { label: 'a U2F entry', name: 'Fixture U2F Key', entryId: 'akid:f1d0000000000000000000000000000000000011' },
  { label: 'a UAF entry', name: 'Fixture UAF Authenticator', entryId: 'aaid:F1D0#0012' },
  { label: 'an uploaded entry', name: 'Fixture Uploaded Authenticator', entryId: 'aaguid:f1d0f1d0-0000-4000-8000-000000000099', upload: true },
] as const;

const EXPECTED: ExpectedDifference[] = [
  {
    only: 'shown',
    section: 'User Verification Details',
    token: /^(Self-attested|FRR|FAR|Max|templates|retries|Block|slowdown|Min|complexity|\d+(\.\d+)?)$/,
    reason: 'the biometric (baDesc) and pattern (paDesc) accuracy, which the current page left out (new in the new UI)',
  },
  {
    only: 'shown',
    section: 'Status Reports',
    token: /^(Last|Status|Change|\d{4}-\d{2}-\d{2})$/,
    reason: "the entry's last status change (timeOfLastStatusChange), which the current page left out (new in the new UI)",
  },
  {
    only: 'shown',
    section: 'Status Reports',
    token: /^(Profiles|consumer|enterprise|Sunset|Date|FIPS|Revision|Physical|Security|Level|[23]|Fixture|Future|Field|A|field|no|MDS3|version|defines|Certificate|MII[A-Za-z0-9+/=]{100,})$/,
    reason:
      "a status report's other fields (its profiles, sunset date and FIPS levels, and any a later MDS version adds) and its certificate, which the current page left out (new in the new UI)",
  },
];

async function upload(page: Page) {
  const answer = await page.request.post('/api/mds/metadata/upload', {
    multipart: { files: { name: 'custom-metadata.json', mimeType: 'application/json', buffer: readFileSync(UPLOAD) } },
  });
  expect(answer.ok()).toBe(true);
}

async function betaEntry(page: Page, entryId: string, name: string) {
  await page.goto(`/#mds/${encodeURIComponent(entryId).replace(/%3A/g, ':')}`);
  const entry = page.locator('[data-mds-entry]');
  await expect(entry.getByRole('heading', { level: 3, name })).toBeVisible();
  return entry;
}

test.describe('the MDS entry page reads as recorded', () => {
  const report: string[] = [];

  test.afterAll(async ({}, testInfo) => {
    await testInfo.attach('mds-entry-recorded.txt', { body: report.join('\n') || 'no differences', contentType: 'text/plain' });
    console.log(report.join('\n') || 'no differences');
  });

  for (const entry of ENTRIES) {
    test(entry.label, async ({ page }) => {
      if ('upload' in entry) await upload(page);
      const legacy = recorded<ShownSection[]>('mds-entry', entry.label);
      const beta = await readShownText(await betaEntry(page, entry.entryId, entry.name), 'h4');

      expect(beta.map((section) => section.heading)).toEqual(legacy.map((section) => section.heading));
      const differences = compareShownText(legacy, beta, EXPECTED);
      report.push(`${entry.label}:`, ...describeDifferences(differences).map((line) => `  ${line}`));
      expect(describeDifferences(differences.filter((difference) => !difference.reason))).toEqual([]);
      if (entry.name === 'Fixture Key With Every User Verification Method') {
        expect(differences.some((difference) => difference.reason)).toBe(true);
      }
      if (entry.name === 'Fixture Security Key L1') {
        const statusReports = differences.filter((difference) => difference.section === 'Status Reports');
        expect(statusReports.map((difference) => difference.token)).toEqual(expect.arrayContaining(['Sunset', 'Certificate', 'Future', 'Change']));
      }
    });
  }

  test('a certificate: its summary and decoded output', async ({ page }) => {
    const legacy = recorded<ShownSection[]>('mds-entry', 'a certificate');

    await page.goto('/#mds/aaguid:f1d0f1d0-0000-4000-8000-000000000002/certificate/1');
    const betaPage = page.locator('[data-mds-certificate]');
    await expect(betaPage.locator('pre').last()).toContainText('Version');
    const beta = await readShownText(betaPage, 'h4');

    expect(beta.map((section) => section.heading)).toEqual(legacy.map((section) => section.heading));
    const differences = compareShownText(legacy, beta, EXPECTED);
    report.push('a certificate:', ...describeDifferences(differences).map((line) => `  ${line}`));
    expect(describeDifferences(differences)).toEqual([]);
  });

  test('the raw view: the same text', async ({ page }) => {
    const { legacyText, legacyTitle, legacySubtitle } = recorded<{ legacyText: string; legacyTitle: string; legacySubtitle: string }>(
      'mds-entry',
      'the raw view',
    );

    await betaEntry(page, 'akid:f1d0000000000000000000000000000000000011', 'Fixture U2F Key');
    await page.locator('[data-mds-entry]').getByRole('button', { name: 'Raw' }).last().click();
    const dialog = page.getByRole('dialog', { name: legacyTitle! });
    await expect(dialog).toBeVisible();
    expect(await dialog.locator('pre').textContent()).toBe(legacyText);
    await expect(dialog).toContainText(legacySubtitle!);
    report.push('the raw view: the same title, subtitle and text');
  });
});
