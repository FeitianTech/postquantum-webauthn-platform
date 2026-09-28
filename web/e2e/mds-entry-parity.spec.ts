import { readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';

import type { Page } from '@playwright/test';

import { expect, test } from './fixtures';
import { type ExpectedDifference, compareShownText, describeDifferences, readShownText } from './parity';
import { recorded } from './recorded';

// What an MDS entry's page, one of its certificates and its raw view showed in the
// current UI at / and show in /beta, over the fixture snapshot serve-flask.mjs
// serves (tests/fixtures/mds): each page's text word for word, section by section
// (layout, separators and controls' own labels set aside: parity.ts), and the raw
// view's text exactly. Every difference must be one listed below, with its reason.
// The current UI's side is its recording (recorded.ts).

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
    only: 'beta',
    section: 'User Verification Details',
    token: /^(Self-attested|FRR|FAR|Max|templates|retries|Block|slowdown|Min|complexity|\d+(\.\d+)?)$/,
    reason: 'the biometric (baDesc) and pattern (paDesc) accuracy, which the current page leaves out (new in /beta)',
  },
];

async function upload(page: Page) {
  const answer = await page.request.post('/api/mds/metadata/upload', {
    multipart: { files: { name: 'custom-metadata.json', mimeType: 'application/json', buffer: readFileSync(UPLOAD) } },
  });
  expect(answer.ok()).toBe(true);
}

async function legacyEntry(page: Page, name: string, count: number) {
  await page.goto('/');
  await expect(page.locator('body')).toHaveClass(/app-loaded/);
  await page.locator('.nav-tab[data-tab="mds"]').first().click();
  await expect(page.locator('#mds-table-body tr:not(.mds-empty-row)')).toHaveCount(count);
  await page.locator('#mds-table-body').getByRole('button', { name, exact: true }).click();
  const modal = page.locator('#mds-authenticator-modal');
  await expect(modal.locator('#mds-authenticator-modal-title')).toHaveText(name);
  await expect(modal.locator('.mds-detail-section').first()).toBeVisible();
  return modal;
}

async function betaEntry(page: Page, entryId: string, name: string) {
  await page.goto(`/beta#mds/${encodeURIComponent(entryId).replace(/%3A/g, ':')}`);
  const entry = page.locator('[data-mds-entry]');
  await expect(entry.getByRole('heading', { level: 3, name })).toBeVisible();
  return entry;
}

test.describe('the MDS entry page reads the same in both UIs', () => {
  const report: string[] = [];

  test.afterAll(async ({}, testInfo) => {
    await testInfo.attach('mds-entry-parity.txt', { body: report.join('\n') || 'no differences', contentType: 'text/plain' });
    console.log(report.join('\n') || 'no differences');
  });

  for (const entry of ENTRIES) {
    test(entry.label, async ({ page }) => {
      if ('upload' in entry) await upload(page);
      const count = 'upload' in entry ? 33 : 32;
      const legacy = await recorded('mds-entry-parity', entry.label, async () => readShownText(await legacyEntry(page, entry.name, count), 'h4'));
      const beta = await readShownText(await betaEntry(page, entry.entryId, entry.name), 'h4');

      expect(beta.map((section) => section.heading)).toEqual(legacy.map((section) => section.heading));
      const differences = compareShownText(legacy, beta, EXPECTED);
      report.push(`${entry.label}:`, ...describeDifferences(differences).map((line) => `  ${line}`));
      expect(describeDifferences(differences.filter((difference) => !difference.reason))).toEqual([]);
      if (entry.name === 'Fixture Key With Every User Verification Method') {
        expect(differences.some((difference) => difference.reason)).toBe(true);
      }
    });
  }

  test('a certificate: its summary and decoded output', async ({ page }) => {
    const legacy = await recorded('mds-entry-parity', 'a certificate', async () => {
      const modal = await legacyEntry(page, 'Fixture Security Key L2', 32);
      await modal.locator('.mds-certificate-button').first().click();
      const legacyPage = page.locator('#mds-certificate-page');
      await expect(legacyPage.locator('#mds-certificate-output')).toContainText('Version');
      return readShownText(legacyPage, 'h4, .mds-certificate-summary__heading');
    });

    await page.goto('/beta#mds/aaguid:f1d0f1d0-0000-4000-8000-000000000002/certificate/1');
    const betaPage = page.locator('[data-mds-certificate]');
    await expect(betaPage.locator('pre').last()).toContainText('Version');
    const beta = await readShownText(betaPage, 'h4');

    expect(beta.map((section) => section.heading)).toEqual(legacy.map((section) => section.heading));
    const differences = compareShownText(legacy, beta, EXPECTED);
    report.push('a certificate:', ...describeDifferences(differences).map((line) => `  ${line}`));
    expect(describeDifferences(differences)).toEqual([]);
  });

  test('the raw view: the same text', async ({ page }) => {
    const { legacyText, legacyTitle, legacySubtitle } = await recorded('mds-entry-parity', 'the raw view', async () => {
      const modal = await legacyEntry(page, 'Fixture U2F Key', 32);
      const [popup] = await Promise.all([page.waitForEvent('popup'), modal.locator('#mds-authenticator-modal-raw').click()]);
      const text = await popup.locator('#mds-raw-textarea').inputValue();
      const title = await popup.locator('#mds-raw-title').textContent();
      const subtitle = await popup.locator('#mds-raw-subtitle').textContent();
      await popup.close();
      return { legacyText: text, legacyTitle: title, legacySubtitle: subtitle };
    });

    await betaEntry(page, 'akid:f1d0000000000000000000000000000000000011', 'Fixture U2F Key');
    await page.locator('[data-mds-entry]').getByRole('button', { name: 'Raw' }).last().click();
    const dialog = page.getByRole('dialog', { name: legacyTitle! });
    await expect(dialog).toBeVisible();
    expect(await dialog.locator('pre').textContent()).toBe(legacyText);
    await expect(dialog).toContainText(legacySubtitle!);
    report.push('the raw view: the same title, subtitle and text');
  });
});
