import type { Page } from '@playwright/test';

import { expect, test } from './fixtures';
import { type ExpectedDifference, type ShownSection, compareShownText, describeDifferences, readShownRows } from './recorded-words';
import { recorded } from './recorded';

// What the MDS table shows for each filter, over the fixture snapshot
// serve-flask.mjs serves (tests/fixtures/mds), against its recording (recorded.ts):
// every row's cells word for word (layout, separators and controls' own labels set
// aside: recorded-words.ts), the rows keyed by their ID, and the order of the rows.
// Every difference must be one listed below, with its reason.

// The filters are labelled by their column.
const CASES = [
  { label: 'no filter', filters: {} },
  { label: 'protocol Uaf', filters: { protocol: ['#mds-filter-protocol', 'Protocol', 'Uaf'] } },
  { label: 'certification FIDO Certified L2', filters: { certification: ['#mds-filter-certification', 'Certification', 'FIDO Certified L2'] } },
  { label: 'certification FIDO Certified (every level)', filters: { certification: ['#mds-filter-certification', 'Certification', 'FIDO Certified'] } },
  { label: 'name Security Key', filters: { name: ['#mds-filter-name', 'Name', 'Security Key'] } },
  { label: 'user verification and transports', filters: { uv: ['#mds-filter-user-verification', 'User Verification', 'Fingerprint Internal'], transports: ['#mds-filter-transports', 'Transports', 'Nfc'] } },
] as const;

// Nothing is expected to differ: the words are the server's, in both tables.
const EXPECTED: ExpectedDifference[] = [];

async function betaRows(page: Page, filters: Record<string, readonly string[]>) {
  await page.goto('/#mds');
  const section = page.getByRole('tabpanel', { name: 'FIDO MDS Authenticators' });
  await expect(section.locator('tbody tr[data-entry-id]:not([hidden])')).toHaveCount(32);
  const bar = section.getByRole('region', { name: 'Filters' });
  for (const [, label, value] of Object.values(filters)) {
    const field = bar.getByRole('combobox', { name: label, exact: true }).or(bar.getByRole('searchbox', { name: label, exact: true }));
    await field.fill(value);
    await field.press('Tab');
  }
  return readShownRows(section.locator('tbody'), 'tr[data-entry-id]:not([hidden])', 4);
}

const keys = (rows: ShownSection[]) => rows.map((row) => row.heading);

test.describe('the MDS table reads as recorded', () => {
  const report: string[] = [];

  test.afterAll(async ({}, testInfo) => {
    await testInfo.attach('mds-recorded.txt', { body: report.join('\n') || 'no differences', contentType: 'text/plain' });
    console.log(report.join('\n') || 'no differences');
  });

  for (const { label, filters } of CASES) {
    test(label, async ({ page }) => {
      const legacy = recorded<ShownSection[]>('mds', label);
      const beta = await betaRows(page, filters);
      expect(legacy.length, 'the recording holds rows').toBeGreaterThan(0);
      expect(keys(beta), 'the same rows, in the same order').toEqual(keys(legacy));

      const differences = compareShownText(legacy, beta, EXPECTED);
      report.push(`${label} (${legacy.length} rows):`, ...describeDifferences(differences).map((line) => `  ${line}`));
      expect(describeDifferences(differences.filter((difference) => !difference.reason))).toEqual([]);
    });
  }

  test('sorted by name, both ways', async ({ page }) => {
    const { legacyUp, legacyDown } = recorded<{ legacyUp: string[]; legacyDown: string[] }>('mds', 'sorted by name');

    await betaRows(page, {});
    const section = page.getByRole('tabpanel', { name: 'FIDO MDS Authenticators' });
    const name = section.getByRole('columnheader', { name: /^Name/ }).getByRole('button');
    await name.click();
    const betaUp = keys(await readShownRows(section.locator('tbody'), 'tr[data-entry-id]:not([hidden])', 4));
    await name.click();
    const betaDown = keys(await readShownRows(section.locator('tbody'), 'tr[data-entry-id]:not([hidden])', 4));

    expect(betaUp).toEqual(legacyUp);
    expect(betaDown).toEqual(legacyDown);
  });
});
