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

const REVOKED_KEY = 'f1d0f1d0-0000-4000-8000-000000000005';

// The words are the server's, in both tables; what differs is listed with its reason.
const EXPECTED: ExpectedDifference[] = [
  {
    only: 'recorded',
    token: /^(Nfc|Usb|Ble|Tee|Uaf|Ecdsa|Eddsa|ED25519|NOT)$/,
    reason: 'the MDS words as now spelled: a fixed list of acronyms in capitals (NFC, USB, BLE, TEE, UAF, ECDSA), EdDSA and Ed25519 in their own case, every other word title-cased (Not)',
  },
  {
    only: 'shown',
    token: /^(NFC|USB|BLE|TEE|UAF|ECDSA|EdDSA|Ed25519|Not)$/,
    reason: 'the MDS words as now spelled: a fixed list of acronyms in capitals (NFC, USB, BLE, TEE, UAF, ECDSA), EdDSA and Ed25519 in their own case, every other word title-cased (Not, in the Status column too)',
  },
  {
    only: 'shown',
    section: REVOKED_KEY,
    token: /^(FIDO|Certified|L1|Fixture|Revoked|Key|\(FIDO20020230110005\))$/,
    reason: "the level the revoked key reached in 2023 (L1, its descriptor and number), which Certification shows now and the revocation, its latest status, used to hide",
  },
  {
    only: 'shown',
    token: /^(FIDO|Certified|L1|L2|NOT|Revoked)$/,
    reason: "each entry's latest status, now a column of its own (Status) beside Certification",
  },
];

// Rows a case shows that its recording does not hold, each with its reason: they are
// set aside before the rows, their order and their words are compared.
const EXPECTED_ROWS: { case: string; heading: string; reason: string }[] = [
  {
    case: 'certification FIDO Certified (every level)',
    heading: REVOKED_KEY,
    reason: 'the revoked key reached L1, and Certification now filters by the level reached, not the latest status',
  },
];

async function shownRows(page: Page, filters: Record<string, readonly string[]>) {
  await page.goto('/#mds');
  const section = page.getByRole('tabpanel', { name: 'FIDO MDS Authenticators' });
  await expect(section.locator('tbody tr[data-entry-id]:not([hidden])')).toHaveCount(32);
  const bar = section.getByRole('region', { name: 'Filters' });
  for (const [, label, value] of Object.values(filters)) {
    const field = bar.getByRole('combobox', { name: label, exact: true }).or(bar.getByRole('searchbox', { name: label, exact: true }));
    await field.fill(value);
    await field.press('Tab');
  }
  // The rows follow the filters through React's deferred value, after the typing: the
  // render that hides them marks each filtered column's header, so read once all are marked.
  for (const [, label] of Object.values(filters)) {
    await expect(section.getByRole('columnheader', { name: `${label} (filtered)` })).toBeVisible();
  }
  return readShownRows(section.locator('tbody'), 'tr[data-entry-id]:not([hidden])', 5);
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
      const extra = EXPECTED_ROWS.filter((row) => row.case === label);
      const all = await shownRows(page, filters);
      expect(keys(all), 'the rows expected beyond the recording are shown').toEqual(expect.arrayContaining(extra.map((row) => row.heading)));
      const shown = all.filter((row) => !extra.some((expected) => expected.heading === row.heading));
      expect(legacy.length, 'the recording holds rows').toBeGreaterThan(0);
      expect(keys(shown), 'the same rows, in the same order').toEqual(keys(legacy));

      const differences = compareShownText(legacy, shown, EXPECTED);
      report.push(
        `${label} (${legacy.length} rows):`,
        ...extra.map((row) => `  [${row.heading}] only on the page: the whole row (${row.reason})`),
        ...describeDifferences(differences).map((line) => `  ${line}`),
      );
      expect(describeDifferences(differences.filter((difference) => !difference.reason))).toEqual([]);
    });
  }

  test('sorted by name, both ways', async ({ page }) => {
    const { legacyUp, legacyDown } = recorded<{ legacyUp: string[]; legacyDown: string[] }>('mds', 'sorted by name');

    await shownRows(page, {});
    const section = page.getByRole('tabpanel', { name: 'FIDO MDS Authenticators' });
    const name = section.getByRole('columnheader', { name: /^Name/ }).getByRole('button');
    await name.click();
    const shownUp = keys(await readShownRows(section.locator('tbody'), 'tr[data-entry-id]:not([hidden])', 5));
    await name.click();
    const shownDown = keys(await readShownRows(section.locator('tbody'), 'tr[data-entry-id]:not([hidden])', 5));

    expect(shownUp).toEqual(legacyUp);
    expect(shownDown).toEqual(legacyDown);
  });
});
