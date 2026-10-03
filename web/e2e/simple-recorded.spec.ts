import { readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';

import type { Locator, Page } from '@playwright/test';

import { expect, test } from './fixtures';
import { type ExpectedDifference, type ShownSection, compareShownText, describeDifferences, readShownText } from './recorded-words';
import { recorded } from './recorded';
import { addVirtualAuthenticator } from './virtual-authenticator';

// What the Simple tab and the saved credentials show, against their recording
// (recorded.ts): the tab's own words, each saved credential's row for the same
// stored records, the result panel after an authentication, and the success
// sentences; word for word (layout, separators and controls' own labels set aside:
// recorded-words.ts). Every difference must be one listed below, with its reason.

const repo = resolve(import.meta.dirname, '..', '..');
const STORAGE_KEY = 'postquantum-webauthn.credentials';

function storedCredential(scenario: string, type: string, extra: Record<string, unknown> = {}) {
  const golden = JSON.parse(readFileSync(join(repo, 'tests', 'app', 'characterization', 'golden', 'routes', `${scenario}.json`), 'utf8'));
  const complete = golden.requests.find((entry: { request: string; status: number }) => entry.request.includes('/register/complete') && entry.status === 200);
  return { ...complete.body.storedCredential, type, ...extra } as Record<string, unknown>;
}

const RECORDS = [
  storedCredential('simple-register-packed-x5c-extensions', 'simple', { email: 'x5c@example.com', userName: 'x5c@example.com' }),
  storedCredential('simple-register-mldsa65', 'simple', { email: 'ml@example.com', userName: 'ml@example.com' }),
  storedCredential('advanced-register-packed-x5c-everything', 'advanced', { userName: 'advanced@example.com' }),
  { type: 'simple', credentialId: 'AQIDBA', publicKey: 'pQE', email: 'mds@example.com', aaguidHex: 'f1d0f1d0000040008000000000000001', attestationSummary: { rootValid: true } },
];

const TAB_EXPECTED: ExpectedDifference[] = [
  { only: 'recorded', token: /^Processing\.\.\.$/, reason: 'the progress bar\'s default text, which every step replaces before it shows' },
  { only: 'shown', token: /^0$/, section: 'Saved Credentials', reason: 'how many credentials the list holds (new)' },
];

function rowExpected(name: string, row: Locator): Promise<ExpectedDifference[]> {
  return row.evaluate((element, account) => {
    const values = Array.from(element.querySelectorAll('[data-row-values] code')).map((code) => code.textContent ?? '');
    return [
      {
        only: 'recorded' as const,
        token: account,
        reason: 'the account\'s name, which the new UI shows as the button that opens the details (controls\' labels are set aside; the names are checked equal)',
      },
      {
        only: 'shown' as const,
        token: ['Credential', 'ID', 'AAGUID', ...values],
        reason: 'the credential ID and AAGUID each row now shows, in Geist Mono with copy',
      },
    ];
  }, name).then((entries) =>
    entries.map((entry) => ({
      only: entry.only,
      reason: entry.reason,
      token: Array.isArray(entry.token)
        ? new RegExp(`^(${entry.token.map((word) => word.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('|')})$`)
        : new RegExp(`^${entry.token.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}$`),
    })),
  );
}

// Each check's verdict: the current card said it by the word's colour (green,
// red, grey), recorded as passed, failed or unknown; the new UI by the chip's tone (and
// a word for screen readers).
function shownVerdicts(row: Locator) {
  return row.evaluate((element) =>
    Array.from(element.querySelectorAll<HTMLElement>('[data-check]')).map((chip) => {
      const tone = chip.className.includes('bg-success-tint') ? 'passed' : chip.className.includes('bg-danger-tint') ? 'failed' : 'unknown';
      return `${chip.dataset.check}:${tone}`;
    }),
  );
}

async function keep(page: Page, records: object[]) {
  await page.evaluate(([key, value]) => window.localStorage.setItem(key, value), [STORAGE_KEY, JSON.stringify(records)] as const);
}

async function openPage(page: Page) {
  await page.goto('/#simple');
  await expect(page.locator('[data-saved-credentials] [data-count]')).toBeVisible();
}

type RowRecording = { name: string; sections: ShownSection[]; buttons: string[]; checks: string[] };

test.describe('the Simple tab, as recorded', () => {
  test('shows the same words', async ({ page }) => {
    const legacy = recorded<ShownSection[]>('simple', 'the tab');
    await openPage(page);
    const shownSections = await readShownText(page.locator('#nav-panel-simple'), 'h2, h3');

    const differences = compareShownText(legacy, shownSections, TAB_EXPECTED);
    expect(describeDifferences(differences.filter((difference) => !difference.reason))).toEqual([]);
    expect(legacy.map((section) => section.heading)).toEqual(shownSections.map((section) => section.heading));
  });

  test('shows each saved credential with the same words, in the same order', async ({ page }) => {
    const legacyRows = recorded<RowRecording[]>('simple', 'the rows');
    expect(legacyRows).toHaveLength(RECORDS.length);

    await openPage(page);
    await keep(page, RECORDS);
    await page.reload();
    const shownRows = page.locator('[data-saved-credentials] li[data-credential-key]');
    await expect(shownRows).toHaveCount(RECORDS.length);

    for (let index = 0; index < RECORDS.length; index += 1) {
      const { name, sections: legacy, buttons: legacyButtons, checks: legacyChecks } = legacyRows[index];
      const shownRow = shownRows.nth(index);
      await expect(shownRow.getByRole('button', { name, exact: true })).toBeVisible();
      const shownSections = await readShownText(shownRow, 'h6');
      const shownButtons = (await shownRow.getByRole('button').allTextContents()).filter((text) => ['FIDO MDS', 'Delete'].includes(text));

      const differences = compareShownText(legacy, shownSections, await rowExpected(name, shownRow));
      expect(describeDifferences(differences.filter((difference) => !difference.reason)), name).toEqual([]);
      expect(shownButtons, `${name}'s actions`).toEqual(legacyButtons);
      expect(await shownVerdicts(shownRow), `${name}'s checks`).toEqual(legacyChecks);
      expect(legacyChecks).toHaveLength(4);
    }
  });

  test('says the same after a registration and an authentication', async ({ page }) => {
    await addVirtualAuthenticator(page);
    const name = `recorded-${Date.now()}`;

    await openPage(page);
    await page.getByRole('textbox', { name: 'Username' }).fill(name);
    await page.getByRole('button', { name: 'Register Passkey' }).click();
    const shownRegistered = (await page.locator('[data-toast-viewport]').getByText(/^Registration successful!/).textContent())!;
    await page.getByRole('button', { name: 'Authenticate', exact: true }).click();
    await expect(page.getByText('Authentication successful! You have been verified.')).toBeVisible();
    const shownPanel = await readShownText(page.getByRole('tabpanel', { name: 'Simple Authentication' }).locator('[data-ceremony-result]'), 'h6');

    const current = recorded<{ panel: ShownSection[]; registered: string }>('simple', 'after a registration and an authentication');
    const legacyPanel = current.panel;

    const counter: ExpectedDifference[] = [
      { only: 'recorded', token: /^\d+$/, reason: 'the counter, which each authentication raises (the same credential was used on the page first)' },
      { only: 'shown', token: /^\d+$/, reason: 'the counter, which each authentication raises' },
    ];
    const differences = compareShownText(legacyPanel, shownPanel, counter);
    expect(describeDifferences(differences.filter((difference) => !difference.reason))).toEqual([]);
    expect(shownRegistered.trim()).toBe(current.registered);
  });
});
