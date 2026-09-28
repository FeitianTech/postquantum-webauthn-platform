import { readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';

import type { Locator, Page } from '@playwright/test';

import { expect, test } from './fixtures';
import { type ExpectedDifference, compareShownText, describeDifferences, readShownText } from './parity';
import { addVirtualAuthenticator } from './virtual-authenticator';

// What the Simple tab and the saved credentials show in the current UI at / and
// in /beta: the tab's own words, each saved credential's row for the same stored
// records (both UIs read the one localStorage array), the result panel after an
// authentication in each, and the success sentences; word for word (layout,
// separators and controls' own labels set aside: parity.ts). Every difference
// must be one listed below, with its reason.

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
  { only: 'legacy', token: /^Processing\.\.\.$/, reason: 'the progress bar\'s default text, which every step replaces before it shows (SIM-M2)' },
  { only: 'beta', token: /^0$/, section: 'Saved Credentials', reason: 'how many credentials the list holds (new)' },
];

function rowExpected(name: string, row: Locator): Promise<ExpectedDifference[]> {
  return row.evaluate((element, account) => {
    const values = Array.from(element.querySelectorAll('[data-row-values] code')).map((code) => code.textContent ?? '');
    return [
      {
        only: 'legacy' as const,
        token: account,
        reason: 'the account\'s name, which /beta shows as the button that opens the details (controls\' labels are set aside; the names are checked equal)',
      },
      {
        only: 'beta' as const,
        token: ['Credential', 'ID', 'AAGUID', ...values],
        reason: 'the credential ID and AAGUID each row now shows, in Geist Mono with copy (the brief asks for identifiers on the list)',
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

// Each check's verdict: the current card says it by the word's colour (green,
// red, grey), /beta by the chip's tone (and a word for screen readers).
function legacyVerdicts(row: Locator) {
  return row.evaluate((element) =>
    Array.from(element.querySelectorAll('span'))
      .filter((span) => ['Signature', 'Root', 'RPID', 'AAGUID'].includes(span.textContent ?? ''))
      .map((span) => {
        const colour = span.style.color;
        return `${span.textContent}:${colour === 'rgb(17, 182, 109)' ? 'passed' : colour === 'rgb(220, 53, 69)' ? 'failed' : 'unknown'}`;
      }),
  );
}

function betaVerdicts(row: Locator) {
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

async function openCurrent(page: Page) {
  await page.goto('/');
  await expect(page.locator('body')).toHaveClass(/app-loaded/);
}

async function openBeta(page: Page) {
  await page.goto('/beta#simple');
  await expect(page.locator('[data-saved-credentials] [data-count]')).toBeVisible();
}

test.describe('the Simple tab in / and in /beta', () => {
  test('shows the same words', async ({ page }) => {
    await openCurrent(page);
    const legacy = await readShownText(page.locator('#simple-tab'), 'h2, h3');
    await openBeta(page);
    const beta = await readShownText(page.locator('#nav-panel-simple'), 'h2, h3');

    const differences = compareShownText(legacy, beta, TAB_EXPECTED);
    expect(describeDifferences(differences.filter((difference) => !difference.reason))).toEqual([]);
    expect(legacy.map((section) => section.heading)).toEqual(beta.map((section) => section.heading));
  });

  test('shows each saved credential with the same words, in the same order', async ({ page }) => {
    await openCurrent(page);
    await keep(page, RECORDS);
    await page.reload();
    await expect(page.locator('body')).toHaveClass(/app-loaded/);
    const legacyRows = page.locator('#simple-credentials-list .credential-item');
    await expect(legacyRows).toHaveCount(RECORDS.length);

    await openBeta(page);
    const betaRows = page.locator('[data-saved-credentials] li[data-credential-key]');
    await expect(betaRows).toHaveCount(RECORDS.length);

    for (let index = 0; index < RECORDS.length; index += 1) {
      await openCurrent(page);
      const legacyRow = page.locator('#simple-credentials-list .credential-item').nth(index);
      const name = (await legacyRow.locator('div > div').first().textContent())!.trim();
      const legacy = await readShownText(legacyRow, 'h6');
      const legacyButtons = await legacyRow.getByRole('button').allTextContents();
      const legacyChecks = await legacyVerdicts(legacyRow);

      await openBeta(page);
      const betaRow = page.locator('[data-saved-credentials] li[data-credential-key]').nth(index);
      await expect(betaRow.getByRole('button', { name, exact: true })).toBeVisible();
      const beta = await readShownText(betaRow, 'h6');
      const betaButtons = (await betaRow.getByRole('button').allTextContents()).filter((text) => ['FIDO MDS', 'Delete'].includes(text));

      const differences = compareShownText(legacy, beta, await rowExpected(name, betaRow));
      expect(describeDifferences(differences.filter((difference) => !difference.reason)), name).toEqual([]);
      expect(betaButtons, `${name}'s actions`).toEqual(legacyButtons.map((text) => text.trim()));
      expect(await betaVerdicts(betaRow), `${name}'s checks`).toEqual(legacyChecks);
      expect(legacyChecks).toHaveLength(4);
    }
  });

  test('says the same after a registration and an authentication', async ({ page }) => {
    await addVirtualAuthenticator(page);
    const name = `parity-${Date.now()}`;

    await openBeta(page);
    await page.getByRole('textbox', { name: 'Username' }).fill(name);
    await page.getByRole('button', { name: 'Register Passkey' }).click();
    const betaRegistered = (await page.locator('[data-toast-viewport]').getByText(/^Registration successful!/).textContent())!;
    await page.getByRole('button', { name: 'Authenticate', exact: true }).click();
    await expect(page.getByText('Authentication successful! You have been verified.')).toBeVisible();
    const betaPanel = await readShownText(page.getByRole('tabpanel', { name: 'Simple Authentication' }).locator('[data-ceremony-result]'), 'h6');

    await openCurrent(page);
    await page.locator('#simple-email').fill(name);
    await page.getByRole('button', { name: 'Authenticate', exact: true }).click();
    await expect(page.locator('#simple-status')).toHaveText('Authentication successful! You have been verified.');
    const legacyPanel = await readShownText(page.locator('#simple-ceremony-result'), 'h6');

    const counter: ExpectedDifference[] = [
      { only: 'legacy', token: /^\d+$/, reason: 'the counter, which each authentication raises (the same credential was used in /beta first)' },
      { only: 'beta', token: /^\d+$/, reason: 'the counter, which each authentication raises' },
    ];
    const differences = compareShownText(legacyPanel, betaPanel, counter);
    expect(describeDifferences(differences.filter((difference) => !difference.reason))).toEqual([]);

    await page.locator('#simple-email').fill(`${name}-current`);
    await page.getByRole('button', { name: 'Register Passkey', exact: true }).click();
    await expect(page.locator('#simple-status')).toHaveText(betaRegistered);
  });
});
