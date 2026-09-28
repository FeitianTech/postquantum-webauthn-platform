import { readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';

import type { Page } from '@playwright/test';

import { greyFills } from './design-rules';
import { expect, test } from './fixtures';
import { addVirtualAuthenticator } from './virtual-authenticator';

// The Simple tab at /beta#simple in Chromium, against Flask serving the export
// under the strict CSP: real registrations and authentications answered by
// Chromium's virtual authenticator, and the saved credentials in the one
// localStorage array (what the current UI wrote there: current-ui-records.spec.ts).

const repo = resolve(import.meta.dirname, '..', '..');
const STORAGE_KEY = 'postquantum-webauthn.credentials';

function goldenStoredCredential(scenario: string) {
  const golden = JSON.parse(readFileSync(join(repo, 'tests', 'app', 'characterization', 'golden', 'routes', `${scenario}.json`), 'utf8'));
  const complete = golden.requests.find((entry: { request: string; status: number }) => entry.request.includes('/register/complete') && entry.status === 200);
  return complete.body.storedCredential as Record<string, unknown>;
}

const section = (page: Page) => page.getByRole('tabpanel', { name: 'Simple Authentication' });
const list = (page: Page) => section(page).locator('[data-saved-credentials]');
const rows = (page: Page) => list(page).locator('li[data-credential-key]');
const username = () => `e2e-${Date.now()}-${Math.floor(Math.random() * 1e6)}`;

async function openBeta(page: Page, hash = '#simple') {
  await page.goto(`/beta${hash}`);
  await expect(list(page).locator('[data-count]')).toBeVisible();
}

async function registerInBeta(page: Page, name: string) {
  await section(page).getByRole('textbox', { name: 'Username' }).fill(name);
  await section(page).getByRole('button', { name: 'Register Passkey' }).click();
  await expect(page.getByText(/^Registration successful! Algorithm: /)).toBeVisible();
  await expect(rows(page).filter({ hasText: name })).toHaveCount(1);
}

async function keep(page: Page, records: object[]) {
  await page.evaluate(([key, value]) => window.localStorage.setItem(key, value), [STORAGE_KEY, JSON.stringify(records)] as const);
}

async function storedCount(page: Page) {
  return page.evaluate((key) => JSON.parse(window.localStorage.getItem(key) ?? '[]').length, STORAGE_KEY);
}

test.describe('/beta#simple', () => {
  test('registers a passkey and authenticates with it, saying each outcome and what the server made of it', async ({ page }) => {
    const authenticator = await addVirtualAuthenticator(page);
    await openBeta(page);
    const name = username();
    await registerInBeta(page, name);
    const [registered] = await authenticator.credentials();
    expect(registered.rpId).toBe('localhost');

    await section(page).getByRole('button', { name: 'Authenticate', exact: true }).click();
    await expect(page.getByText('Authentication successful! You have been verified.')).toBeVisible();
    const panel = section(page).locator('[data-ceremony-result]');
    await expect(panel).toContainText('Last authentication');
    await expect(panel).toContainText('Higher than the last counter the server saw for this credential, as it should be.');
    await expect(rows(page).filter({ hasText: name })).toHaveAttribute('data-flash', 'success');

    const [used] = await authenticator.credentials();
    expect(used.credentialId).toBe(registered.credentialId);
    expect(used.signCount).toBeGreaterThan(registered.signCount);
  });

  test('keeps a failure in place, with its sentence', async ({ page }) => {
    await addVirtualAuthenticator(page);
    await openBeta(page);
    await section(page).getByRole('textbox', { name: 'Username' }).fill(username());
    await section(page).getByRole('button', { name: 'Authenticate', exact: true }).click();
    await expect(section(page).getByRole('alert')).toHaveText(
      'No credentials stored in this browser for the provided username. Please register first.',
    );
  });

  test('clears every credential, and warns of an advanced one the server no longer held', async ({ page }) => {
    await openBeta(page);
    await keep(page, [
      { ...goldenStoredCredential('simple-register-es256'), type: 'simple' },
      { ...goldenStoredCredential('advanced-register-none-es256'), type: 'advanced' },
    ]);
    await page.reload();
    await expect(rows(page)).toHaveCount(2);

    await list(page).getByRole('button', { name: 'Clear All' }).click();
    await page.getByRole('alertdialog', { name: 'Clear All' }).getByRole('button', { name: 'Clear All' }).click();
    await expect(list(page).locator('[data-notice="warning"]')).toHaveText(
      'Clearing complete. 1 credential was already absent from server storage.',
    );
    await expect(list(page).getByText('No credentials registered yet.')).toBeVisible();
    expect(await storedCount(page)).toBe(0);
  });

  test('opens a credential\'s details at their own URL, and Back closes them', async ({ page }) => {
    await openBeta(page);
    const record: Record<string, unknown> = { ...goldenStoredCredential('simple-register-es256'), type: 'simple' };
    await keep(page, [record]);
    await page.reload();
    await rows(page).first().getByRole('button', { name: 'user@example.com' }).click();

    const detail = page.getByRole('dialog', { name: 'Credential Details' });
    await expect(detail).toContainText(record.credentialIdBase64Url as string);
    await expect(page).toHaveURL(new RegExp(`#simple/credential/id:${record.credentialIdBase64Url}$`));
    await page.goBack();
    await expect(detail).toBeHidden();
    await expect(page).toHaveURL(/\/beta#simple$/);

    await page.goForward();
    await expect(detail).toBeVisible();
    await page.reload();
    await expect(detail).toBeVisible();
  });

  test('opens a saved credential\'s FIDO MDS entry, and Back returns to the list', async ({ page }) => {
    await openBeta(page);
    await keep(page, [
      { type: 'simple', credentialId: 'AQIDBA', email: 'mds@example.com', aaguidHex: 'f1d0f1d0000040008000000000000001', attestationSummary: { rootValid: true } },
    ]);
    await page.reload();
    await rows(page).first().getByRole('button', { name: 'FIDO MDS' }).click();
    await expect(page).toHaveURL(/#mds\/aaguid:f1d0f1d0-0000-4000-8000-000000000001$/);
    await expect(page.getByRole('heading', { level: 3, name: 'Fixture Security Key L1' })).toBeVisible();

    await page.goBack();
    await expect(page).toHaveURL(/\/beta#simple$/);
    await expect(rows(page)).toHaveCount(1);
  });

  for (const width of [1440, 1024, 800, 375]) {
    test(`never scrolls the page sideways at ${width} px, and has no grey fill`, async ({ page }) => {
      await page.setViewportSize({ width, height: 900 });
      await openBeta(page);
      await keep(page, [
        { ...goldenStoredCredential('simple-register-packed-x5c-extensions'), type: 'simple' },
        { ...goldenStoredCredential('advanced-register-packed-x5c-everything'), type: 'advanced' },
      ]);
      await page.reload();
      await expect(rows(page)).toHaveCount(2);
      expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(width);
      expect(await greyFills(page, '#nav-panel-simple')).toEqual([]);
      if (width >= 800) {
        // Where a row has room, its identifiers are whole: never cut when they fit.
        const cut = await rows(page).locator('[data-row-values] code').evaluateAll((codes) =>
          codes.filter((code) => code.scrollWidth > code.clientWidth).map((code) => code.textContent),
        );
        expect(cut).toEqual([]);
      }
    });
  }
});
