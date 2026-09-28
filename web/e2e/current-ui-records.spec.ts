import type { Page } from '@playwright/test';

import { STORAGE_KEY, keep } from './credential-views';
import { expect, test } from './fixtures';
import { recorded } from './recorded';
import { type VirtualCredential, addVirtualAuthenticator } from './virtual-authenticator';

// What a visitor's browser holds from the current UI at /, which Phase 30 removed:
// a Simple and an Advanced credential it registered, as it stored them, and the
// virtual authenticator's credentials (their private keys and counters), recorded
// before it went (recorded.ts). The new UI lists them, opens their details,
// deletes them, and authenticates with the Advanced one once its key is back on
// an authenticator; the server holds nothing of either (a fresh run's stores).

type StoredRecord = Record<string, unknown> & { type: string; credentialIdBase64Url: string };

const { records, credentials } = recorded<{ records: StoredRecord[]; credentials: VirtualCredential[] }>('current-ui-records', 'records');
const SIMPLE = 'current-ui-simple@example.com';
const ADVANCED = 'current-ui-advanced';
const advancedRecord = records.find((record) => record.type === 'advanced')!;

const simpleSection = (page: Page) => page.getByRole('tabpanel', { name: 'Simple Authentication' });
const rows = (page: Page) => simpleSection(page).locator('li[data-credential-key]');
const dialog = (page: Page) => page.getByRole('dialog');
const advanced = (page: Page) => page.getByRole('tabpanel', { name: 'Advanced Authentication' });

async function openWithRecords(page: Page, hash: string) {
  await page.goto(`/beta${hash}`);
  await keep(page, records);
  await page.reload();
}

const base64url = (base64: string) => base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

test.describe('what the current UI stored, in /beta', () => {
  test('lists both credentials, and opens each one\'s details (the Advanced one\'s registration from its saved snapshot)', async ({ page }) => {
    await openWithRecords(page, '#simple');
    await expect(rows(page)).toHaveCount(2);

    await rows(page).filter({ hasText: SIMPLE }).getByRole('button', { name: SIMPLE }).click();
    await expect(dialog(page).locator('[data-section="Public Key"]')).toContainText('EdDSA (-8)');
    await dialog(page).getByRole('button', { name: 'Close credential details' }).click();

    const key = await rows(page).filter({ hasText: ADVANCED }).getAttribute('data-credential-key');
    await page.goto(`/beta#simple/credential/${encodeURIComponent(key!).replace(/%3A/gi, ':')}/registration`);
    const registration = dialog(page).locator('[data-level="registration"]');
    await expect(registration).toContainText('Response for navigator.credentials.create()');
    await expect(registration.locator('[data-section="Authenticator Response"]')).toContainText('"type": "webauthn.create"');
  });

  test('deletes the Simple one, asking first, and clears the Advanced one', async ({ page }) => {
    await openWithRecords(page, '#simple');
    await expect(rows(page)).toHaveCount(2);

    await rows(page).filter({ hasText: SIMPLE }).getByRole('button', { name: 'Delete' }).click();
    const question = page.getByRole('alertdialog', { name: 'Delete credential' });
    await expect(question).toContainText(`Are you sure you want to delete the credential for ${SIMPLE}? This action cannot be undone.`);
    await expect(question.getByRole('button', { name: 'Cancel' })).toBeFocused();
    await question.getByRole('button', { name: 'Delete' }).click();
    await expect(rows(page)).toHaveCount(1);

    await simpleSection(page).getByRole('button', { name: 'Clear All' }).click();
    await page.getByRole('alertdialog', { name: 'Clear All' }).getByRole('button', { name: 'Clear All' }).click();
    await expect(simpleSection(page).locator('[data-notice="warning"]')).toHaveText(
      'Clearing complete. 1 credential was already absent from server storage.',
    );
    await expect(rows(page)).toHaveCount(0);
    expect(await page.evaluate((storageKey) => JSON.parse(window.localStorage.getItem(storageKey) ?? '[]').length, STORAGE_KEY)).toBe(0);
  });

  test('authenticates with the Advanced one, chosen in Allow Credentials, once its key is back on an authenticator', async ({ page }) => {
    const authenticator = await addVirtualAuthenticator(page);
    await authenticator.add(credentials.find((credential) => base64url(credential.credentialId) === advancedRecord.credentialIdBase64Url)!);
    await openWithRecords(page, '#advanced');
    await advanced(page).getByRole('tab', { name: 'Authentication' }).click();
    const form = page.locator('#advanced-ceremony-panel-authentication');
    const allow = form.getByLabel('Allow Credentials', { exact: true });
    await allow.selectOption(await allow.locator('option').filter({ hasText: ADVANCED }).getAttribute('value'));
    const editor = advanced(page).getByRole('textbox', { name: 'JSON Editor (CredentialRequestOptions)' });
    expect(JSON.parse(await editor.inputValue()).publicKey.allowCredentials).toHaveLength(1);

    await advanced(page).getByRole('button', { name: 'Assert Credential' }).click();
    await expect(page.getByText('Advanced authentication successful!')).toBeVisible();
    await expect(advanced(page).locator('[data-ceremony-result]').locator('[data-row="Challenge"]')).toContainText(
      'Issued by this server for this ceremony.',
    );
  });
});
