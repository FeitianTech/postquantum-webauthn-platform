import type { Page } from '@playwright/test';

import { STORAGE_KEY, keep } from './credential-views';
import { expect, test } from './fixtures';
import { recorded } from './recorded';
import { type VirtualCredential, addVirtualAuthenticator } from './virtual-authenticator';

// What visitors' browsers hold from an earlier release of the site: a Simple and
// an Advanced credential it registered, as it stored them, and the virtual
// authenticator's credentials (their private keys and counters), recorded
// (recorded.ts). The site lists them, opens their details, deletes them, and
// authenticates in Advanced with each once its key is back on an authenticator;
// the server holds nothing of either (a fresh run's stores).

type StoredRecord = Record<string, unknown> & { type: string; credentialIdBase64Url: string };

const { records, credentials } = recorded<{ records: StoredRecord[]; credentials: VirtualCredential[] }>('stored-records', 'records');
const SIMPLE = 'current-ui-simple@example.com';
const ADVANCED = 'current-ui-advanced';
const advancedRecord = records.find((record) => record.type === 'advanced')!;
const simpleRecord = records.find((record) => record.type === 'simple')!;

const simpleSection = (page: Page) => page.getByRole('tabpanel', { name: 'Simple Authentication' });
const rows = (page: Page) => simpleSection(page).locator('li[data-credential-key]');
const dialog = (page: Page) => page.getByRole('dialog');
const advanced = (page: Page) => page.getByRole('tabpanel', { name: 'Advanced Authentication' });

async function openWithRecords(page: Page, hash: string) {
  await page.goto(`/${hash}`);
  await keep(page, records);
  await page.reload();
}

const base64url = (base64: string) => base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

test.describe('credentials an earlier release stored', () => {
  test('lists both credentials, and opens each one\'s details (the Advanced one\'s registration from its saved snapshot)', async ({ page }) => {
    await openWithRecords(page, '#simple');
    await expect(rows(page)).toHaveCount(2);

    await rows(page).filter({ hasText: SIMPLE }).getByRole('button', { name: SIMPLE }).click();
    await expect(dialog(page).locator('[data-section="Public Key"]')).toContainText('EdDSA (-8)');
    await dialog(page).getByRole('button', { name: 'Close credential details' }).click();

    const key = await rows(page).filter({ hasText: ADVANCED }).getAttribute('data-credential-key');
    await page.goto(`/#simple/credential/${encodeURIComponent(key!).replace(/%3A/gi, ':')}/registration`);
    const registration = dialog(page).locator('[data-level="registration"]');
    await expect(registration).toContainText('Response for navigator.credentials.create()');
    await expect(registration.locator('[data-section="Authenticator Response"]')).toContainText('"type": "webauthn.create"');
    // Its attestation's findings in words: the sentence that release's server wrote
    // for a missing root as it was sent, the code beside it in words.
    const findings = registration.locator('[data-section="Verification findings"]');
    await expect(findings.locator('[data-finding="No root found for Authenticator"]')).toContainText('No root found for Authenticator');
    await expect(findings.locator('[data-finding="metadata_entry_missing"] [lang="en"]')).toHaveText(
      'The metadata has no entry for this authenticator',
    );
    await expect(findings.locator('[data-severity="error"]')).toHaveCount(2);
  });

  test('opens the Advanced one\'s certificate in the Codec, from the PEM its saved snapshot kept', async ({ page }) => {
    await openWithRecords(page, '#simple');
    const key = await rows(page).filter({ hasText: ADVANCED }).getAttribute('data-credential-key');
    await page.goto(`/#simple/credential/${encodeURIComponent(key!).replace(/%3A/gi, ':')}/registration/certificate/1`);
    await dialog(page).getByRole('button', { name: 'Decode in Codec: certificate' }).click();

    await expect(page).toHaveURL(/\/#codec$/);
    const decoding = page.locator('#codec-mode-panel-decode');
    await expect(decoding.getByRole('textbox', { name: 'Input to decode' })).toHaveValue(/^-----BEGIN CERTIFICATE-----\n[\s\S]+-----END CERTIFICATE-----$/);
    await expect(decoding.getByRole('region', { name: 'Codec Output' }).locator('[data-role="outcome"]')).toHaveText('Success✓');
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
    // The server holds no record of it (a fresh run's stores): deleted here, and said so.
    await expect(simpleSection(page).locator('[data-notice="warning"]')).toHaveText(
      'Credential was already absent from server storage and has been removed locally.',
    );

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
    // Both are offered: the tabs share the saved list.
    await expect(allow.locator('option').filter({ hasText: SIMPLE })).toHaveCount(1);
    await allow.selectOption(await allow.locator('option').filter({ hasText: ADVANCED }).getAttribute('value'));
    const editor = advanced(page).getByRole('textbox', { name: 'JSON Editor (CredentialRequestOptions)' });
    expect(JSON.parse(await editor.inputValue()).publicKey.allowCredentials).toHaveLength(1);

    await advanced(page).getByRole('button', { name: 'Assert Credential' }).click();
    await expect(page.getByText('Advanced authentication successful!')).toBeVisible();
    await expect(advanced(page).locator('[data-ceremony-result]').locator('[data-row="Challenge"]')).toContainText(
      'Issued by this server for this ceremony.',
    );
  });

  test('authenticates in Advanced with the Simple one, chosen in Allow Credentials, and keeps its counter', async ({ page }) => {
    const authenticator = await addVirtualAuthenticator(page);
    await authenticator.add(credentials.find((credential) => base64url(credential.credentialId) === simpleRecord.credentialIdBase64Url)!);
    await openWithRecords(page, '#advanced');
    await advanced(page).getByRole('tab', { name: 'Authentication' }).click();
    const allow = page.locator('#advanced-ceremony-panel-authentication').getByLabel('Allow Credentials', { exact: true });
    await allow.selectOption(await allow.locator('option').filter({ hasText: SIMPLE }).getAttribute('value'));
    const editor = advanced(page).getByRole('textbox', { name: 'JSON Editor (CredentialRequestOptions)' });
    expect(JSON.parse(await editor.inputValue()).publicKey.allowCredentials).toHaveLength(1);

    await advanced(page).getByRole('button', { name: 'Assert Credential' }).click();
    await expect(page.getByText('Advanced authentication successful!')).toBeVisible();
    // The server read its key from what this browser sent; the browser keeps the new counter.
    await expect
      .poll(() => page.evaluate((storageKey) => {
        const kept = JSON.parse(window.localStorage.getItem(storageKey) ?? '[]') as { type: string; signCount: number }[];
        return kept.find((record) => record.type === 'simple')?.signCount;
      }, STORAGE_KEY))
      .toBe(2);
  });
});
