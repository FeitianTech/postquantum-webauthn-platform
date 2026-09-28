import type { Page } from '@playwright/test';

import { betaLevel, betaSubViews, expectedFor, legacyDetail, legacySubViews, openCurrent, report } from './credential-views';
import { expect, test } from './fixtures';
import { compareShownText, describeDifferences, readShownText } from './parity';
import { addVirtualAuthenticator } from './virtual-authenticator';

// What the Advanced tab's registration shows in the current UI at / and in
// /beta#advanced: the form's words section by section (layout, separators and
// controls' own labels set aside: parity.ts), each field's info popup in English
// and 中文, the algorithm and hint choices, the JSON editor's text for the same
// settings byte for byte, and a registration made in /beta shown by the current
// modal. Every difference must be one listed, with its reason.

const USER_ID = '00112233445566778899aabbccddeeff';
const USER_NAME = 'paritycheck';
const CHALLENGE = 'ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100';

const beta = (page: Page) => page.getByRole('tabpanel', { name: 'Advanced Authentication' });
const betaEditor = (page: Page) => beta(page).getByRole('textbox', { name: 'JSON Editor (CredentialCreationOptions)' });

async function openLegacyAdvanced(page: Page) {
  await openCurrent(page);
  await page.locator('[data-action="switch-tab"][data-tab="advanced"]').first().click();
  await expect(page.locator('#json-editor')).toHaveValue(/"publicKey"/);
}

async function openBeta(page: Page) {
  await page.goto('/beta#advanced');
  await expect(betaEditor(page)).toHaveValue(/"publicKey"/);
}

const squeeze = (text: string | null) => (text ?? '').replace(/\s+/g, '');

test.describe('the Advanced tab\'s registration in / and in /beta', () => {
  test('shows the same words, section by section', async ({ page }) => {
    await openLegacyAdvanced(page);
    // The popups, the checkboxes' own labels and the hidden errors are compared on their own below.
    await page.evaluate(() => {
      for (const element of document.querySelectorAll('#registration-form .info-popup, #registration-form .checkbox-item, #registration-form .error-message')) {
        element.setAttribute('data-parity-skip', '');
      }
    });
    const legacy = await readShownText(page.locator('#registration-form'), '.section-header span');

    await openBeta(page);
    const shown = await readShownText(beta(page).locator('[data-registration-form]'), 'h3');

    const differences = compareShownText(legacy, shown, []);
    expect(describeDifferences(differences)).toEqual([]);
    expect(legacy.map((section) => section.heading)).toEqual(shown.map((section) => section.heading));
  });

  test('gives each field the same info popup, in English and 中文', async ({ page }) => {
    await openLegacyAdvanced(page);
    const legacy = await page.locator('#registration-form .form-group').evaluateAll((groups) =>
      groups
        .filter((group) => group.querySelector('.info-popup'))
        .map((group) => ({
          label: (group.querySelector('.label-with-info label')?.textContent ?? '').trim(),
          en: group.querySelector('.info-popup .text-en')?.textContent ?? '',
          zh: group.querySelector('.info-popup .text-zh')?.textContent ?? '',
        })),
    );

    await openBeta(page);
    const shown = await beta(page)
      .locator('[data-registration-form] button[aria-label^="About "]')
      .evaluateAll((buttons) =>
        buttons.map((button) => {
          const popup = document.getElementById(button.getAttribute('aria-controls') ?? '');
          return {
            label: (button.getAttribute('aria-label') ?? '').replace(/^About /, ''),
            en: popup?.querySelector('[lang="en"]')?.textContent ?? '',
            zh: popup?.querySelector('[lang="zh"]')?.textContent ?? '',
          };
        }),
      );

    expect(shown).toHaveLength(18);
    // The current form's labels gain " (hex)" once the page has loaded, as /beta's carry it.
    expect(shown.map((popup) => popup.label)).toEqual(legacy.map((popup) => popup.label));
    expect(shown.map(({ en, zh }) => [squeeze(en), squeeze(zh)])).toEqual(legacy.map(({ en, zh }) => [squeeze(en), squeeze(zh)]));
  });

  test('offers the same algorithms and hints, in the same order', async ({ page }) => {
    await openLegacyAdvanced(page);
    const legacy = await page.locator('#registration-form .form-group').evaluateAll((groups) =>
      groups
        .filter((group) => group.querySelector('.checkbox-group'))
        .map((group) => [...group.querySelectorAll('.checkbox-item span')].map((span) => (span.textContent ?? '').trim())),
    );

    await openBeta(page);
    const chipsOf = (name: string) => beta(page).getByRole('group', { name }).getByRole('button').allTextContents();
    expect([await chipsOf('Public Key Credential Parameters'), await chipsOf('Hints')]).toEqual(legacy);
  });

  test('writes the same request for the same settings, byte for byte', async ({ page }) => {
    await openLegacyAdvanced(page);
    await page.locator('#user-id').fill(USER_ID);
    await page.locator('#user-name').fill(USER_NAME);
    await page.locator('#challenge-reg').fill(CHALLENGE);
    const legacyDefault = await page.locator('#json-editor').inputValue();
    await page.locator('#authenticator-attachment').selectOption('unspecified');
    await page.locator('#resident-key').selectOption('required');
    await page.locator('#attestation').selectOption('none');
    await page.locator('#exclude-credentials').setChecked(false, { force: true });
    await page.locator('#timeout-reg').fill('5000');
    await page.locator('#param-es512').setChecked(true, { force: true });
    await page.locator('#param-mldsa87').setChecked(false, { force: true });
    await page.locator('#hint-hybrid').setChecked(true, { force: true });
    await page.locator('#min-pin-length').setChecked(true, { force: true });
    await page.locator('#cred-protect').selectOption('userVerificationRequired');
    await page.locator('#large-blob-reg').selectOption('preferred');
    await page.locator('#prf-reg').setChecked(true, { force: true });
    await page.locator('#prf-eval-first-reg').fill('aa'.repeat(32));
    const legacyChanged = await page.locator('#json-editor').inputValue();

    await openBeta(page);
    const form = beta(page).locator('#advanced-ceremony-panel-registration');
    await form.getByLabel('User ID (hex)', { exact: true }).fill(USER_ID);
    await form.getByLabel('User Name', { exact: true }).fill(USER_NAME);
    await form.getByLabel('Challenge (hex)', { exact: true }).fill(CHALLENGE);
    expect(await betaEditor(page).inputValue()).toBe(legacyDefault);
    await form.getByLabel('Authenticator Attachment', { exact: true }).selectOption('unspecified');
    await form.getByLabel('Resident Key', { exact: true }).selectOption('required');
    await form.getByLabel('Attestation', { exact: true }).selectOption('none');
    await form.getByRole('switch', { name: 'Exclude Credentials' }).click();
    await form.getByLabel('Timeout (milliseconds)', { exact: true }).fill('5000');
    await form.getByRole('button', { name: 'ES512', exact: true }).click();
    await form.getByRole('button', { name: 'ML-DSA-87', exact: true }).click();
    await form.getByRole('button', { name: 'Hybrid', exact: true }).click();
    await form.getByRole('switch', { name: 'minPinLength' }).click();
    await form.getByLabel('credProtect', { exact: true }).selectOption('userVerificationRequired');
    await form.getByLabel('largeBlob', { exact: true }).selectOption('preferred');
    await form.getByRole('switch', { name: 'prf' }).click();
    await form.getByLabel('prf eval first (hex)', { exact: true }).fill('aa'.repeat(32));
    expect(await betaEditor(page).inputValue()).toBe(legacyChanged);
  });

  test('a registration made in /beta shows the same words in the current modal as in /beta\'s levels', async ({ page }) => {
    await addVirtualAuthenticator(page);
    await openBeta(page);
    const name = await beta(page).getByLabel('User Name', { exact: true }).inputValue();
    await beta(page).getByRole('button', { name: 'Create Credential' }).click();
    const registration = await betaLevel(page, 'registration', 'h4, [data-parity-heading]');
    const betaSubs = await betaSubViews(page);
    await page.getByRole('dialog').getByRole('button', { name: 'Back' }).click();
    const detail = await betaLevel(page, 'detail', 'h4');

    await openCurrent(page);
    const legacy = await legacyDetail(page, name);
    const legacySubs = await legacySubViews(page, '#modalBody');

    expect(report(legacy, [...detail, ...registration], expectedFor(name))).toEqual([]);
    expect(betaSubs).toEqual(legacySubs);
  });
});
