import { readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';

import type { Page } from '@playwright/test';

import { betaLevel, betaSubViews, expectedFor, keep, legacyDetail, legacySubViews, openCurrent, report } from './credential-views';
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

// The authentication in both UIs, over the two credentials the recorded
// authentications registered (the first reports largeBlob and prf support):
// the form's words section by section, the 11 info popups, the choices, the
// editor's text for the same settings byte for byte; and the result of an
// authentication with a credential registered by the virtual authenticator.
const repo = resolve(import.meta.dirname, '..', '..');
const RECORDS = (
  JSON.parse(readFileSync(join(repo, 'tests', 'app', 'characterization', 'golden', 'routes', 'advanced-authentication-answers.json'), 'utf8'))
    .requests as { request: string; body: { storedCredential: Record<string, unknown> } }[]
)
  .filter((entry) => entry.request.includes('/register/complete'))
  .map((entry, index): Record<string, unknown> => ({
    ...entry.body.storedCredential,
    type: 'advanced',
    userName: index ? 'plain@example.com' : 'capable@example.com',
  }));
const CAPABLE_ID = RECORDS[0].credentialIdHex as string;

const betaAuth = (page: Page) => page.locator('#advanced-ceremony-panel-authentication');
const betaAuthEditor = (page: Page) => beta(page).getByRole('textbox', { name: 'JSON Editor (CredentialRequestOptions)' });

async function openLegacyAuthentication(page: Page, records: object[] = RECORDS) {
  await page.goto('/');
  await keep(page, records);
  await openCurrent(page);
  await page.locator('[data-action="switch-tab"][data-tab="advanced"]').first().click();
  await page.locator('[data-action="switch-sub-tab"][data-sub-tab="authentication"]').click();
  await expect(page.locator('#json-editor')).toHaveValue(/"rpId"/);
}

async function openBetaAuthentication(page: Page, records: object[] = RECORDS) {
  await page.goto('/beta#advanced');
  await keep(page, records);
  await page.reload();
  await beta(page).getByRole('tab', { name: 'Authentication' }).click();
  await expect(betaAuthEditor(page)).toHaveValue(/"rpId"/);
}

test.describe('the Advanced tab\'s authentication in / and in /beta', () => {
  test('shows the same words, section by section, and the same notes', async ({ page }) => {
    await openLegacyAuthentication(page, []);
    const legacyNotes = await page.locator('#large-blob-capability-message, #prf-capability-message').allTextContents();
    await page.evaluate(() => {
      for (const element of document.querySelectorAll('#authentication-form .info-popup, #authentication-form .checkbox-item, #authentication-form .error-message')) {
        element.setAttribute('data-parity-skip', '');
      }
    });
    const legacy = await readShownText(page.locator('#authentication-form'), '.section-header span');

    await openBetaAuthentication(page, []);
    const form = betaAuth(page).locator('[data-authentication-form]');
    const betaNotes = [
      await form.getByLabel('largeBlob', { exact: true }).getAttribute('aria-describedby'),
      await form.getByLabel('prf eval first (hex)', { exact: true }).getAttribute('aria-describedby'),
    ];
    const notes = await Promise.all(betaNotes.map((id) => page.locator(`[id="${id}"]`).textContent()));
    // The notes are compared on their own: the current form keeps them among its errors.
    await page.evaluate(() => {
      for (const element of document.querySelectorAll('[data-authentication-form] [id$="-hint"]')) element.setAttribute('data-parity-skip', '');
    });
    const shown = await readShownText(form, 'h3');

    expect(describeDifferences(compareShownText(legacy, shown, []))).toEqual([]);
    expect(legacy.map((section) => section.heading)).toEqual(shown.map((section) => section.heading));
    expect(notes).toEqual(legacyNotes.map((note) => note.trim()));
  });

  test('gives each field the same info popup, in English and 中文', async ({ page }) => {
    await openLegacyAuthentication(page);
    const legacy = await page.locator('#authentication-form .form-group').evaluateAll((groups) =>
      groups
        .filter((group) => group.querySelector('.info-popup'))
        .map((group) => ({
          label: (group.querySelector('.label-with-info label')?.textContent ?? '').trim(),
          en: group.querySelector('.info-popup .text-en')?.textContent ?? '',
          zh: group.querySelector('.info-popup .text-zh')?.textContent ?? '',
        })),
    );

    await openBetaAuthentication(page);
    const shown = await betaAuth(page)
      .locator('[data-authentication-form] button[aria-label^="About "]')
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

    expect(shown).toHaveLength(11);
    expect(shown.map((popup) => popup.label)).toEqual(legacy.map((popup) => popup.label));
    expect(shown.map(({ en, zh }) => [squeeze(en), squeeze(zh)])).toEqual(legacy.map(({ en, zh }) => [squeeze(en), squeeze(zh)]));
  });

  test('offers the same choices, in the same order', async ({ page }) => {
    const choices = (select: string) => page.locator(select).locator('option').allTextContents();
    await openLegacyAuthentication(page);
    const legacy = {
      allow: await choices('#allow-credentials'),
      verification: await choices('#user-verification-auth'),
      hash: await choices('#hash-algorithm-auth'),
      largeBlob: await choices('#large-blob-auth'),
      hints: (await page.locator('#authentication-form .checkbox-item span').allTextContents()).map((text) => text.trim()),
    };

    await openBetaAuthentication(page);
    const form = betaAuth(page);
    const options = (label: string) => form.getByLabel(label, { exact: true }).locator('option').allTextContents();
    expect({
      allow: await options('Allow Credentials'),
      verification: await options('User Verification'),
      hash: await options('Hash Algorithm'),
      largeBlob: await options('largeBlob'),
      hints: await form.getByRole('group', { name: 'Hints' }).getByRole('button').allTextContents(),
    }).toEqual(legacy);
    expect(legacy.allow).toHaveLength(4);
  });

  test('writes the same request for the same settings, byte for byte', async ({ page }) => {
    await openLegacyAuthentication(page);
    const legacyTexts = [];
    await page.locator('#challenge-auth').fill(CHALLENGE);
    legacyTexts.push(await page.locator('#json-editor').inputValue());
    await page.locator('#user-verification-auth').selectOption('discouraged');
    await page.locator('#timeout-auth').fill('5000');
    await page.locator('#hint-hybrid-auth').setChecked(true, { force: true });
    legacyTexts.push(await page.locator('#json-editor').inputValue());
    await page.locator('#allow-credentials').selectOption(CAPABLE_ID);
    await page.locator('#large-blob-auth').selectOption('write');
    await page.locator('#large-blob-write').fill('ab'.repeat(32));
    await page.locator('#prf-eval-first-auth').fill('cd'.repeat(32));
    await page.locator('#prf-eval-second-auth').fill('ef'.repeat(32));
    legacyTexts.push(await page.locator('#json-editor').inputValue());
    await page.locator('#allow-credentials').selectOption('empty');
    await page.locator('#large-blob-auth').selectOption('read');
    legacyTexts.push(await page.locator('#json-editor').inputValue());

    await openBetaAuthentication(page);
    const form = betaAuth(page);
    const betaTexts = [];
    await form.getByLabel('Challenge (hex)', { exact: true }).fill(CHALLENGE);
    betaTexts.push(await betaAuthEditor(page).inputValue());
    await form.getByLabel('User Verification', { exact: true }).selectOption('discouraged');
    await form.getByLabel('Timeout (milliseconds)', { exact: true }).fill('5000');
    await form.getByRole('button', { name: 'Hybrid', exact: true }).click();
    betaTexts.push(await betaAuthEditor(page).inputValue());
    await form.getByLabel('Allow Credentials', { exact: true }).selectOption(CAPABLE_ID);
    await form.getByLabel('largeBlob', { exact: true }).selectOption('write');
    await form.getByLabel('largeBlob write (hex)', { exact: true }).fill('ab'.repeat(32));
    await form.getByLabel('prf eval first (hex)', { exact: true }).fill('cd'.repeat(32));
    await form.getByLabel('prf eval second (hex)', { exact: true }).fill('ef'.repeat(32));
    betaTexts.push(await betaAuthEditor(page).inputValue());
    await form.getByLabel('Allow Credentials', { exact: true }).selectOption('empty');
    await form.getByLabel('largeBlob', { exact: true }).selectOption('read');
    betaTexts.push(await betaAuthEditor(page).inputValue());

    expect(betaTexts).toEqual(legacyTexts);
    expect(JSON.parse(legacyTexts[2]).publicKey.extensions.prf.eval.second).toEqual({ $hex: 'ef'.repeat(32) });
  });

  test('says the same after an authentication', async ({ page }) => {
    await addVirtualAuthenticator(page);
    await openBeta(page);
    await beta(page).getByRole('button', { name: 'Create Credential' }).click();
    await expect(page.getByRole('heading', { level: 2, name: 'Registration Details' })).toBeVisible();

    await openCurrent(page);
    await page.locator('[data-action="switch-tab"][data-tab="advanced"]').first().click();
    await page.locator('[data-action="switch-sub-tab"][data-sub-tab="authentication"]').click();
    await page.locator('[data-action="advanced-authenticate"]').click();
    await expect(page.locator('#advanced-status')).toHaveText('Advanced authentication successful!');
    const legacy = await page.locator('#advanced-ceremony-result').innerText();

    await page.goto('/beta#advanced');
    await beta(page).getByRole('tab', { name: 'Authentication' }).click();
    await beta(page).getByRole('button', { name: 'Assert Credential' }).click();
    await expect(page.getByText('Advanced authentication successful!')).toBeVisible();
    const shown = await beta(page).locator('[data-ceremony-result]').innerText();

    // The counter's value is the authenticator's, one more for the second authentication.
    const words = (text: string) => squeeze(text.replace(/\b\d+\b/g, '#'));
    expect(words(shown)).toBe(words(legacy));
    expect(legacy).toContain('Issued by this server for this ceremony.');
  });
});
