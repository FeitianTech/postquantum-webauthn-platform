import { readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';

import type { Page } from '@playwright/test';

import { expect, test } from './fixtures';
import { type ExpectedDifference, type ShownSection, compareShownText, describeDifferences, readShownText } from './parity';
import { addVirtualAuthenticator } from './virtual-authenticator';

// What a saved credential's details and its registration show in the current UI
// at / (the modal, its registration view, the second modal for a certificate or
// the authenticator data) and in /beta (the dialog's levels), for the same
// stored records and for an advanced credential registered at /: word for word
// per section (layout, separators and controls' own labels set aside:
// parity.ts), and each certificate's and the authenticator data's text equal.
// Every difference must be one listed below, with its reason.

const repo = resolve(import.meta.dirname, '..', '..');
const STORAGE_KEY = 'postquantum-webauthn.credentials';

// registration-detail-decodes: ES256, EdDSA, ML-DSA-65 and a packed one with a
// certificate, as the server registered them.
const REGISTERED = JSON.parse(
  readFileSync(join(repo, 'tests', 'app', 'characterization', 'golden', 'routes', 'registration-detail-decodes.json'), 'utf8'),
)
  .requests.filter((entry: { request: string }) => entry.request.includes('/register/complete'))
  .map((entry: { body: { storedCredential: Record<string, unknown> } }) => entry.body.storedCredential);

const RECORDS = ['es256', 'eddsa', 'mldsa65', 'x5c'].map((name, index) => ({
  ...REGISTERED[index],
  type: 'simple',
  userName: `${name}@example.com`,
  email: `${name}@example.com`,
})) as Record<string, unknown>[];

const escape = (word: string) => word.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

function expectedFor(name: string): ExpectedDifference[] {
  return [
    { only: 'beta', token: new RegExp(`^${escape(name)}$`), section: '', reason: 'the credential\'s name, the details\' title (new)' },
    {
      only: 'beta',
      token: /^(Registration|Details)$/,
      section: 'Registration Details',
      reason: 'the way to the registration\'s own level: its heading (the button\'s label is set aside)',
    },
    {
      only: 'legacy',
      token: /^[()]$/,
      section: 'Properties',
      reason: 'the roots Root Valid tried (FIDO MDS, Chain) are chips, each in its verdict\'s tone, not a list in parentheses',
    },
  ];
}

async function keep(page: Page, records: object[]) {
  await page.evaluate(([key, value]) => window.localStorage.setItem(key, value), [STORAGE_KEY, JSON.stringify(records)] as const);
}

async function openCurrent(page: Page) {
  await page.goto('/');
  await expect(page.locator('body')).toHaveClass(/app-loaded/);
}

async function legacyDetail(page: Page, name: string) {
  await page.locator('#simple-credentials-list .credential-item').filter({ hasText: name }).click();
  await expect(page.locator('#credentialModal')).toBeVisible();
  await expect(page.locator('#modalBody')).toContainText('Attestation Information');
  return readShownText(page.locator('#modalBody'), 'h3, h4');
}

// The second modal's text for each of the modal's certificate and authenticator-data buttons.
async function legacySubViews(page: Page, root: string) {
  const texts: Record<string, string> = {};
  const buttons = page.locator(`${root} .registration-detail-button-row button`);
  for (let index = 0; index < (await buttons.count()); index += 1) {
    const button = buttons.nth(index);
    const label = (await button.textContent())!.trim();
    await button.click();
    await expect(page.locator('#registrationDetailModal')).toBeVisible();
    texts[label] = await page.locator('#registrationDetailModalBody textarea').inputValue();
    await page.locator('[data-action="close-registration-detail-modal"]').click();
  }
  return texts;
}

async function betaLevel(page: Page, level: string, headings: string) {
  const root = page.getByRole('dialog').locator(`[data-level="${level}"]`);
  await expect(root).toBeVisible();
  return readShownText(root, headings);
}

// The dialog's certificate and authenticator-data levels' text, by their buttons.
async function betaSubViews(page: Page) {
  const texts: Record<string, string> = {};
  const dialog = page.getByRole('dialog');
  const buttons = dialog.locator('[data-level="registration"] [data-level-open]');
  const labels = await buttons.allTextContents();
  for (const label of labels) {
    await dialog.locator('[data-level="registration"]').getByRole('button', { name: label.trim(), exact: true }).click();
    const shown = dialog.locator('[data-level]:not([hidden])');
    await expect(shown).not.toHaveAttribute('data-level', 'registration');
    const text = shown.locator('[data-section="Decoded Output"] pre, :scope > div > pre, pre').last();
    texts[label.trim()] = (await text.textContent()) ?? '';
    await dialog.getByRole('button', { name: 'Back' }).click();
    await expect(dialog.locator('[data-level="registration"]')).toBeVisible();
  }
  return texts;
}

function report(legacy: ShownSection[], beta: ShownSection[], expected: ExpectedDifference[]) {
  const differences = compareShownText(legacy, beta, expected);
  return describeDifferences(differences.filter((difference) => !difference.reason));
}

test.describe('a saved credential\'s details in / and in /beta', () => {
  for (const record of RECORDS) {
    const name = record.userName as string;
    test(`show the same words, section by section, and the same certificates and authenticator data: ${name}`, async ({ page }) => {
      await openCurrent(page);
      await keep(page, RECORDS);
      await page.reload();
      await expect(page.locator('body')).toHaveClass(/app-loaded/);
      const legacy = await legacyDetail(page, name);
      const legacySubs = await legacySubViews(page, '#modalBody');

      await page.goto('/beta#simple');
      await page.goto(`/beta#simple/credential/id:${record.credentialIdBase64Url}`);
      const detail = await betaLevel(page, 'detail', 'h4');
      await page.getByRole('dialog').getByRole('button', { name: 'Show registration details' }).click();
      const registration = await betaLevel(page, 'registration', 'h4, [data-parity-heading]');
      const betaSubs = await betaSubViews(page);

      expect(report(legacy, [...detail, ...registration], expectedFor(name))).toEqual([]);
      expect(legacy.map((section) => section.heading)).toEqual(
        [...detail, ...registration].map((section) => section.heading).filter((heading) => heading && heading !== 'Registration Details'),
      );
      expect(betaSubs).toEqual(legacySubs);
    });
  }

  test('an advanced registration\'s result at / shows the words its registration level shows in /beta', async ({ page }) => {
    await addVirtualAuthenticator(page);
    await openCurrent(page);
    await page.locator('[data-action="switch-tab"][data-tab="advanced"]').first().click();
    await page.locator('[data-action="advanced-register"]').click();
    await expect(page.locator('#registrationResultModal')).toBeVisible();
    const legacy = await readShownText(page.locator('#registrationResultBody'), 'h3, h4');
    const legacySubs = await legacySubViews(page, '#registrationResultBody');

    await page.goto('/beta#simple');
    const key = await page.locator('li[data-credential-key]').first().getAttribute('data-credential-key');
    await page.goto(`/beta#simple/credential/${encodeURIComponent(key!).replace(/%3A/gi, ':')}/registration`);
    const beta = await betaLevel(page, 'registration', 'h4, [data-parity-heading]');
    const betaSubs = await betaSubViews(page);

    expect(report(legacy, beta, [])).toEqual([]);
    expect(legacy.map((section) => section.heading)).toEqual(beta.map((section) => section.heading));
    expect(betaSubs).toEqual(legacySubs);
  });
});
