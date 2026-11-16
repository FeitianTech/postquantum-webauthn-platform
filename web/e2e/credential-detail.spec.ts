import { readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';

import type { Page } from '@playwright/test';

import { greyFills } from './design-rules';
import { expect, test } from './fixtures';
import { addVirtualAuthenticator } from './virtual-authenticator';

// A saved credential's details at /#simple/credential/<key> in Chromium,
// against Flask serving the export under the strict CSP: the detail, the
// registration's level and under it a certificate's and the authenticator data's,
// each at its own URL, Back going up one; for credentials registered by
// Chromium's virtual authenticator, and for the server's recorded registrations
// (an ES256 one, and one with an attestation certificate).

const repo = resolve(import.meta.dirname, '..', '..');
const STORAGE_KEY = 'postquantum-webauthn.credentials';

// registration-detail-decodes registers ES256, EdDSA, ML-DSA-65 and a packed one
// with a certificate: the stored credentials, as the browser keeps them.
function goldenRecords(): Record<string, unknown>[] {
  const golden = JSON.parse(
    readFileSync(join(repo, 'tests', 'app', 'characterization', 'golden', 'routes', 'registration-detail-decodes.json'), 'utf8'),
  );
  return golden.requests
    .filter((entry: { request: string }) => entry.request.includes('/register/complete'))
    .map((entry: { body: { storedCredential: Record<string, unknown> } }) => ({ ...entry.body.storedCredential, type: 'simple' }));
}

const [ES256, , , X5C] = goldenRecords();
const named = (record: Record<string, unknown>, userName: string) => ({ ...record, userName, email: userName });

const section = (page: Page) => page.getByRole('tabpanel', { name: 'Simple Authentication' });
const rows = (page: Page) => section(page).locator('li[data-credential-key]');
const dialog = (page: Page) => page.getByRole('dialog');
const shownLevel = (page: Page) => dialog(page).locator('[data-level]:not([hidden])');
const detailSection = (page: Page, title: string) => shownLevel(page).locator(`[data-section="${title}"]`);
const username = () => `e2e-${Date.now()}-${Math.floor(Math.random() * 1e6)}`;

async function openPage(page: Page, hash = '#simple') {
  await page.goto(`/${hash}`);
  await expect(section(page).locator('[data-count]')).toBeVisible();
}

async function keep(page: Page, records: object[]) {
  await page.evaluate(([key, value]) => window.localStorage.setItem(key, value), [STORAGE_KEY, JSON.stringify(records)] as const);
}

async function registerPasskey(page: Page, name: string) {
  await section(page).getByRole('textbox', { name: 'Username' }).fill(name);
  await section(page).getByRole('button', { name: 'Register Passkey' }).click();
  await expect(page.getByText(/^Registration successful! Algorithm: /)).toBeVisible();
  await expect(rows(page).filter({ hasText: name })).toHaveCount(1);
}

async function openDetailOf(page: Page, name: string) {
  await rows(page).filter({ hasText: name }).getByRole('button', { name }).click();
  await expect(dialog(page).getByRole('button', { name: 'Show registration details' })).toBeVisible();
}

test.describe('a saved credential\'s details', () => {
  test('show every section of a credential registered here, its registration and authenticator data, Back going up a level', async ({ page }) => {
    await addVirtualAuthenticator(page);
    await openPage(page);
    const name = username();
    await registerPasskey(page, name);
    await openDetailOf(page, name);

    const key = await rows(page).filter({ hasText: name }).getAttribute('data-credential-key');
    const url = `#simple/credential/${key}`;
    await expect(page).toHaveURL(new RegExp(`${url}$`));
    await expect(dialog(page).getByRole('heading', { level: 2 })).toHaveText('Credential Details');
    for (const title of ['Properties', 'User info at creation', 'Attestation Format', 'Public Key', 'Registration Details']) {
      await expect(detailSection(page, title)).toBeVisible();
    }
    await expect(detailSection(page, 'Public Key')).toContainText('EdDSA (-8)');
    await expect(detailSection(page, 'User info at creation')).toContainText(name);

    await dialog(page).getByRole('button', { name: 'Show registration details' }).click();
    await expect(page).toHaveURL(new RegExp(`${url}/registration$`));
    await expect(dialog(page).getByRole('heading', { level: 2 })).toHaveText('Registration Details');
    for (const title of ['Authenticator Response', 'Server-retrieved Data', 'Attestation Information']) {
      await expect(detailSection(page, title)).toBeVisible();
    }
    await expect(detailSection(page, 'Authenticator Response')).toContainText('"type": "webauthn.create"');

    await detailSection(page, 'Attestation Information').getByRole('button', { name: 'Authenticator Data' }).click();
    await expect(page).toHaveURL(new RegExp(`${url}/registration/authenticator-data$`));
    await expect(dialog(page).getByRole('heading', { level: 2 })).toHaveText('Authenticator Data');
    await expect(shownLevel(page).locator('pre')).toContainText('"rpIdHash"');

    await dialog(page).getByRole('button', { name: 'Back' }).click();
    await expect(page).toHaveURL(new RegExp(`${url}/registration$`));
    await expect(dialog(page).getByRole('button', { name: 'Authenticator Data' })).toBeFocused();
    await page.goBack();
    await expect(page).toHaveURL(new RegExp(`${url}$`));
    await expect(dialog(page).getByRole('button', { name: 'Show registration details' })).toBeVisible();
    await page.goBack();
    await expect(dialog(page)).toBeHidden();
    await expect(page).toHaveURL(/\/#simple$/);

    // Forward opens the details again, and a reload keeps them open.
    await page.goForward();
    await expect(dialog(page).getByRole('heading', { level: 2 })).toHaveText('Credential Details');
    await page.reload();
    await expect(dialog(page).getByRole('heading', { level: 2 })).toHaveText('Credential Details');
  });

  test('open a certificate from a link or a reload, and × closes every level from there', async ({ page }) => {
    await openPage(page);
    await keep(page, [named(X5C, 'x5c@example.com')]);
    await page.reload();
    const url = `#simple/credential/id:${X5C.credentialIdBase64Url}/registration/certificate/1`;
    await page.goto(`/${url}`);

    await expect(dialog(page).getByRole('heading', { level: 2 })).toHaveText('Attestation Certificate');
    await expect(shownLevel(page).locator('[data-certificate-subject]')).toContainText('CN=Characterization Attestation Leaf');
    await expect(detailSection(page, 'Decoded Output').locator('pre')).toContainText('X509v3 extensions:');
    await page.reload();
    await expect(dialog(page).getByRole('heading', { level: 2 })).toHaveText('Attestation Certificate');

    await dialog(page).getByRole('button', { name: 'Close credential details' }).click();
    await expect(dialog(page)).toBeHidden();
    await expect(page).toHaveURL(/\/#simple$/);
  });

  test('open the attestation object and a certificate in the Codec, decoded, Back returning to the level as it was', async ({ page }) => {
    await page.setViewportSize({ width: 1024, height: 600 });
    await openPage(page);
    await keep(page, [named(X5C, 'x5c@example.com')]);
    await page.reload();
    const url = `#simple/credential/id:${X5C.credentialIdBase64Url}/registration`;
    await page.goto(`/${url}`);
    await expect(dialog(page).getByRole('heading', { level: 2 })).toHaveText('Registration Details');

    const decodeObject = dialog(page).getByRole('button', { name: 'Decode in Codec: attestation object' });
    await decodeObject.scrollIntoViewIfNeeded();
    const scroller = dialog(page).locator('[data-overlay-scroll]');
    expect(await scroller.evaluate((element) => element.scrollTop)).toBeGreaterThan(0);
    // Where the button sits in the dialog's view, which Back finds again.
    const place = () =>
      decodeObject.evaluate((button) => Math.round(button.getBoundingClientRect().top - button.closest('[data-overlay-scroll]')!.getBoundingClientRect().top));
    const left = await place();
    await decodeObject.click();

    await expect(page).toHaveURL(/\/#codec$/);
    const decoding = page.getByRole('tabpanel', { name: 'Codec' }).locator('#codec-mode-panel-decode');
    const { attestationObject } = (X5C.registrationResponse as { response: Record<string, string> }).response;
    await expect(decoding.getByRole('textbox', { name: 'Input to decode' })).toHaveValue(attestationObject);
    await expect(decoding.getByRole('region', { name: 'Codec Output' }).locator('[data-role="outcome"]')).toHaveText('Success✓');

    await page.goBack();
    await expect(page).toHaveURL(new RegExp(`${url}$`));
    await expect(decodeObject).toBeFocused();
    await expect.poll(async () => Math.abs((await place()) - left)).toBeLessThanOrEqual(1);

    await dialog(page).getByRole('button', { name: 'Attestation Certificate' }).click();
    await dialog(page).getByRole('button', { name: 'Decode in Codec: certificate' }).click();
    await expect(page).toHaveURL(/\/#codec$/);
    const [kept] = (X5C.properties as { attestationCertificates: { derBase64: string }[] }).attestationCertificates;
    await expect(decoding.getByRole('textbox', { name: 'Input to decode' })).toHaveValue(kept.derBase64);
    await expect(decoding.getByRole('region', { name: 'Codec Output' }).locator('[data-role="type"]')).toContainText('X.509');
    await page.goBack();
    await expect(page).toHaveURL(new RegExp(`${url}/certificate/1$`));
    await expect(dialog(page).getByRole('button', { name: 'Decode in Codec: certificate' })).toBeFocused();
  });

  test('give under the checks what FIDO\'s metadata said of the authenticator, and nothing where the record keeps none', async ({ page }) => {
    await openPage(page);
    // The server's record of the fixture's revoked key, as a registration keeps it since.
    const kept = X5C.properties as { attestationChecks: { metadata: object } };
    const metadata = {
      ...kept.attestationChecks.metadata,
      latest_status: 'Revoked',
      certification_level: 'FIDO Certified L1 • Fixture Revoked Key • (FIDO20020230110005)',
    };
    await keep(page, [
      named({ ...X5C, properties: { ...kept, attestationChecks: { ...kept.attestationChecks, metadata } } }, 'x5c@example.com'),
      named(ES256, 'es256@example.com'),
    ]);
    await page.reload();

    await page.goto(`/#simple/credential/id:${X5C.credentialIdBase64Url}`);
    const checks = detailSection(page, 'Properties').locator('[data-check]');
    await expect(checks).toHaveCount(6);
    await expect(checks.nth(4)).toHaveAttribute('data-check', 'MDS Status');
    await expect(checks.nth(4).locator('[data-value]')).toContainText('Revoked');
    await expect(checks.nth(5)).toHaveAttribute('data-check', 'MDS Certification');
    await expect(checks.nth(5).locator('[data-value]')).toContainText('FIDO Certified L1 • Fixture Revoked Key • (FIDO20020230110005)');
    expect(await greyFills(page, '[data-overlay-panel]')).toEqual([]);

    await page.goto(`/#simple/credential/id:${ES256.credentialIdBase64Url}`);
    await expect(detailSection(page, 'Properties').locator('[data-check]')).toHaveCount(4);
  });

  test('list the attestation\'s findings in words first on the registration\'s level, and none where there are none', async ({ page }) => {
    await openPage(page);
    await keep(page, [named(X5C, 'x5c@example.com'), named(ES256, 'es256@example.com')]);
    await page.reload();

    await page.goto(`/#simple/credential/id:${X5C.credentialIdBase64Url}/registration`);
    const findings = detailSection(page, 'Verification findings');
    await expect(findings.locator('[data-finding="metadata_not_available"] [lang="en"]')).toHaveText(
      'No FIDO metadata was available to check the authenticator against',
    );
    await expect(findings.locator('[data-severity="warning"]')).toContainText('Warning');
    await expect(shownLevel(page).locator('section').first()).toHaveAttribute('data-section', 'Verification findings');

    await page.goto(`/#simple/credential/id:${ES256.credentialIdBase64Url}/registration`);
    await expect(detailSection(page, 'Authenticator Response')).toBeVisible();
    await expect(detailSection(page, 'Verification findings')).toHaveCount(0);
  });

  test('show an ES256 credential the server registered, and correct a level it does not have', async ({ page }) => {
    await openPage(page);
    await keep(page, [named(ES256, 'es256@example.com')]);
    await page.reload();
    await page.goto(`/#simple/credential/id:${ES256.credentialIdBase64Url}/registration/certificate/1`);

    await expect(page).toHaveURL(new RegExp(`#simple/credential/id:${ES256.credentialIdBase64Url}/registration$`));
    await expect(detailSection(page, 'Attestation Information')).toContainText('No attestation certificates available.');
    await dialog(page).getByRole('button', { name: 'Back' }).click();
    await expect(detailSection(page, 'Public Key')).toContainText('ES256 (-7)');
    await expect(detailSection(page, 'User info at creation').locator('[data-identifier="AAGUID"]')).toContainText(
      '00112233-4455-6677-8899-aabbccddeeff',
    );
  });

  test('draw a credential whose stored AAGUID no spelling reads', async ({ page }) => {
    await openPage(page);
    const unreadable = { type: 'simple', userName: 'unreadable', credentialId: 'AQID', aaguid: 'abcde' };
    await keep(page, [named(ES256, 'es256@example.com'), unreadable, named(X5C, 'x5c@example.com')]);
    await page.reload();
    await expect(rows(page)).toHaveCount(3);
    await expect(rows(page).filter({ hasText: 'unreadable' }).locator('[data-unreadable="aaguid"]')).toContainText('abcde');
  });

  for (const width of [1440, 1024, 375]) {
    test(`fit a phone and a wide screen: every level at ${width} px, identifiers whole, no grey, no sideways scroll`, async ({ page }) => {
      await page.setViewportSize({ width, height: 900 });
      await openPage(page);
      await keep(page, [named(X5C, 'x5c-with-a-long-name-for-the-row@example.com')]);
      await page.reload();
      const rowCodes = rows(page).locator('[data-row-values] code');
      await expect(rowCodes.first()).toBeVisible();
      // Geist Mono is fetched when mono text first shows: measure in it, not in its fallback.
      await page.evaluate(() => document.fonts.ready);
      const cutInRow = await rowCodes.evaluateAll((codes) => codes.filter((code) => code.scrollWidth > code.clientWidth).map((code) => code.textContent));
      expect(cutInRow).toEqual([]);

      await openDetailOf(page, 'x5c-with-a-long-name-for-the-row@example.com');
      const aaguid = dialog(page).locator('[data-identifier="AAGUID"] code');
      await expect(aaguid.last()).toHaveText('00112233-4455-6677-8899-aabbccddeeff');
      await page.evaluate(() => document.fonts.ready);
      const cutAaguid = await aaguid.evaluateAll((codes) => codes.filter((code) => code.scrollWidth > code.clientWidth).map((code) => code.textContent));
      expect(cutAaguid).toEqual([]);
      expect(await greyFills(page, '[data-overlay-panel]')).toEqual([]);

      for (const level of ['Show registration details', 'Attestation Certificate']) {
        await dialog(page).getByRole('button', { name: level }).click();
        await expect(shownLevel(page)).toBeVisible();
        expect(await greyFills(page, '[data-overlay-panel]')).toEqual([]);
      }
      expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(width);
    });
  }
});

test.describe('another tab', () => {
  test('a deletion in one tab shows in the other without a reload', async ({ page, context }) => {
    await openPage(page);
    await keep(page, [named(ES256, 'first@example.com'), named(X5C, 'second@example.com')]);
    await page.reload();
    await expect(rows(page)).toHaveCount(2);
    const other = await context.newPage();
    await openPage(other);
    await expect(rows(other)).toHaveCount(2);

    await rows(page).filter({ hasText: 'first@example.com' }).getByRole('button', { name: 'Delete' }).click();
    await page.getByRole('alertdialog').getByRole('button', { name: 'Delete' }).click();
    await expect(rows(page)).toHaveCount(1);
    await expect(rows(other)).toHaveCount(1);

    await section(other).getByRole('button', { name: 'Clear All' }).click();
    await other.getByRole('alertdialog', { name: 'Clear All' }).getByRole('button', { name: 'Clear All' }).click();
    await expect(rows(other)).toHaveCount(0);
    await expect(rows(page)).toHaveCount(0);
    await other.close();
  });

  test('two tabs holding an advanced credential with an artifact settle, without waking each other for ever', async ({ page, context }) => {
    await addVirtualAuthenticator(page);
    await page.goto('/#advanced');
    await page.getByRole('tabpanel', { name: 'Advanced Authentication' }).getByRole('button', { name: 'Create Credential' }).click();
    await expect(page.getByRole('heading', { level: 2, name: 'Registration Details' })).toBeVisible();

    const other = await context.newPage();
    await openPage(other);
    await expect(rows(other)).toHaveCount(1);
    const counting = () => (window as unknown as { __writes?: number }).__writes ?? 0;
    for (const tab of [page, other]) {
      await tab.evaluate(() => {
        window.addEventListener('storage', () => {
          const holder = window as unknown as { __writes?: number };
          holder.__writes = (holder.__writes ?? 0) + 1;
        });
      });
    }
    // One change, which each tab reads again (and warms up once).
    await page.evaluate((key) => {
      const records = JSON.parse(window.localStorage.getItem(key) ?? '[]');
      records[0].userName = 'renamed';
      window.localStorage.setItem(key, JSON.stringify(records));
    }, STORAGE_KEY);
    await expect(rows(other).filter({ hasText: 'renamed' })).toHaveCount(1);
    await other.waitForTimeout(1500);
    const settled = [await page.evaluate(counting), await other.evaluate(counting)];
    await other.waitForTimeout(1500);
    expect([await page.evaluate(counting), await other.evaluate(counting)]).toEqual(settled);
    await other.close();
  });
});
