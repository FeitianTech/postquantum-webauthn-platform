import type { Locator, Page } from '@playwright/test';

import { STORAGE_KEY, openCurrent } from './credential-views';
import { greyFills } from './design-rules';
import { expect, test } from './fixtures';
import { addVirtualAuthenticator } from './virtual-authenticator';

// The Advanced tab at /beta#advanced in Chromium, against Flask serving the
// export under the strict CSP: registrations answered by Chromium's virtual
// authenticator (a CTAP2 key on USB: the default request asks for a
// cross-platform one), from the form and from an edited JSON; the saved
// credentials' drawer; and credentials registered in one UI used in the other.

const section = (page: Page) => page.getByRole('tabpanel', { name: 'Advanced Authentication' });
const editor = (page: Page) => section(page).getByRole('textbox', { name: 'JSON Editor (CredentialCreationOptions)' });
const dialog = (page: Page) => page.getByRole('dialog', { name: /Registration Details|Credential Details/ });

async function openBeta(page: Page) {
  await page.goto('/beta#advanced');
  await expect(editor(page)).toHaveValue(/"publicKey"/);
}

async function request(page: Page) {
  return JSON.parse(await editor(page).inputValue());
}

async function register(page: Page) {
  await section(page).getByRole('button', { name: 'Create Credential' }).click();
  await expect(page.getByText(/^Advanced registration successful! Algorithm: /)).toBeVisible();
  await expect(page.getByRole('heading', { level: 2, name: 'Registration Details' })).toBeVisible();
}

async function box(locator: Locator) {
  const found = await locator.boundingBox();
  if (!found) throw new Error('not laid out');
  return found;
}

test.describe('/beta#advanced', () => {
  test('registers from the form, keeps the credential, and opens its registration with the detail under it', async ({ page }) => {
    const authenticator = await addVirtualAuthenticator(page);
    await openBeta(page);
    const name = await section(page).getByLabel('User Name').inputValue();

    await register(page);
    const [created] = await authenticator.credentials();
    expect(created.rpId).toBe('localhost');
    await expect(page).toHaveURL(/#advanced\/credential\/.+\/registration$/);
    const panel = section(page).locator('[data-ceremony-result]');
    await expect(panel).toContainText('Last registration');
    await expect(panel).toContainText('Issued by this server for this ceremony. First use.');

    await page.getByRole('dialog').getByRole('button', { name: 'Back' }).click();
    await expect(page.getByRole('heading', { level: 2, name: 'Credential Details' })).toBeVisible();
    await expect(page.getByRole('dialog').getByRole('heading', { level: 3, name })).toBeVisible();
    await page.getByRole('dialog').getByRole('button', { name: 'Close credential details' }).click();
    await expect(page).toHaveURL(/#advanced$/);
    await expect(section(page).getByRole('button', { name: 'Saved Credentials 1' })).toBeVisible();
    // The fields drawn at random are drawn again.
    await expect(section(page).getByLabel('User Name')).not.toHaveValue(name);
  });

  test('registers from an edited JSON: the form follows the edit, and the request sent is the edit', async ({ page }) => {
    await addVirtualAuthenticator(page);
    await openBeta(page);
    const edited = await request(page);
    edited.publicKey.pubKeyCredParams = [{ type: 'public-key', alg: -7 }];
    await editor(page).fill(JSON.stringify(edited, null, 2));

    await expect(section(page).getByRole('button', { name: 'ES256', exact: true })).toHaveAttribute('aria-pressed', 'true');
    await expect(section(page).getByRole('button', { name: 'EdDSA', exact: true })).toHaveAttribute('aria-pressed', 'false');
    const begin = page.waitForRequest((sent) => sent.url().endsWith('/api/advanced/register/begin'));
    await section(page).getByRole('button', { name: 'Create Credential' }).click();
    expect(JSON.parse((await begin).postData()!).publicKey.pubKeyCredParams).toEqual([{ type: 'public-key', alg: -7 }]);
    await expect(page.getByText(/^Advanced registration successful! Algorithm: ES256/)).toBeVisible();
  });

  test('says where an edit stops being JSON, keeps the form, and refuses to send it', async ({ page }) => {
    await addVirtualAuthenticator(page);
    await openBeta(page);
    const before = await section(page).getByLabel('Attestation', { exact: true }).inputValue();
    await editor(page).fill('{\n  "publicKey": {\n    "attestation": "none",\n  }\n}');

    await expect(section(page).getByRole('alert')).toContainText('JSON validation failed:');
    await expect(section(page).locator('[data-location]')).toHaveText('Line 4, column 3');
    await expect(section(page).getByLabel('Attestation', { exact: true })).toHaveValue(before);
    let asked = false;
    page.on('request', (sent) => {
      if (sent.url().includes('/api/advanced/register/')) asked = true;
    });
    await section(page).getByRole('button', { name: 'Create Credential' }).click();
    await expect(section(page).locator('[data-role="failure"]')).toContainText('Credential registration failed:');
    expect(asked).toBe(false);
  });

  test('lists the saved credentials in a drawer, and opens a credential\'s details over it', async ({ page }) => {
    await addVirtualAuthenticator(page);
    await openBeta(page);
    const name = await section(page).getByLabel('User Name').inputValue();
    await register(page);
    await page.getByRole('dialog').getByRole('button', { name: 'Close credential details' }).click();

    await section(page).getByRole('button', { name: 'Saved Credentials 1' }).click();
    const drawer = page.getByRole('dialog', { name: 'Saved Credentials' });
    await expect(drawer).toBeVisible();
    await drawer.getByRole('button', { name, exact: true }).click();
    await expect(page.getByRole('heading', { level: 2, name: 'Credential Details' })).toBeVisible();
    await page.keyboard.press('Escape');
    await expect(page.getByRole('heading', { level: 2, name: 'Credential Details' })).toHaveCount(0);
    await expect(drawer).toBeVisible();
    await expect(drawer.getByRole('button', { name, exact: true })).toBeFocused();
    await page.keyboard.press('Escape');
    await expect(drawer).toHaveCount(0);
  });

  test('registers in /beta a credential the current Advanced tab authenticates with', async ({ page }) => {
    await addVirtualAuthenticator(page);
    await openBeta(page);
    await register(page);

    await openCurrent(page);
    await page.locator('[data-action="switch-tab"][data-tab="advanced"]').first().click();
    await page.locator('[data-action="switch-sub-tab"][data-sub-tab="authentication"]').click();
    await page.locator('[data-action="advanced-authenticate"]').click();
    await expect(page.locator('#advanced-status')).toHaveText('Advanced authentication successful!');
  });

  test('lists a credential the current Advanced tab registered, and opens its registration', async ({ page }) => {
    await addVirtualAuthenticator(page);
    await openCurrent(page);
    await page.locator('[data-action="switch-tab"][data-tab="advanced"]').first().click();
    const name = await page.locator('#user-name').inputValue();
    await page.locator('[data-action="advanced-register"]').click();
    await expect(page.locator('#registrationResultModal')).toBeVisible();

    await openBeta(page);
    await section(page).getByRole('button', { name: 'Saved Credentials 1' }).click();
    await page.getByRole('dialog', { name: 'Saved Credentials' }).getByRole('button', { name, exact: true }).click();
    await page.getByRole('dialog').getByRole('button', { name: 'Show registration details' }).click();
    await expect(page.getByRole('heading', { level: 2, name: 'Registration Details' })).toBeVisible();
    await expect(page.getByRole('dialog').locator('[data-level="registration"]')).toContainText('Response for navigator.credentials.create()');
  });

  for (const [width, height] of [
    [1440, 900],
    [1024, 900],
    [375, 812],
  ] as const) {
    test(`fits ${width} px: no sideways scroll, no grey fill, the editor ${width >= 1280 ? 'beside' : 'below'} the form`, async ({ page }) => {
      await page.setViewportSize({ width, height });
      await openBeta(page);

      expect(await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth)).toBeLessThanOrEqual(0);
      expect(await greyFills(page, '#nav-panel-advanced')).toEqual([]);
      const form = await box(section(page).locator('[data-registration-form]'));
      const json = await box(section(page).locator('#advanced-ceremony-panel-registration [data-json-editor]'));
      if (width >= 1280) expect(json.x).toBeGreaterThanOrEqual(form.x + form.width);
      else expect(json.y).toBeGreaterThanOrEqual(form.y + form.height);

      await section(page).getByRole('button', { name: /^Saved Credentials/ }).click();
      const drawer = page.getByRole('dialog', { name: 'Saved Credentials' });
      await expect(drawer).toBeVisible();
      expect(await greyFills(page, '[data-overlay="drawer"]')).toEqual([]);
    });
  }

  test('keeps what an edit typed through a form change: rp.id and a timeout of 0', async ({ page }) => {
    await openBeta(page);
    const edited = await request(page);
    edited.publicKey.rp.id = 'example.com';
    edited.publicKey.timeout = 0;
    await editor(page).fill(JSON.stringify(edited, null, 2));

    await section(page).getByRole('switch', { name: 'credProps' }).click();

    const followed = await request(page);
    expect(followed.publicKey.extensions).not.toHaveProperty('credProps');
    expect([followed.publicKey.rp.id, followed.publicKey.timeout]).toEqual(['example.com', 0]);
  });
});

// The Authentication segment: authentications answered by the same virtual
// authenticator, of credentials registered in either UI.
const authentication = (page: Page) => page.locator('#advanced-ceremony-panel-authentication');
const authEditor = (page: Page) => section(page).getByRole('textbox', { name: 'JSON Editor (CredentialRequestOptions)' });
const result = (page: Page) => section(page).locator('[data-ceremony-result]');

async function toAuthentication(page: Page) {
  await section(page).getByRole('tab', { name: 'Authentication' }).click();
  await expect(authEditor(page)).toHaveValue(/"publicKey"/);
}

/** Registers in /beta#advanced and closes the details the registration opens; gives the saved record. */
async function registerInBeta(page: Page) {
  await openBeta(page);
  await register(page);
  await page.keyboard.press('Escape');
  await expect(page).toHaveURL(/#advanced$/);
  const records = await page.evaluate((key) => JSON.parse(window.localStorage.getItem(key) ?? '[]'), STORAGE_KEY);
  return records.at(-1) as { credentialIdHex: string; userName: string; signCount?: number };
}

test.describe('/beta#advanced authentication', () => {
  test('authenticates from the form: the counter and the challenge, the counter kept, the row tinted', async ({ page }) => {
    await addVirtualAuthenticator(page);
    await registerInBeta(page);
    await toAuthentication(page);

    await section(page).getByRole('button', { name: 'Assert Credential' }).click();

    await expect(page.getByText('Advanced authentication successful!')).toBeVisible();
    await expect(result(page)).toContainText('Last authentication');
    await expect(result(page).locator('[data-row="Signature counter"]')).toContainText('Higher than the last counter the server saw');
    await expect(result(page).locator('[data-row="Challenge"]')).toContainText('Issued by this server for this ceremony. First use.');
    await expect(page.locator('#nav-panel-simple li[data-flash="success"]')).toHaveCount(1);
    const [record] = await page.evaluate((key) => JSON.parse(window.localStorage.getItem(key) ?? '[]'), STORAGE_KEY);
    expect(record.signCount).toBeGreaterThan(0);
    await expect(page.getByRole('dialog')).toHaveCount(0);
  });

  test('authenticates from an edited JSON: the form follows the edit, and the request sent is the edit', async ({ page }) => {
    await addVirtualAuthenticator(page);
    await registerInBeta(page);
    await toAuthentication(page);
    const edited = JSON.parse(await authEditor(page).inputValue());
    edited.publicKey.userVerification = 'discouraged';
    edited.publicKey.allowCredentials = [{ ...edited.publicKey.allowCredentials[0], transports: ['usb'] }];
    await authEditor(page).fill(JSON.stringify(edited, null, 2));
    await expect(authentication(page).getByLabel('User Verification', { exact: true })).toHaveValue('discouraged');

    const begin = page.waitForRequest('**/api/advanced/authenticate/begin');
    await section(page).getByRole('button', { name: 'Assert Credential' }).click();

    expect((await begin).postDataJSON().publicKey).toEqual(edited.publicKey);
    await expect(page.getByText('Advanced authentication successful!')).toBeVisible();
  });

  test('says in place why the server refused an authentication, with the result, and tints the credential', async ({ page, watch }) => {
    // The refused complete's own status.
    watch.allow(/status of 400/);
    await addVirtualAuthenticator(page);
    await registerInBeta(page);
    await toAuthentication(page);
    // The authenticator signed the client data's SHA-256 hash: SHA-512 does not verify.
    await authentication(page).getByLabel('Hash Algorithm', { exact: true }).selectOption('SHA-512');

    await section(page).getByRole('button', { name: 'Assert Credential' }).click();

    await expect(section(page).locator('[data-role="failure"]')).toHaveText(/^Advanced authentication failed: /);
    await expect(result(page)).toContainText('Last authentication');
    await expect(result(page).locator('[data-row="Challenge"]')).toContainText('Issued by this server for this ceremony.');
    await expect(page.locator('#nav-panel-simple li[data-flash="failure"]')).toHaveCount(1);
  });

  test('registers in /beta a credential the current tab chooses in Allow Credentials and authenticates with', async ({ page }) => {
    await addVirtualAuthenticator(page);
    const record = await registerInBeta(page);

    await openCurrent(page);
    await page.locator('[data-action="switch-tab"][data-tab="advanced"]').first().click();
    await page.locator('[data-action="switch-sub-tab"][data-sub-tab="authentication"]').click();
    await page.locator('#allow-credentials').selectOption(record.credentialIdHex);
    await expect(page.locator('#json-editor')).toHaveValue(new RegExp(record.credentialIdHex));
    await page.locator('[data-action="advanced-authenticate"]').click();
    await expect(page.locator('#advanced-status')).toHaveText('Advanced authentication successful!');
  });

  test('chooses and authenticates with a credential the current tab registered', async ({ page }) => {
    await addVirtualAuthenticator(page);
    await openCurrent(page);
    await page.locator('[data-action="switch-tab"][data-tab="advanced"]').first().click();
    const name = await page.locator('#user-name').inputValue();
    await page.locator('[data-action="advanced-register"]').click();
    await expect(page.locator('#registrationResultModal')).toBeVisible();

    await openBeta(page);
    await toAuthentication(page);
    const allow = authentication(page).getByLabel('Allow Credentials', { exact: true });
    const option = allow.locator('option').filter({ hasText: name });
    await allow.selectOption(await option.getAttribute('value'));
    expect(JSON.parse(await authEditor(page).inputValue()).publicKey.allowCredentials).toHaveLength(1);
    await section(page).getByRole('button', { name: 'Assert Credential' }).click();
    await expect(page.getByText('Advanced authentication successful!')).toBeVisible();
  });

  for (const [width, height] of [
    [1440, 900],
    [1024, 900],
    [375, 812],
  ] as const) {
    test(`fits ${width} px: no sideways scroll, no grey fill, the editor ${width >= 1280 ? 'beside' : 'below'} the form`, async ({ page }) => {
      await page.setViewportSize({ width, height });
      await openBeta(page);
      await toAuthentication(page);

      expect(await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth)).toBeLessThanOrEqual(0);
      expect(await greyFills(page, '#nav-panel-advanced')).toEqual([]);
      const form = await box(authentication(page).locator('[data-authentication-form]'));
      const json = await box(authentication(page).locator('[data-json-editor]'));
      if (width >= 1280) expect(json.x).toBeGreaterThanOrEqual(form.x + form.width);
      else expect(json.y).toBeGreaterThanOrEqual(form.y + form.height);
    });
  }
});
