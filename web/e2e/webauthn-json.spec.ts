import type { Page } from '@playwright/test';

import { expect, test } from './fixtures';
import { addVirtualAuthenticator } from './virtual-authenticator';

// The ceremonies on the browser's own WebAuthn JSON in Chromium:
// PublicKeyCredential.parseCreationOptionsFromJSON / parseRequestOptionsFromJSON
// read the server's options, and credential.toJSON() writes what the server is
// sent. The Simple tab's request is the server's (no hints, no extensions);
// the Advanced tab asks for hints, prf and largeBlob, answered by a CTAP 2.1
// virtual authenticator. Without the methods, the page asks for an update and
// runs nothing.

type Shown = { bytes: string } | string | number | boolean | null | Shown[] | { [key: string]: Shown };
type Ceremony = { name: 'create' | 'get'; publicKey: Record<string, Shown> };

// What navigator.credentials.create() and get() are given, kept in the page
// before its own code runs: each buffer as its hex.
async function recordCeremonies(page: Page) {
  await page.addInitScript(() => {
    const show = (value: unknown): unknown => {
      if (value instanceof ArrayBuffer || ArrayBuffer.isView(value)) {
        const view = value instanceof ArrayBuffer ? new Uint8Array(value) : new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
        return { bytes: Array.from(view, (byte) => byte.toString(16).padStart(2, '0')).join('') };
      }
      if (Array.isArray(value)) return value.map(show);
      if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, show(item)]));
      return value;
    };
    const calls: unknown[] = [];
    Object.defineProperty(window, 'recordedCeremonies', { value: calls });
    const container = navigator.credentials;
    for (const name of ['create', 'get'] as const) {
      const original = container[name].bind(container);
      Object.defineProperty(container, name, {
        value: (options: CredentialCreationOptions & CredentialRequestOptions) => {
          calls.push({ name, publicKey: show(options.publicKey) });
          return original(options);
        },
      });
    }
  });
}

const ceremonies = (page: Page) => page.evaluate(() => (window as unknown as { recordedCeremonies: Ceremony[] }).recordedCeremonies);

// What the page sent to `path` when `act` ran, once the server has answered it.
async function sentBody(page: Page, path: string, act: () => Promise<void>) {
  const [request] = await Promise.all([page.waitForRequest((sent) => new URL(sent.url()).pathname === path), act()]);
  expect((await request.response())?.status(), path).toBe(200);
  return request.postDataJSON();
}

const bytesOf = (base64url: string) => Buffer.from(base64url, 'base64url');
const advanced = (page: Page) => page.getByRole('tabpanel', { name: 'Advanced Authentication' });
const registrationForm = (page: Page) => page.locator('#advanced-ceremony-panel-registration');
const authenticationForm = (page: Page) => page.locator('#advanced-ceremony-panel-authentication');

const PRF_INPUT = 'a1'.repeat(32);
const BLOB = 'b2'.repeat(32);

test.describe('the browser\'s own WebAuthn JSON', () => {
  test('runs the Simple tab\'s registration and authentication', async ({ page }) => {
    await addVirtualAuthenticator(page);
    await recordCeremonies(page);
    await page.goto('/#simple');
    const simple = page.getByRole('tabpanel', { name: 'Simple Authentication' });
    await simple.getByRole('textbox', { name: 'Username' }).fill('native-json');

    const registration = await sentBody(page, '/api/register/complete', () => simple.getByRole('button', { name: 'Register Passkey' }).click());
    await expect(page.getByText(/^Registration successful!/)).toBeVisible();
    // The browser's own JSON: the response carries its authenticator data and public key too.
    expect(Object.keys(registration.response).sort()).toEqual(
      ['attestationObject', 'authenticatorData', 'clientDataJSON', 'publicKey', 'publicKeyAlgorithm', 'transports'],
    );
    expect(registration.authenticatorAttachment).toBe('cross-platform');

    const assertion = await sentBody(page, '/api/authenticate/complete', () => simple.getByRole('button', { name: 'Authenticate', exact: true }).click());
    await expect(page.getByText('Authentication successful! You have been verified.')).toBeVisible();
    expect(assertion.credential.id).toBe(registration.id);
    // Beside the assertion, the credentials begin was sent, again: the session keeps only their digest.
    expect(assertion.credentials.map(({ credentialId }: { credentialId: string }) => credentialId)).toEqual([registration.id]);
    expect((await ceremonies(page)).map(({ name }) => name)).toEqual(['create', 'get']);
  });

  test('gives the authenticator the Advanced tab\'s hints, prf and largeBlob, and the server every output in base64url', async ({ page }) => {
    await addVirtualAuthenticator(page, { ctap2Version: 'ctap2_1', hasLargeBlob: true, hasPrf: true });
    await recordCeremonies(page);
    await page.goto('/#advanced');
    const form = registrationForm(page);
    await form.getByRole('button', { name: 'Security-key', exact: true }).click();
    await form.getByLabel('Resident Key', { exact: true }).selectOption('required');
    await form.getByLabel('largeBlob', { exact: true }).selectOption('required');
    await form.getByRole('switch', { name: 'prf' }).click();
    await form.getByLabel('prf eval first (hex)', { exact: true }).fill(PRF_INPUT);

    const registered = await sentBody(page, '/api/advanced/register/complete', () => advanced(page).getByRole('button', { name: 'Create Credential' }).click());
    await expect(page.getByText(/^Advanced registration successful!/)).toBeVisible();
    const [created] = await ceremonies(page);
    expect(created.name).toBe('create');
    expect(created.publicKey.hints).toEqual(['security-key']);
    expect(created.publicKey.extensions).toMatchObject({ largeBlob: { support: 'required' }, prf: { eval: { first: { bytes: PRF_INPUT } } } });
    const outputs = registered.__credential_response.clientExtensionResults;
    expect(outputs.largeBlob).toEqual({ supported: true });
    expect(outputs.prf.enabled).toBe(true);
    await page.getByRole('dialog').getByRole('button', { name: 'Close credential details' }).click();

    // A write, then a read, of the credential's large blob, with a PRF evaluation.
    const credentialIdHex = bytesOf(registered.__credential_response.rawId).toString('hex');
    await advanced(page).getByRole('tab', { name: 'Authentication' }).click();
    const auth = authenticationForm(page);
    await auth.getByLabel('Allow Credentials', { exact: true }).selectOption(credentialIdHex);
    await auth.getByLabel('largeBlob', { exact: true }).selectOption('write');
    await auth.getByLabel('largeBlob write (hex)', { exact: true }).fill(BLOB);
    await auth.getByLabel('prf eval first (hex)', { exact: true }).fill(PRF_INPUT);
    const written = await sentBody(page, '/api/advanced/authenticate/complete', () => advanced(page).getByRole('button', { name: 'Assert Credential' }).click());
    await expect(page.getByText('Advanced authentication successful!')).toBeVisible();
    const [, asked] = await ceremonies(page);
    expect(asked.publicKey.extensions).toMatchObject({ largeBlob: { write: { bytes: BLOB } }, prf: { eval: { first: { bytes: PRF_INPUT } } } });
    const writeOutputs = written.__assertion_response.clientExtensionResults;
    expect(writeOutputs.largeBlob).toEqual({ written: true });
    expect(bytesOf(writeOutputs.prf.results.first)).toHaveLength(32);

    await auth.getByLabel('largeBlob', { exact: true }).selectOption('read');
    // The first authentication's toast may still be up: the server's answer says this one passed.
    const read = await sentBody(page, '/api/advanced/authenticate/complete', () => advanced(page).getByRole('button', { name: 'Assert Credential' }).click());
    expect(bytesOf(read.__assertion_response.clientExtensionResults.largeBlob.blob).toString('hex')).toBe(BLOB);
  });

  test('asks a browser without the methods to update, and runs no ceremony', async ({ page }) => {
    await page.addInitScript(() => {
      const credentialClass = window.PublicKeyCredential as unknown as Record<string, unknown> & { prototype: Record<string, unknown> };
      delete credentialClass.parseCreationOptionsFromJSON;
      delete credentialClass.parseRequestOptionsFromJSON;
      delete credentialClass.prototype.toJSON;
    });
    const ceremonyRequests: string[] = [];
    page.on('request', (request) => {
      const path = new URL(request.url()).pathname;
      if (/^\/api\/(register|authenticate|advanced\/(register|authenticate))\//.test(path)) ceremonyRequests.push(path);
    });

    await page.goto('/#simple');
    const simple = page.getByRole('tabpanel', { name: 'Simple Authentication' });
    await expect(simple.getByText(/This browser cannot run WebAuthn ceremonies here/)).toBeVisible();
    await expect(simple.getByRole('button', { name: 'Register Passkey' })).toBeDisabled();
    await expect(simple.getByRole('button', { name: 'Authenticate', exact: true })).toBeDisabled();

    await page.goto('/#advanced');
    await expect(advanced(page).getByText(/This browser cannot run WebAuthn ceremonies here/)).toBeVisible();
    await expect(advanced(page).getByRole('button', { name: 'Create Credential' })).toBeDisabled();
    await advanced(page).getByRole('tab', { name: 'Authentication' }).click();
    await expect(advanced(page).getByRole('button', { name: 'Assert Credential' })).toBeDisabled();
    expect(ceremonyRequests).toEqual([]);
  });
});
