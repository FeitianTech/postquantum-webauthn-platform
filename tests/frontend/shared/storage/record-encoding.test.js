import { beforeEach, describe, expect, it, vi } from 'vitest';

import { ADVANCED_RECORD, SIMPLE_RECORD } from './pre-phase-23-records.js';
import { base64ToBytes, base64UrlToBytes } from '../../../../frontend/static/scripts/shared/utils/base64.js';
import {
  getCredentialIdHex,
  getCredentialUserHandleHex,
} from '../../../../frontend/static/scripts/advanced/credentials/utils.js';

vi.mock('../../../../frontend/static/scripts/shared/storage/artifacts-client.js', () => ({
  fetchCredentialArtifactsBulk: vi.fn(),
  updateCredentialSnapshot: vi.fn(),
  uploadCredentialArtifact: vi.fn(),
}));

const SHARED_STORAGE_KEY = 'postquantum-webauthn.credentials';

async function loadStorage(records) {
  localStorage.setItem(SHARED_STORAGE_KEY, JSON.stringify(records));
  vi.resetModules();
  // As index.html does: no boot records, so the module reads localStorage.
  window.__INITIAL_CREDENTIAL_RECORDS__ = null;
  return import('../../../../frontend/static/scripts/shared/storage/local.js');
}

function bytesOf(value) {
  return Array.from(value.includes('-') || value.includes('_') || !/[+/=]/.test(value)
    ? base64UrlToBytes(value)
    : base64ToBytes(value));
}

describe('credential records saved before base64url', () => {
  beforeEach(() => {
    window.localStorage.clear();
  });

  it('are read back in base64url, holding the same bytes', async () => {
    const storage = await loadStorage([SIMPLE_RECORD, ADVANCED_RECORD]);

    const [simple] = storage.getAllSimpleCredentials();
    const [advanced] = storage.getAllAdvancedCredentials();

    expect(simple.credentialId).toBe(SIMPLE_RECORD.credentialIdBase64Url);
    expect(simple.publicKey).toBe(SIMPLE_RECORD.publicKeyBase64Url);
    expect(simple.publicKeyBytes).toBe(SIMPLE_RECORD.publicKeyBase64Url);
    expect(advanced.publicKey).toBe(ADVANCED_RECORD.publicKeyBase64Url);
    expect(advanced.userHandle).toBe(ADVANCED_RECORD.userHandleBase64Url);

    const pairs = [
      [SIMPLE_RECORD.publicKeyCose['-2'], simple.publicKeyCose['-2']],
      [SIMPLE_RECORD.publicKeyCose['-3'], simple.publicKeyCose['-3']],
      [SIMPLE_RECORD.attestationStatement.sig, simple.attestationStatement.sig],
      [SIMPLE_RECORD.attestationStatement.x5c[0], simple.attestationStatement.x5c[0]],
      [ADVANCED_RECORD.publicKeyCose['-2'], advanced.publicKeyCose['-2']],
    ];
    for (const [saved, read] of pairs) {
      expect(read).toMatch(/^[A-Za-z0-9_-]+$/);
      expect(bytesOf(read)).toEqual(bytesOf(saved));
    }
  });

  it('keep fields named for base64, extension outputs and text as they were', async () => {
    const statement = { ...SIMPLE_RECORD.attestationStatement, ver: '2.0' };
    const storage = await loadStorage([
      { ...SIMPLE_RECORD, attestationStatement: statement },
      ADVANCED_RECORD,
    ]);

    const [simple] = storage.getAllSimpleCredentials();
    const [advanced] = storage.getAllAdvancedCredentials();
    expect(simple.attestationStatement.ver).toBe('2.0');
    expect(simple.attestationStatement.alg).toBe(-7);
    expect(simple.publicKeyCose['-1']).toBe(1);
    expect(simple.clientExtensionOutputs).toEqual(SIMPLE_RECORD.clientExtensionOutputs);
    expect(advanced.publicKeyBase64).toBe(ADVANCED_RECORD.publicKeyBase64);
    expect(advanced.userHandleBase64).toBe(ADVANCED_RECORD.userHandleBase64);
    expect(advanced.credentialIdHex).toBe(ADVANCED_RECORD.credentialIdHex);
  });

  it('are saved once in the new spelling, and read again without another save', async () => {
    const storage = await loadStorage([SIMPLE_RECORD]);
    const setItem = vi.spyOn(window.localStorage, 'setItem');

    storage.getAllSimpleCredentials();
    const [saved] = JSON.parse(localStorage.getItem(SHARED_STORAGE_KEY));
    expect(saved.publicKey).toBe(SIMPLE_RECORD.publicKeyBase64Url);

    vi.resetModules();
    const again = await import('../../../../frontend/static/scripts/shared/storage/local.js');
    setItem.mockClear();
    again.getAllSimpleCredentials();
    expect(setItem).not.toHaveBeenCalled();
    setItem.mockRestore();
  });

  it('a simple record saved without credentialIdBase64Url is found by the ID the server reports', async () => {
    const legacy = { ...SIMPLE_RECORD };
    delete legacy.credentialIdBase64Url;
    const storage = await loadStorage([legacy]);

    const updated = storage.updateSimpleCredentialSignCount(
      'user@example.com',
      SIMPLE_RECORD.credentialIdBase64Url,
      5,
    );

    expect(updated).toBe(true);
    expect(storage.getAllSimpleCredentials()[0].signCount).toBe(5);
  });

  it('still name the same credential and user handle', async () => {
    const storage = await loadStorage([SIMPLE_RECORD, ADVANCED_RECORD]);

    const [simple] = storage.getAllSimpleCredentials();
    const [advanced] = storage.getAllAdvancedCredentials();
    expect(getCredentialIdHex({ credentialId: simple.credentialId })).toBe(SIMPLE_RECORD.credentialIdHex);
    expect(getCredentialIdHex({ credentialId: advanced.credentialId })).toBe(ADVANCED_RECORD.credentialIdHex);
    expect(getCredentialUserHandleHex({ userHandle: advanced.userHandle })).toBe(ADVANCED_RECORD.userHandleHex);
  });
});
