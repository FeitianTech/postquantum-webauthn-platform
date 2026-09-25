import { beforeEach, describe, expect, it, vi } from 'vitest';

import { ADVANCED_RECORD, SIMPLE_RECORD } from './pre-phase-23-records.js';

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

describe('credential records saved before base64url', () => {
  beforeEach(() => {
    window.localStorage.clear();
  });

  it('are read back as they were saved', async () => {
    const storage = await loadStorage([SIMPLE_RECORD, ADVANCED_RECORD]);

    const [simple] = storage.getAllSimpleCredentials();
    const [advanced] = storage.getAllAdvancedCredentials();
    expect(simple.credentialId).toBe(SIMPLE_RECORD.credentialId);
    expect(simple.publicKey).toBe(SIMPLE_RECORD.publicKey);
    expect(simple.publicKeyCose).toEqual(SIMPLE_RECORD.publicKeyCose);
    expect(simple.attestationStatement).toEqual(SIMPLE_RECORD.attestationStatement);
    expect(advanced.publicKey).toBe(ADVANCED_RECORD.publicKey);
    expect(advanced.userHandle).toBe(ADVANCED_RECORD.userHandle);
  });

  it('a simple record saved without credentialIdBase64Url is not found by the ID the server reports', async () => {
    const legacy = { ...SIMPLE_RECORD };
    delete legacy.credentialIdBase64Url;
    const storage = await loadStorage([legacy]);

    const updated = storage.updateSimpleCredentialSignCount(
      'user@example.com',
      SIMPLE_RECORD.credentialIdBase64Url,
      5,
    );

    expect(updated).toBe(false);
    expect(storage.getAllSimpleCredentials()[0].signCount).toBe(0);
  });
});
