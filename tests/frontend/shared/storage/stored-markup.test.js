import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../../../frontend/static/scripts/shared/storage/artifacts-client.js', () => ({
  fetchCredentialArtifactsBulk: vi.fn(),
  updateCredentialSnapshot: vi.fn(),
  uploadCredentialArtifact: vi.fn(),
}));

const SHARED_STORAGE_KEY = 'postquantum-webauthn.credentials';
const MARKUP = '<section><img src=x onerror="window.__xss=1"></section>';

// A record saved by an earlier version: registration detail stored as composed
// HTML, in the snapshot and under the raw registrationDetailHtml-style keys.
function savedRecord() {
  return {
    type: 'advanced',
    credentialId: 'AQID',
    storageId: 'AQID::storage',
    userName: 'alice',
    registrationDetailHtml: MARKUP,
    registration_detail_combined_html: MARKUP,
    registrationDetailSnapshot: {
      schemaVersion: 1,
      html: MARKUP,
      attestationSectionHtml: MARKUP,
      combinedHtml: MARKUP,
      state: { authenticatorDataHex: '0a0b' },
    },
  };
}

async function loadStorage() {
  vi.resetModules();
  // As index.html does: no boot records, so the module reads localStorage.
  window.__INITIAL_CREDENTIAL_RECORDS__ = null;
  return import('../../../../frontend/static/scripts/shared/storage/local.js');
}

describe('registration markup saved by an earlier version', () => {
  beforeEach(() => {
    window.localStorage.clear();
  });

  it('is read back as it was saved', async () => {
    localStorage.setItem(SHARED_STORAGE_KEY, JSON.stringify([savedRecord()]));

    const storage = await loadStorage();
    const [record] = storage.getAllAdvancedCredentials();

    expect(record.registrationDetailHtml).toBe(MARKUP);
    expect(record.registration_detail_combined_html).toBe(MARKUP);
    expect(record.registrationDetailSnapshot.html).toBe(MARKUP);
    expect(record.registrationDetailSnapshot.state).toEqual({ authenticatorDataHex: '0a0b' });
  });
});
