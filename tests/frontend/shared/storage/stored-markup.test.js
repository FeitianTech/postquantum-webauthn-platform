import { beforeEach, describe, expect, it, vi } from 'vitest';
import { removePageData } from '../../page-data-helper.js';

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
  removePageData('initial-credential-records');
  return import('../../../../frontend/static/scripts/shared/storage/local.js');
}

describe('registration markup saved by an earlier version', () => {
  beforeEach(() => {
    window.localStorage.clear();
  });

  it('is dropped when the record is read, and the record saved without it', async () => {
    localStorage.setItem(SHARED_STORAGE_KEY, JSON.stringify([savedRecord()]));

    const storage = await loadStorage();
    const [record] = storage.getAllAdvancedCredentials();

    expect(record.registrationDetailHtml).toBeUndefined();
    expect(record.registration_detail_combined_html).toBeUndefined();
    expect(record.registrationDetailSnapshot).toEqual({ schemaVersion: 1, state: { authenticatorDataHex: '0a0b' } });
    expect(record.userName).toBe('alice');

    const [saved] = JSON.parse(localStorage.getItem(SHARED_STORAGE_KEY));
    expect(JSON.stringify(saved)).not.toContain('<section>');
    expect(saved.registrationDetailSnapshot.state).toEqual({ authenticatorDataHex: '0a0b' });
  });

  it('takes the snapshot away when markup was all it held', async () => {
    const record = savedRecord();
    delete record.registrationDetailSnapshot.state;
    localStorage.setItem(SHARED_STORAGE_KEY, JSON.stringify([record]));

    const storage = await loadStorage();

    expect(storage.getAllAdvancedCredentials()[0].registrationDetailSnapshot).toBeUndefined();
  });

  it('leaves a record without markup as it is', async () => {
    const record = { type: 'advanced', credentialId: 'AQID', storageId: 'AQID::storage', userName: 'bob' };
    localStorage.setItem(SHARED_STORAGE_KEY, JSON.stringify([record]));
    const before = localStorage.getItem(SHARED_STORAGE_KEY);

    const storage = await loadStorage();
    storage.getAllAdvancedCredentials();

    expect(localStorage.getItem(SHARED_STORAGE_KEY)).toBe(before);
  });
});
