import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import {
  updateAdvancedCredentialRegistrationSnapshot,
} from '../../../../frontend/static/scripts/shared/storage/local/advanced-snapshot-update.js';
import {
  seedUnifiedCredentialRecords,
} from '../../../../frontend/static/scripts/shared/storage/local/storage-core.js';

const SHARED_STORAGE_KEY = 'postquantum-webauthn.credentials';
const STORAGE_ID = 'THBi3GyG-MexchMynbz3x5Nv::1a0c4506c00::abb1b052d88044e486bb1446aa6a1e87';
const OTHER_STORAGE_ID = 'dGVzdC1vdGhlcg::1a0c4506d11::0f6e4d1c2b3a49588776655443322110';

const SNAPSHOT = {
  schemaVersion: 2,
  capturedAt: '2026-09-27T10:00:00Z',
  state: { authenticatorDataHash: '35e7921c9a11ca76baebcda053d2ac87f6372546283c31c01e13db1b2cec1dad' },
};

function store(records) {
  window.localStorage.setItem(SHARED_STORAGE_KEY, JSON.stringify(records));
}

function stored() {
  return JSON.parse(window.localStorage.getItem(SHARED_STORAGE_KEY));
}

describe('updating an advanced credential\'s registration snapshot', () => {
  beforeEach(() => {
    seedUnifiedCredentialRecords(null);
    window.localStorage.clear();
    vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({ status: 'OK' }), {
      headers: { 'Content-Type': 'application/json' },
    })));
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('leaves a simple credential as it was', async () => {
    const simple = { type: 'simple', credentialId: 'c2ltcGxlLWNyZWQ', email: 'user@example.com' };
    store([simple, { type: 'advanced', credentialId: 'YWR2YW5jZWQ', storageId: STORAGE_ID }]);

    await updateAdvancedCredentialRegistrationSnapshot(STORAGE_ID, SNAPSHOT);

    expect(stored()[0]).toEqual(simple);
  });

  it('finds an advanced credential by its local storage id when it has no storage id', async () => {
    store([{ type: 'advanced', credentialId: 'YWR2YW5jZWQ', localStorageId: STORAGE_ID }]);

    await expect(updateAdvancedCredentialRegistrationSnapshot(STORAGE_ID, SNAPSHOT)).resolves.toBe(true);

    expect(stored()[0].registrationDetailSnapshot).toEqual(SNAPSHOT);
  });

  it('leaves an advanced credential with another storage id as it was', async () => {
    store([
      { type: 'advanced', credentialId: 'b3RoZXI', storageId: OTHER_STORAGE_ID },
      { type: 'advanced', credentialId: 'YWR2YW5jZWQ', storageId: STORAGE_ID },
    ]);

    await updateAdvancedCredentialRegistrationSnapshot(STORAGE_ID, SNAPSHOT);

    expect(stored()[0].registrationDetailSnapshot).toBeUndefined();
    expect(stored()[1].registrationDetailSnapshot).toEqual(SNAPSHOT);
  });

  it('leaves an advanced credential with no storage id as it was', async () => {
    store([
      { type: 'advanced', credentialId: 'bm8tc3RvcmFnZS1pZA' },
      { type: 'advanced', credentialId: 'YWR2YW5jZWQ', storageId: STORAGE_ID },
    ]);

    await updateAdvancedCredentialRegistrationSnapshot(STORAGE_ID, SNAPSHOT);

    expect(stored()[0]).toEqual({ type: 'advanced', credentialId: 'bm8tc3RvcmFnZS1pZA' });
  });
});
