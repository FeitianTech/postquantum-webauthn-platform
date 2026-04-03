import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../static/scripts/shared/credential-artifacts-client.js', () => ({
  fetchCredentialArtifactsBulk: vi.fn(),
  updateCredentialSnapshot: vi.fn(),
  uploadCredentialArtifact: vi.fn(),
}));

import {
  fetchCredentialArtifactsBulk,
  updateCredentialSnapshot,
  uploadCredentialArtifact,
} from '../../static/scripts/shared/credential-artifacts-client.js';

async function loadLocalStorageModule() {
  vi.resetModules();
  return import('../../static/scripts/shared/local-storage.js');
}

const SHARED_STORAGE_KEY = 'postquantum-webauthn.credentials';

describe('local-storage module', () => {
  beforeEach(() => {
    window.localStorage.clear();
    window.__INITIAL_CREDENTIAL_RECORDS__ = [];
  });

  it('stores, updates, prepares, and removes simple credentials', async () => {
    const storage = await loadLocalStorageModule();

    const saved = storage.saveSimpleCredential({
      credentialId: 'cred-1',
      email: 'user@example.com',
      publicKey: 'cHVibGlj',
      signCount: 2,
      aaguid: 'aaguid-1',
    });

    expect(saved.credentialIdBase64Url).toBe('cred-1');
    expect(storage.getSimpleCredentialsForEmail('USER@example.com')).toHaveLength(1);
    expect(storage.prepareCredentialsForServer(storage.getAllSimpleCredentials())).toEqual([
      {
        credentialId: 'cred-1',
        aaguid: 'aaguid-1',
        publicKey: 'cHVibGlj',
        signCount: 2,
        algorithm: undefined,
      },
    ]);

    expect(storage.updateSimpleCredentialSignCount('user@example.com', 'cred-1')).toBe(true);
    expect(storage.getAllSimpleCredentials()[0].signCount).toBe(3);
    expect(storage.removeSimpleCredential('cred-1', 'user@example.com')).toBe(true);
    expect(storage.getAllSimpleCredentials()).toHaveLength(0);
  });

  it('stores, prepares, updates, and removes advanced credentials', async () => {
    const storage = await loadLocalStorageModule();

    storage.saveSimpleCredential({
      credentialId: 'adv-1',
      email: 'advanced@example.com',
      publicKey: 'cHVibGlj',
      signCount: 1,
    });

    const saved = storage.saveAdvancedCredential({
      credentialId: 'adv-1',
      publicKey: 'cHVibGlj',
      signCount: 4,
      authenticatorAttachment: 'platform',
      residentKey: true,
      createdAt: '2026-04-03T00:00:00Z',
    });

    expect(saved.storageId).toContain('adv-1');
    expect(storage.getAllSimpleCredentials()).toHaveLength(0);
    expect(storage.getAllAdvancedCredentials()).toHaveLength(1);

    const prepared = storage.prepareAdvancedCredentialsForServer();
    expect(prepared).toEqual([
      {
        credentialId: 'adv-1',
        publicKey: 'cHVibGlj',
        aaguid: null,
        signCount: 4,
        algorithm: undefined,
        authenticatorAttachment: 'platform',
        resident: true,
      },
    ]);

    expect(storage.updateAdvancedCredentialSignCount('adv-1', undefined, saved.storageId)).toBe(true);
    expect(storage.getAllAdvancedCredentials()[0].signCount).toBe(5);
    expect(storage.removeAdvancedCredential('adv-1', saved.storageId)).toBe(true);
    expect(storage.getAllAdvancedCredentials()).toHaveLength(0);
  });

  it('synchronizes artifacts, snapshots, and registration detail updates', async () => {
    const heavyRecord = {
      type: 'advanced',
      credentialId: 'adv-2',
      storageId: 'adv-2::storage',
      attestationObject: 'heavy-data',
      publicKey: 'cHVibGlj',
      hasServerArtifact: false,
    };
    localStorage.setItem(SHARED_STORAGE_KEY, JSON.stringify([heavyRecord]));

    uploadCredentialArtifact.mockResolvedValue(true);
    fetchCredentialArtifactsBulk.mockResolvedValue({
      'adv-2::storage': {
        registrationDetailSnapshot: {
          html: '<p>summary</p>',
        },
      },
    });
    updateCredentialSnapshot.mockResolvedValue(true);

    const storage = await loadLocalStorageModule();

    expect(await storage.ensureAdvancedCredentialArtifactsSynced()).toBe(true);

    const afterSync = JSON.parse(localStorage.getItem(SHARED_STORAGE_KEY));
    expect(afterSync[0].hasServerArtifact).toBe(true);
    expect(uploadCredentialArtifact).toHaveBeenCalled();

    expect(await storage.ensureAdvancedCredentialSnapshotsPrefetched()).toBe(true);
    const afterPrefetch = JSON.parse(localStorage.getItem(SHARED_STORAGE_KEY));
    expect(afterPrefetch[0].registrationDetailSnapshot.html).toBe('<p>summary</p>');

    expect(await storage.updateAdvancedCredentialRegistrationSnapshot('adv-2::storage', {
      html: '<p>updated</p>',
    })).toBe(true);
    expect(updateCredentialSnapshot).toHaveBeenCalledWith('adv-2::storage', {
      html: '<p>updated</p>',
    });
  });
});
