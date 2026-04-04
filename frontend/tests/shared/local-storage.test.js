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
    fetchCredentialArtifactsBulk.mockReset();
    updateCredentialSnapshot.mockReset();
    uploadCredentialArtifact.mockReset();
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

  it('migrates legacy storage keys into unified records and removes legacy keys', async () => {
    window.__INITIAL_CREDENTIAL_RECORDS__ = null;

    localStorage.setItem('postquantum-webauthn.simpleCredentials', JSON.stringify([
      {
        credentialId: 'simple-legacy',
        email: 'legacy@example.com',
        publicKey: 'cHVibGlj',
        signCount: 1,
      },
    ]));
    localStorage.setItem('postquantum-webauthn.advancedCredentials', JSON.stringify([
      {
        type: 'advanced',
        credentialId: 'advanced-legacy',
        storageId: 'advanced-legacy::storage',
        publicKey: 'cHVibGlj',
        signCount: 2,
      },
    ]));

    const storage = await loadLocalStorageModule();

    const ordered = storage.getAllStoredCredentialsInOrder();
    expect(ordered).toHaveLength(2);
    expect(ordered.find((record) => record.type === 'simple')?.credentialId).toBe('simple-legacy');
    expect(ordered.find((record) => record.type === 'advanced')?.credentialId).toBe('advanced-legacy');

    expect(localStorage.getItem('postquantum-webauthn.simpleCredentials')).toBeNull();
    expect(localStorage.getItem('postquantum-webauthn.advancedCredentials')).toBeNull();

    const unified = JSON.parse(localStorage.getItem(SHARED_STORAGE_KEY));
    expect(unified).toHaveLength(2);
  });

  it('updates advanced records when saving matching simple credentials', async () => {
    window.__INITIAL_CREDENTIAL_RECORDS__ = null;

    localStorage.setItem(SHARED_STORAGE_KEY, JSON.stringify([
      {
        type: 'advanced',
        credentialId: 'shared-id',
        storageId: 'shared-id::storage',
        publicKey: 'cHVibGlj',
        signCount: 3,
      },
    ]));

    const storage = await loadLocalStorageModule();
    const saved = storage.saveSimpleCredential({
      credentialId: 'shared-id',
      email: 'merged@example.com',
      userName: 'merged@example.com',
      publicKey: 'cHVibGlj',
      signCount: 9,
    });

    expect(saved).not.toBeNull();
    expect(storage.getAllSimpleCredentials()).toHaveLength(0);
    expect(storage.getAllAdvancedCredentials()).toHaveLength(1);
    expect(storage.getAllAdvancedCredentials()[0].email).toBe('merged@example.com');
    expect(storage.getAllAdvancedCredentials()[0].signCount).toBe(9);
  });

  it('applies strict email matching for simple updates/removal and handles explicit sign counts', async () => {
    const storage = await loadLocalStorageModule();

    storage.saveSimpleCredential({
      credentialId: 'simple-email-1',
      email: 'owner@example.com',
      publicKey: 'cHVibGlj',
      signCount: 4,
    });

    expect(storage.updateSimpleCredentialSignCount('other@example.com', 'simple-email-1')).toBe(false);
    expect(storage.getAllSimpleCredentials()[0].signCount).toBe(4);

    expect(storage.updateSimpleCredentialSignCount('owner@example.com', 'simple-email-1', 11)).toBe(true);
    expect(storage.getAllSimpleCredentials()[0].signCount).toBe(11);

    expect(storage.removeSimpleCredential('simple-email-1', 'wrong@example.com')).toBe(false);
    expect(storage.removeSimpleCredential('simple-email-1', 'owner@example.com')).toBe(true);
    expect(storage.getAllSimpleCredentials()).toHaveLength(0);
  });

  it('merges simple credential data into advanced saves and updates/removes by storageId', async () => {
    const storage = await loadLocalStorageModule();

    storage.saveSimpleCredential({
      credentialId: 'advanced-merge',
      email: 'advanced-merge@example.com',
      publicKey: 'cHVibGlj',
      signCount: 6,
    });

    const savedAdvanced = storage.saveAdvancedCredential({
      credentialId: 'advanced-merge',
      publicKey: 'cHVibGlj',
      authenticatorAttachment: 'cross-platform',
    });

    expect(savedAdvanced).not.toBeNull();
    expect(savedAdvanced.storageId).toContain('advanced-merge');
    expect(storage.getAllSimpleCredentials()).toHaveLength(0);

    const advanced = storage.getAllAdvancedCredentials();
    expect(advanced).toHaveLength(1);
    expect(advanced[0].email).toBe('advanced-merge@example.com');
    expect(advanced[0].signCount).toBe(6);

    expect(storage.updateAdvancedCredentialSignCount('', 19, savedAdvanced.storageId)).toBe(true);
    expect(storage.getAllAdvancedCredentials()[0].signCount).toBe(19);

    expect(storage.removeAdvancedCredential('', savedAdvanced.storageId)).toBe(true);
    expect(storage.getAllAdvancedCredentials()).toHaveLength(0);
  });

  it('prefetches snapshots only for missing advanced records with server artifacts', async () => {
    window.__INITIAL_CREDENTIAL_RECORDS__ = null;

    localStorage.setItem(SHARED_STORAGE_KEY, JSON.stringify([
      {
        type: 'advanced',
        credentialId: 'needs-snapshot',
        storageId: 'needs-snapshot::storage',
        hasServerArtifact: true,
      },
      {
        type: 'advanced',
        credentialId: 'already-snapshotted',
        storageId: 'already-snapshotted::storage',
        hasServerArtifact: true,
        registrationDetailSnapshot: { html: '<p>exists</p>' },
      },
      {
        type: 'advanced',
        credentialId: 'no-artifact',
        storageId: 'no-artifact::storage',
        hasServerArtifact: false,
      },
    ]));

    fetchCredentialArtifactsBulk.mockResolvedValue({
      'needs-snapshot::storage': {
        registrationDetailSnapshot: {
          schemaVersion: 1,
          html: '<p>prefetched</p>',
          state: {
            authenticatorDataHex: 'aa'.repeat(10),
          },
        },
      },
    });

    const storage = await loadLocalStorageModule();
    const changed = await storage.ensureAdvancedCredentialSnapshotsPrefetched();

    expect(changed).toBe(true);
    expect(fetchCredentialArtifactsBulk).toHaveBeenCalledWith(['needs-snapshot::storage']);

    const records = JSON.parse(localStorage.getItem(SHARED_STORAGE_KEY));
    const updated = records.find((record) => record.storageId === 'needs-snapshot::storage');
    expect(updated.registrationDetailSnapshot.html).toBe('<p>prefetched</p>');
  });

  it('sanitizes registration snapshots and returns upload result when local record is unchanged', async () => {
    localStorage.setItem(SHARED_STORAGE_KEY, JSON.stringify([
      {
        type: 'advanced',
        credentialId: 'different-record',
        storageId: 'different-record::storage',
        hasServerArtifact: true,
      },
    ]));

    updateCredentialSnapshot.mockResolvedValue(true);

    const storage = await loadLocalStorageModule();
    const result = await storage.updateAdvancedCredentialRegistrationSnapshot('missing::storage', {
      schemaVersion: 1,
      html: `<section>${'x'.repeat(130000)}</section>`,
      combinedHtml: '<section>combined</section>',
      state: {
        attestationObject: {
          fmt: 'packed',
          attStmt: {
            x5c: [{ parsedX5c: { subject: 'CN=Subject', der: 'raw-value' } }],
          },
        },
        attestationCertificates: [
          {
            parsedX5c: {
              subject: 'CN=Example',
              derBase64: 'AAAA',
            },
          },
        ],
        authenticatorDataHex: 'ab'.repeat(5000),
        authenticatorDataHash: 'cd'.repeat(1000),
      },
    });

    expect(result).toBe(true);
    expect(updateCredentialSnapshot).toHaveBeenCalledWith(
      'missing::storage',
      expect.objectContaining({
        schemaVersion: 1,
        html: expect.any(String),
        state: expect.any(Object),
      }),
    );

    const uploadedSnapshot = updateCredentialSnapshot.mock.calls[0][1];
    expect(uploadedSnapshot.html.length).toBeLessThanOrEqual(120000);
    expect(uploadedSnapshot.state.authenticatorDataHex.length).toBeLessThanOrEqual(8192);
    expect(uploadedSnapshot.state.authenticatorDataHash.length).toBeLessThanOrEqual(1024);
    expect(uploadedSnapshot.state.attestationCertificates[0].parsedX5c.derBase64).toBeUndefined();
  });

  it('prepares server payloads with dedupe, filtering, and best sign count', async () => {
    const storage = await loadLocalStorageModule();

    storage.saveSimpleCredential({
      credentialId: 'simple-ready',
      email: 'simple@example.com',
      publicKey: 'cHVibGlj',
      signCount: 1,
      algorithm: -7,
    });

    storage.saveAdvancedCredential({
      credentialId: 'advanced-ready',
      publicKey: 'cHVibGlj',
      signCount: 2,
      aaguidHex: '00112233445566778899aabbccddeeff',
      authenticatorAttachment: 'platform',
      residentKey: true,
      algorithm: -257,
    });

    storage.saveAdvancedCredential({
      credentialId: 'advanced-ready',
      publicKey: 'cHVibGlj',
      signCount: 9,
      authenticatorAttachment: 'cross-platform',
      resident: false,
      algorithm: -257,
    });

    const simpleServerPayload = storage.prepareCredentialsForServer([
      ...storage.getAllSimpleCredentials(),
      { credentialId: '', publicKey: '' },
    ]);
    expect(simpleServerPayload).toEqual([
      {
        credentialId: 'simple-ready',
        aaguid: null,
        publicKey: 'cHVibGlj',
        signCount: 1,
        algorithm: -7,
      },
    ]);

    const advancedServerPayload = storage.prepareAdvancedCredentialsForServer([
      {
        credentialId: 'advanced-ready',
        publicKey: 'cHVibGlj',
        signCount: 4,
        authenticatorAttachment: 'platform',
        residentKey: true,
      },
      {
        credentialId: 'advanced-ready',
        publicKey: 'cHVibGlj',
        signCount: 10,
        authenticatorAttachment: 'cross-platform',
        resident: false,
      },
      {
        credentialId: 'missing-key',
      },
    ]);

    expect(advancedServerPayload).toEqual([
      {
        credentialId: 'advanced-ready',
        publicKey: 'cHVibGlj',
        aaguid: null,
        signCount: 10,
        algorithm: undefined,
        authenticatorAttachment: 'cross-platform',
        resident: false,
      },
    ]);
  });
});
