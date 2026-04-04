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

describe('local-storage edge cases', () => {
  beforeEach(() => {
    window.localStorage.clear();
    window.__INITIAL_CREDENTIAL_RECORDS__ = [];
    fetchCredentialArtifactsBulk.mockReset();
    updateCredentialSnapshot.mockReset();
    uploadCredentialArtifact.mockReset();
  });

  it('retries artifact synchronization after transient upload failures', async () => {
    localStorage.setItem(SHARED_STORAGE_KEY, JSON.stringify([
      {
        type: 'advanced',
        credentialId: 'retry-artifact',
        storageId: 'retry-artifact::storage',
        publicKey: 'cHVibGlj',
        attestationObject: 'heavy-data',
        hasServerArtifact: false,
      },
    ]));

    uploadCredentialArtifact.mockRejectedValueOnce(new Error('upload failed'));

    const storage = await loadLocalStorageModule();
    expect(await storage.ensureAdvancedCredentialArtifactsSynced()).toBe(false);

    uploadCredentialArtifact.mockResolvedValueOnce(true);
    expect(await storage.ensureAdvancedCredentialArtifactsSynced()).toBe(true);

    const records = JSON.parse(localStorage.getItem(SHARED_STORAGE_KEY));
    expect(records[0].hasServerArtifact).toBe(true);
  });

  it('prefetches snapshots from storedCredential fallback and sanitizes nested fields', async () => {
    window.__INITIAL_CREDENTIAL_RECORDS__ = null;

    localStorage.setItem(SHARED_STORAGE_KEY, JSON.stringify([
      {
        type: 'advanced',
        credentialId: 'snapshot-fallback',
        storageId: 'snapshot-fallback::storage',
        hasServerArtifact: true,
      },
    ]));

    fetchCredentialArtifactsBulk.mockResolvedValue({
      'snapshot-fallback::storage': {
        storedCredential: {
          registrationDetailSnapshot: {
            combinedHtml: '<section>combined-fallback</section>',
            stateSnapshot: {
              visibleAttestationCertificateIndices: ['1', 'NaN', null],
              attestationCertificates: [
                {
                  parsedX5c: {
                    subject: 'CN=Snapshot',
                    extensions: [{ oid: '1.2.3.4', raw: 'drop', derBase64: 'drop' }],
                  },
                },
              ],
              authenticatorData: {
                rawBuffer: 'drop-buffer',
                value: 'keep-value',
              },
            },
          },
        },
      },
    });

    const storage = await loadLocalStorageModule();
    const changed = await storage.ensureAdvancedCredentialSnapshotsPrefetched();

    expect(changed).toBe(true);
    const records = JSON.parse(localStorage.getItem(SHARED_STORAGE_KEY));
    const snapshot = records[0].registrationDetailSnapshot;

    expect(snapshot.html).toBe('<section>combined-fallback</section>');
    expect(snapshot.state.visibleAttestationCertificateIndices).toEqual([1]);
    expect(snapshot.state.attestationCertificates[0].parsedX5c.extensions[0].raw).toBeUndefined();
    expect(snapshot.state.authenticatorData.rawBuffer).toBeUndefined();
    expect(snapshot.state.authenticatorData.value).toBe('keep-value');
  });

  it('rejects invalid snapshot updates and reports false when nothing is removed', async () => {
    const storage = await loadLocalStorageModule();

    updateCredentialSnapshot.mockResolvedValue(false);

    await expect(storage.updateAdvancedCredentialRegistrationSnapshot('', { html: '<p>x</p>' })).resolves.toBe(false);
    await expect(storage.updateAdvancedCredentialRegistrationSnapshot('missing::storage', null)).resolves.toBe(false);
    await expect(storage.updateAdvancedCredentialRegistrationSnapshot('missing::storage', { html: 'x' })).resolves.toBe(false);

    expect(storage.removeAdvancedCredential('', null)).toBe(false);
    expect(updateCredentialSnapshot).toHaveBeenCalledTimes(1);
  });

  it('builds advanced server payloads from COSE maps and keeps highest signCount variant', async () => {
    const storage = await loadLocalStorageModule();

    const payload = storage.prepareAdvancedCredentialsForServer([
      {
        credentialId: 'cose-derived',
        publicKeyCose: { 1: 2, 3: -8 },
        signCount: 3,
        relyingParty: { residentKey: true },
      },
      {
        credentialId: 'cose-derived',
        publicKeyCose: { 1: 2, 3: -8 },
        signCount: 9,
        authenticatorAttachment: 'platform',
      },
    ]);

    expect(payload).toHaveLength(1);
    expect(payload[0]).toEqual(
      expect.objectContaining({
        credentialId: 'cose-derived',
        signCount: 9,
        algorithm: -8,
        authenticatorAttachment: 'platform',
      }),
    );
    expect(payload[0].publicKey).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(payload[0].resident).toBe(false);
  });

  it('filters boot records and clears simple/advanced partitions independently', async () => {
    window.__INITIAL_CREDENTIAL_RECORDS__ = [
      null,
      'not-an-object',
      {
        type: 'simple',
        credentialId: 'boot-simple',
        email: 'boot@example.com',
        publicKey: 'cHVibGlj',
      },
      {
        type: 'advanced',
        credentialId: 'boot-advanced',
        storageId: 'boot-advanced::storage',
        publicKey: 'cHVibGlj',
      },
    ];

    const storage = await loadLocalStorageModule();
    const ordered = storage.getAllStoredCredentialsInOrder();
    expect(ordered).toHaveLength(2);

    storage.clearSimpleCredentials();
    expect(storage.getAllSimpleCredentials()).toHaveLength(0);
    expect(storage.getAllAdvancedCredentials()).toHaveLength(1);

    storage.clearAdvancedCredentials();
    expect(storage.getAllAdvancedCredentials()).toHaveLength(0);
  });

  it('updates sign counts across partitions and handles snapshot prefetch failures', async () => {
    const storage = await loadLocalStorageModule();

    const savedAdvanced = storage.saveAdvancedCredential({
      credentialId: 'shared-counter',
      publicKey: 'cHVibGlj',
      storageId: 'shared-counter::storage',
    });
    expect(savedAdvanced).not.toBeNull();

    expect(storage.updateSimpleCredentialSignCount('', 'shared-counter')).toBe(true);
    expect(storage.getAllAdvancedCredentials()[0].signCount).toBe(1);

    storage.saveSimpleCredential({
      credentialId: 'simple-counter',
      email: 'simple@example.com',
      publicKey: 'cHVibGlj',
      signCount: 2,
    });

    expect(storage.updateAdvancedCredentialSignCount('simple-counter')).toBe(true);
    expect(storage.getAllSimpleCredentials()[0].signCount).toBe(3);

    fetchCredentialArtifactsBulk.mockRejectedValueOnce(new Error('prefetch failed'));
    await expect(storage.ensureAdvancedCredentialSnapshotsPrefetched()).resolves.toBe(false);
  });

  it('summarizes heavy advanced fields before persisting synced artifacts', async () => {
    localStorage.setItem(SHARED_STORAGE_KEY, JSON.stringify([
      {
        type: 'advanced',
        credentialId: 'summary-target',
        storageId: 'summary-target::storage',
        publicKey: 'cHVibGlj',
        hasServerArtifact: false,
        attestationObject: 'heavy-object',
        properties: {
          registrationData: { authenticatorData: 'aa' },
          customFlag: true,
        },
        relyingParty: {
          attestationObject: 'heavy-rp-object',
          displayName: 'RP Display',
        },
      },
    ]));

    uploadCredentialArtifact.mockResolvedValueOnce(true);

    const storage = await loadLocalStorageModule();
    const changed = await storage.ensureAdvancedCredentialArtifactsSynced();

    expect(changed).toBe(true);

    const records = JSON.parse(localStorage.getItem(SHARED_STORAGE_KEY));
    const stored = records[0];
    expect(stored.hasServerArtifact).toBe(true);
    expect(stored.attestationObject).toBeUndefined();
    expect(stored.properties.customFlag).toBe(true);
    expect(stored.properties.registrationData).toBeUndefined();
    expect(stored.relyingParty.displayName).toBe('RP Display');
  });
});
