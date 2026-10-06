import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { ensureAdvancedCredentialArtifactsSynced, ensureAdvancedCredentialSnapshotsPrefetched } from './advanced-sync.js';
import { seedUnifiedCredentialRecords } from './storage-core.js';
import * as artifactsClient from '../artifacts-client.js';
import { saveAdvancedCredential } from './advanced-credentials.js';

const SHARED_STORAGE_KEY = 'postquantum-webauthn.credentials';
const STORAGE_ID = 'THBi3GyG-MexchMynbz3x5Nv::1a0c4506c00::abb1b052d88044e486bb1446aa6a1e87';
const PUBLIC_KEY = 'pQECAyYgASFYIDMAqV_ceu7i7Gw9sutq4PjEPKbbjqmToYzZWR03vPwCIlggivkDu6wVP_oBEKxHEVurqEqp4Q7zkRyxRmqawViw2Lg';

const SNAPSHOT = {
  schemaVersion: 2,
  capturedAt: '2026-09-27T10:00:00Z',
  state: { authenticatorDataHash: '35e7921c9a11ca76baebcda053d2ac87f6372546283c31c01e13db1b2cec1dad' },
};

function advanced(fields = {}) {
  return {
    type: 'advanced',
    credentialId: 'THBi3GyG-MexchMynbz3x5NvGe5iGSPJDYpBGvL7i9Y',
    publicKey: PUBLIC_KEY,
    ...fields,
  };
}

function jsonAnswer(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

function store(records) {
  window.localStorage.setItem(SHARED_STORAGE_KEY, JSON.stringify(records));
}

function stored() {
  return JSON.parse(window.localStorage.getItem(SHARED_STORAGE_KEY));
}

function answerWith(body, status = 200) {
  const fetchMock = vi.fn(async () => jsonAnswer(body, status));
  vi.stubGlobal('fetch', fetchMock);
  return fetchMock;
}

function requestedStorageIds(fetchMock) {
  return JSON.parse(fetchMock.mock.calls[0][1].body).storageIds;
}

beforeEach(() => {
  seedUnifiedCredentialRecords(null);
  window.localStorage.clear();
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe('synchronising advanced credential artifacts', () => {
  it('has nothing to do when nothing is saved', async () => {
    await expect(ensureAdvancedCredentialArtifactsSynced()).resolves.toBe(false);
  });

  it('leaves a credential saved without a type as it was', async () => {
    const fetchMock = answerWith({ status: 'OK' });
    const simple = { credentialId: 'c2ltcGxlLWNyZWQ', email: 'user@example.com' };
    store([simple]);

    await expect(ensureAdvancedCredentialArtifactsSynced()).resolves.toBe(false);
    expect(stored()).toEqual([simple]);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('keeps a heavy credential whole when the server refuses its artifact', async () => {
    answerWith({ error: 'Unable to store artifact.' }, 400);
    const heavy = advanced({ storageId: STORAGE_ID, attestationObject: 'o2NmbXRkbm9uZQ', hasServerArtifact: false });
    store([heavy]);

    await expect(ensureAdvancedCredentialArtifactsSynced()).resolves.toBe(false);
    expect(stored()).toEqual([heavy]);
  });

  it('summarises a credential the server already holds without uploading it again', async () => {
    const fetchMock = answerWith({ status: 'OK' });
    store([advanced({ storageId: STORAGE_ID, hasServerArtifact: true, artifactVersion: 1 })]);

    await expect(ensureAdvancedCredentialArtifactsSynced()).resolves.toBe(true);
    expect(stored()[0].localStorageId).toBe(STORAGE_ID);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('reports no change, and writes nothing, for a credential an earlier warm-up summarised', async () => {
    const fetchMock = answerWith({ status: 'OK' });
    store([advanced({ storageId: STORAGE_ID, hasServerArtifact: true, artifactVersion: 1 })]);
    await expect(ensureAdvancedCredentialArtifactsSynced()).resolves.toBe(true);
    const summarised = window.localStorage.getItem(SHARED_STORAGE_KEY);
    const setItem = vi.spyOn(window.localStorage, 'setItem');

    await expect(ensureAdvancedCredentialArtifactsSynced()).resolves.toBe(false);
    expect(setItem).not.toHaveBeenCalled();
    expect(window.localStorage.getItem(SHARED_STORAGE_KEY)).toBe(summarised);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('shares the synchronisation already under way', async () => {
    const first = ensureAdvancedCredentialArtifactsSynced();

    expect(ensureAdvancedCredentialArtifactsSynced()).toBe(first);
    await first;
  });
});

describe('prefetching advanced credential snapshots', () => {
  it('has nothing to do when nothing is saved', async () => {
    await expect(ensureAdvancedCredentialSnapshotsPrefetched()).resolves.toBe(false);
  });

  it('asks once for two credentials that share a storage id', async () => {
    const fetchMock = answerWith({ artifacts: { [STORAGE_ID]: { registrationDetailSnapshot: SNAPSHOT } } });
    store([
      advanced({ storageId: STORAGE_ID, hasServerArtifact: true }),
      advanced({ credentialId: 'c2Vjb25kLWNyZWQ', localStorageId: STORAGE_ID, hasServerArtifact: true }),
    ]);

    await expect(ensureAdvancedCredentialSnapshotsPrefetched()).resolves.toBe(true);
    expect(requestedStorageIds(fetchMock)).toEqual([STORAGE_ID]);
    expect(stored()[1].registrationDetailSnapshot).toEqual(SNAPSHOT);
  });

  it('does not ask for a credential without a storage id, and leaves it as it was', async () => {
    const fetchMock = answerWith({ artifacts: { [STORAGE_ID]: { registrationDetailSnapshot: SNAPSHOT } } });
    const withoutId = advanced({ credentialId: 'bm8tc3RvcmFnZS1pZA', hasServerArtifact: true });
    store([withoutId, advanced({ storageId: STORAGE_ID, hasServerArtifact: true })]);

    await ensureAdvancedCredentialSnapshotsPrefetched();

    expect(requestedStorageIds(fetchMock)).toEqual([STORAGE_ID]);
    expect(stored()[0]).toEqual(withoutId);
  });

  it('leaves a simple credential as it was', async () => {
    answerWith({ artifacts: { [STORAGE_ID]: { registrationDetailSnapshot: SNAPSHOT } } });
    const simple = { type: 'simple', credentialId: 'c2ltcGxlLWNyZWQ', email: 'user@example.com' };
    store([simple, advanced({ storageId: STORAGE_ID, hasServerArtifact: true })]);

    await ensureAdvancedCredentialSnapshotsPrefetched();

    expect(stored()[0]).toEqual(simple);
  });

  it('changes nothing when the artifact holds no snapshot it can keep', async () => {
    answerWith({ artifacts: { [STORAGE_ID]: { registrationDetailSnapshot: { html: '<p>old</p>' } } } });
    store([advanced({ storageId: STORAGE_ID, hasServerArtifact: true })]);

    await expect(ensureAdvancedCredentialSnapshotsPrefetched()).resolves.toBe(false);
    expect(stored()[0].registrationDetailSnapshot).toBeUndefined();
  });

  it('gives up quietly when the browser refuses access to its storage', async () => {
    Object.defineProperty(window, 'localStorage', {
      configurable: true,
      get() {
        throw new DOMException('The operation is insecure.', 'SecurityError');
      },
    });

    await expect(ensureAdvancedCredentialSnapshotsPrefetched()).resolves.toBe(false);
  });

  it('shares the prefetch already under way', async () => {
    const first = ensureAdvancedCredentialSnapshotsPrefetched();

    expect(ensureAdvancedCredentialSnapshotsPrefetched()).toBe(first);
    await first;
  });
});


describe("stored credentials: artifacts", () => {
  let fetchCredentialArtifactsBulk;
  let updateCredentialSnapshot;
  let uploadCredentialArtifact;
  beforeEach(() => {
    window.localStorage.clear();
    seedUnifiedCredentialRecords([]);
    fetchCredentialArtifactsBulk = vi.spyOn(artifactsClient, 'fetchCredentialArtifactsBulk').mockReset();
    updateCredentialSnapshot = vi.spyOn(artifactsClient, 'updateCredentialSnapshot').mockReset();
    uploadCredentialArtifact = vi.spyOn(artifactsClient, 'uploadCredentialArtifact').mockReset();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("synchronizes an artifact and marks its stored record", async () => {
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
    expect(await ensureAdvancedCredentialArtifactsSynced()).toBe(true);
    const afterSync = JSON.parse(localStorage.getItem(SHARED_STORAGE_KEY));
    expect(afterSync[0].hasServerArtifact).toBe(true);
    expect(uploadCredentialArtifact).toHaveBeenCalled();
  });

  it("prefetches a registration snapshot for a server artifact", async () => {
    const heavyRecord = {
          type: 'advanced',
          credentialId: 'adv-2',
          storageId: 'adv-2::storage',
          attestationObject: 'heavy-data',
          publicKey: 'cHVibGlj',
          hasServerArtifact: false,
        };
    localStorage.setItem(SHARED_STORAGE_KEY, JSON.stringify([{ ...heavyRecord, hasServerArtifact: true }]));
    seedUnifiedCredentialRecords(null);
    fetchCredentialArtifactsBulk.mockResolvedValue({
          'adv-2::storage': {
            registrationDetailSnapshot: {
              html: '<p>summary</p>',
              state: { authenticatorDataHex: '0a0b' },
            },
          },
        });
    expect(await ensureAdvancedCredentialSnapshotsPrefetched()).toBe(true);
    const afterPrefetch = JSON.parse(localStorage.getItem(SHARED_STORAGE_KEY));
    expect(afterPrefetch[0].registrationDetailSnapshot).toEqual({ state: { authenticatorDataHex: '0a0b' } });
  });

  it("prefetches snapshots only for missing advanced records with server artifacts", async () => {
    seedUnifiedCredentialRecords(null);
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
            registrationDetailSnapshot: { html: '<p>exists</p>', state: { authenticatorDataHex: '0a0b' } },
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
    const changed = await ensureAdvancedCredentialSnapshotsPrefetched();
    expect(changed).toBe(true);
    expect(fetchCredentialArtifactsBulk).toHaveBeenCalledWith(['needs-snapshot::storage']);
    const records = JSON.parse(localStorage.getItem(SHARED_STORAGE_KEY));
    const updated = records.find((record) => record.storageId === 'needs-snapshot::storage');
    expect(updated.registrationDetailSnapshot.html).toBeUndefined();
    expect(updated.registrationDetailSnapshot.state.authenticatorDataHex).toBe('aa'.repeat(10));
  });

  it("retries artifact synchronization after transient upload failures", async () => {
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
    expect(await ensureAdvancedCredentialArtifactsSynced()).toBe(false);
    uploadCredentialArtifact.mockResolvedValueOnce(true);
    expect(await ensureAdvancedCredentialArtifactsSynced()).toBe(true);
    const records = JSON.parse(localStorage.getItem(SHARED_STORAGE_KEY));
    expect(records[0].hasServerArtifact).toBe(true);
  });

  it("prefetches snapshots from storedCredential fallback and sanitizes nested fields", async () => {
    seedUnifiedCredentialRecords(null);
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
                state: {
                  visibleAttestationCertificateIndices: ['1', 'NaN', null],
                  attestationCertificates: [
                    {
                      parsedX5c: {
                        subject: 'CN=Snapshot',
                        derBase64: 'drop',
                        extensions: [{ oid: '1.2.3.4', value: { 'Hex value': '0102' } }],
                      },
                    },
                  ],
                  authenticatorData: {
                    value: 'keep-value',
                  },
                },
              },
            },
          },
        });
    const changed = await ensureAdvancedCredentialSnapshotsPrefetched();
    expect(changed).toBe(true);
    const records = JSON.parse(localStorage.getItem(SHARED_STORAGE_KEY));
    const snapshot = records[0].registrationDetailSnapshot;
    expect(snapshot.html).toBeUndefined();
    expect(snapshot.combinedHtml).toBeUndefined();
    expect(snapshot.state.visibleAttestationCertificateIndices).toEqual([1]);
    expect(snapshot.state.attestationCertificates[0].parsedX5c.derBase64).toBeUndefined();
    expect(snapshot.state.attestationCertificates[0].parsedX5c.extensions).toEqual([{ oid: '1.2.3.4', value: { 'Hex value': '0102' } }]);
    expect(snapshot.state.authenticatorData.value).toBe('keep-value');
  });

  it("summarizes heavy advanced fields before persisting synced artifacts", async () => {
    localStorage.setItem(SHARED_STORAGE_KEY, JSON.stringify([
          {
            type: 'advanced',
            credentialId: 'summary-target',
            storageId: 'summary-target::storage',
            publicKey: 'cHVibGlj',
            hasServerArtifact: false,
            attestationObject: 'heavy-object',
            properties: {
              attestationChecks: { authenticator_data: { counter: 0 } },
              customFlag: true,
            },
            relyingParty: {
              attestationObject: 'heavy-rp-object',
              displayName: 'RP Display',
            },
          },
        ]));
    uploadCredentialArtifact.mockResolvedValueOnce(true);
    const changed = await ensureAdvancedCredentialArtifactsSynced();
    expect(changed).toBe(true);
    const records = JSON.parse(localStorage.getItem(SHARED_STORAGE_KEY));
    const stored = records[0];
    expect(stored.hasServerArtifact).toBe(true);
    expect(stored.attestationObject).toBeUndefined();
    expect(stored.properties.customFlag).toBe(true);
    expect(stored.properties.attestationChecks).toBeUndefined();
    expect(stored.relyingParty.displayName).toBe('RP Display');
  });

  it("changes nothing when the snapshots cannot be fetched", async () => {
    saveAdvancedCredential({
          credentialId: 'shared-counter',
          publicKey: 'cHVibGlj',
          storageId: 'shared-counter::storage',
        });
    fetchCredentialArtifactsBulk.mockRejectedValueOnce(new Error('prefetch failed'));
    await expect(ensureAdvancedCredentialSnapshotsPrefetched()).resolves.toBe(false);
  });
});
