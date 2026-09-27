import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import {
  ensureAdvancedCredentialArtifactsSynced,
  ensureAdvancedCredentialSnapshotsPrefetched,
} from '../../../../frontend/static/scripts/shared/storage/local/advanced-sync.js';
import {
  seedUnifiedCredentialRecords,
} from '../../../../frontend/static/scripts/shared/storage/local/storage-core.js';

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
  vi.spyOn(console, 'warn').mockImplementation(() => {});
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
    expect(console.warn).toHaveBeenCalledWith(
      'Failed to prefetch advanced credential snapshots',
      expect.any(DOMException),
    );
  });

  it('shares the prefetch already under way', async () => {
    const first = ensureAdvancedCredentialSnapshotsPrefetched();

    expect(ensureAdvancedCredentialSnapshotsPrefetched()).toBe(first);
    await first;
  });
});
