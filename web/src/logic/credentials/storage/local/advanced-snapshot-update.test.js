import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { updateAdvancedCredentialRegistrationSnapshot } from './advanced-snapshot-update.js';
import { seedUnifiedCredentialRecords } from './storage-core.js';
import * as artifactsClient from '../artifacts-client.js';

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

  it("updates registration data and uploads the sanitized snapshot", async () => {
    const heavyRecord = {
          type: 'advanced',
          credentialId: 'adv-2',
          storageId: 'adv-2::storage',
          attestationObject: 'heavy-data',
          publicKey: 'cHVibGlj',
          hasServerArtifact: false,
        };
    localStorage.setItem(SHARED_STORAGE_KEY, JSON.stringify([heavyRecord]));
    seedUnifiedCredentialRecords(null);
    updateCredentialSnapshot.mockResolvedValue(true);
    const dataSnapshot = { schemaVersion: 2, response: { credential: { id: 'adv-2' } } };
    expect(await updateAdvancedCredentialRegistrationSnapshot('adv-2::storage', {
          ...dataSnapshot,
          html: '<p>updated</p>',
        })).toBe(true);
    expect(updateCredentialSnapshot).toHaveBeenCalledWith('adv-2::storage', dataSnapshot);
  });

  it("sanitizes registration snapshots and returns upload result when local record is unchanged", async () => {
    localStorage.setItem(SHARED_STORAGE_KEY, JSON.stringify([
          {
            type: 'advanced',
            credentialId: 'different-record',
            storageId: 'different-record::storage',
            hasServerArtifact: true,
          },
        ]));
    updateCredentialSnapshot.mockResolvedValue(true);
    const result = await updateAdvancedCredentialRegistrationSnapshot('missing::storage', {
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
            state: expect.any(Object),
          }),
        );
    const uploadedSnapshot = updateCredentialSnapshot.mock.calls[0][1];
    expect(uploadedSnapshot.html).toBeUndefined();
    expect(uploadedSnapshot.combinedHtml).toBeUndefined();
    expect(uploadedSnapshot.state.authenticatorDataHex.length).toBeLessThanOrEqual(8192);
    expect(uploadedSnapshot.state.authenticatorDataHash.length).toBeLessThanOrEqual(1024);
    expect(uploadedSnapshot.state.attestationCertificates[0].parsedX5c.derBase64).toBeUndefined();
  });

  it("rejects invalid registration snapshot updates", async () => {
    updateCredentialSnapshot.mockResolvedValue(false);
    await expect(updateAdvancedCredentialRegistrationSnapshot('', { html: '<p>x</p>' })).resolves.toBe(false);
    await expect(updateAdvancedCredentialRegistrationSnapshot('missing::storage', null)).resolves.toBe(false);
    await expect(updateAdvancedCredentialRegistrationSnapshot('missing::storage', { html: 'x' })).resolves.toBe(false);
    await expect(updateAdvancedCredentialRegistrationSnapshot('missing::storage', {
          state: { authenticatorDataHex: '0a0b' },
        })).resolves.toBe(false);
    expect(updateCredentialSnapshot).toHaveBeenCalledTimes(1);
  });
});
