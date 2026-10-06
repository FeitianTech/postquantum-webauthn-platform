import { readFileSync } from 'node:fs';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { getAllAdvancedCredentials, prepareAdvancedCredentialsForServer, removeAdvancedCredential, saveAdvancedCredential, updateAdvancedCredentialSignCount } from './advanced-credentials.js';
import { seedUnifiedCredentialRecords } from './storage-core.js';
import { repoFile } from '@/test/logic/repo-file.js';
import { getAllSimpleCredentials, saveSimpleCredential } from './simple-credentials.js';

const SHARED_STORAGE_KEY = 'postquantum-webauthn.credentials';

// The summary the browser saves after an advanced registration, as the server answers it.
const SERVER_STORED_CREDENTIAL = JSON.parse(
  readFileSync(repoFile('tests/app/characterization/golden/routes/advanced-register-none-es256.json'), 'utf8'),
).requests.find(entry => entry.request === 'POST /api/advanced/register/complete').body.storedCredential;

const CREDENTIAL_ID = SERVER_STORED_CREDENTIAL.credentialIdBase64Url;
const OTHER_ID = 'b3RoZXItY3JlZGVudGlhbC1pZA';

function registeredCredential(overrides = {}) {
  return { ...structuredClone(SERVER_STORED_CREDENTIAL), ...overrides };
}

function storedAdvanced(credentialId, storageId, overrides = {}) {
  return { type: 'advanced', credentialId, credentialIdBase64Url: credentialId, storageId, ...overrides };
}

function store(records) {
  window.localStorage.setItem(SHARED_STORAGE_KEY, JSON.stringify(records));
}

function stored() {
  return JSON.parse(window.localStorage.getItem(SHARED_STORAGE_KEY));
}

// Storage that refuses any value longer than `limit`, as a full browser storage does.
function limitStorageTo(limit) {
  const setItem = window.localStorage.setItem.bind(window.localStorage);
  vi.spyOn(window.localStorage, 'setItem').mockImplementation((key, value) => {
    if (String(value).length > limit) {
      throw new DOMException('The quota has been exceeded.', 'QuotaExceededError');
    }
    setItem(key, value);
  });
}

beforeEach(() => {
  window.localStorage.clear();
  seedUnifiedCredentialRecords(null);
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe('saveAdvancedCredential', () => {
  it('saves the stored credential the server answered and reads it back', () => {
    saveAdvancedCredential(registeredCredential());

    expect(getAllAdvancedCredentials().map(record => record.storageId)).toEqual([
      SERVER_STORED_CREDENTIAL.storageId,
    ]);
  });

  it('refuses something that is not a record', () => {
    expect(saveAdvancedCredential(null)).toBeNull();
    expect(saveAdvancedCredential('advanced')).toBeNull();
  });

  it('refuses a record without a credential id', () => {
    expect(saveAdvancedCredential({ userName: 'alice', signCount: 0 })).toBeNull();
    expect(window.localStorage.getItem(SHARED_STORAGE_KEY)).toBeNull();
  });

  it.each([
    ['its email', { email: 'alice@example.com' }, 'alice@example.com'],
    ['its user name', { userName: 'alice' }, 'alice'],
    ['its legacy username', { username: 'alice-legacy' }, 'alice-legacy'],
    ['no name at all', {}, ''],
  ])('takes the name of the simple credential it replaces, which has %s', (_label, names, expected) => {
    store([{ type: 'simple', credentialId: CREDENTIAL_ID, ...names }]);

    const saved = saveAdvancedCredential(registeredCredential({ userName: undefined }));

    expect(saved.email).toBe(expected);
    expect(stored().map(record => record.type)).toEqual(['advanced']);
  });

  it('keeps its own email over the one of the simple credential it replaces', () => {
    store([{ type: 'simple', credentialId: CREDENTIAL_ID, email: 'old@example.com' }]);

    const saved = saveAdvancedCredential(registeredCredential({ email: 'alice@example.com' }));

    expect(saved.email).toBe('alice@example.com');
  });

  it('carries over the counter of the stored copy it replaces', () => {
    store([storedAdvanced(CREDENTIAL_ID, 'earlier-copy', { signCount: 9 })]);

    const saved = saveAdvancedCredential(registeredCredential({ signCount: undefined }));

    expect(saved.signCount).toBe(9);
    expect(stored().map(record => record.storageId)).toEqual([SERVER_STORED_CREDENTIAL.storageId]);
  });

  it('keeps the other advanced credentials beside the one it saves', () => {
    store([storedAdvanced(OTHER_ID, 'other-copy')]);

    saveAdvancedCredential(registeredCredential());

    expect(stored().map(record => record.storageId)).toEqual(['other-copy', SERVER_STORED_CREDENTIAL.storageId]);
  });

  it('keeps a stored advanced record that has no credential id', () => {
    store([{ type: 'advanced', storageId: 'no-id-copy', userName: 'bob' }]);

    saveAdvancedCredential(registeredCredential());

    expect(stored().map(record => record.storageId)).toEqual(['no-id-copy', SERVER_STORED_CREDENTIAL.storageId]);
  });

  it('saves a trimmed copy when the full one does not fit in storage', () => {
    store([storedAdvanced(OTHER_ID, 'other-copy')]);
    const registrationResponse = {
      id: CREDENTIAL_ID,
      type: 'public-key',
      response: { clientDataJSON: 'eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0'.repeat(600) },
    };
    limitStorageTo(12000);

    const saved = saveAdvancedCredential(registeredCredential({ registrationResponse }));

    expect(saved).not.toHaveProperty('registrationResponse');
    expect(stored().map(record => record.storageId)).toEqual(['other-copy', SERVER_STORED_CREDENTIAL.storageId]);
  });

  it('saves nothing when even the trimmed copy does not fit in storage', () => {
    store([storedAdvanced(OTHER_ID, 'other-copy')]);
    limitStorageTo(0);

    expect(saveAdvancedCredential(registeredCredential())).toBeNull();
    expect(stored().map(record => record.storageId)).toEqual(['other-copy']);
  });
});

describe('removeAdvancedCredential', () => {
  it('removes the credential with the given id when no storage id is given', () => {
    store([storedAdvanced(CREDENTIAL_ID, 'mine'), storedAdvanced(OTHER_ID, 'other')]);

    expect(removeAdvancedCredential(CREDENTIAL_ID)).toBe(true);
    expect(stored().map(record => record.storageId)).toEqual(['other']);
  });

  it('removes only the copy with the given storage id', () => {
    store([storedAdvanced(CREDENTIAL_ID, 'first'), storedAdvanced(CREDENTIAL_ID, 'second')]);

    expect(removeAdvancedCredential(CREDENTIAL_ID, ' second ')).toBe(true);
    expect(stored().map(record => record.storageId)).toEqual(['first']);
  });

  it('removes nothing when given neither an id nor a storage id', () => {
    store([storedAdvanced(CREDENTIAL_ID, 'mine')]);

    expect(removeAdvancedCredential('', null)).toBe(false);
    expect(stored()).toHaveLength(1);
  });
});


describe('updateAdvancedCredentialSignCount', () => {
  it('does nothing without an id or a storage id', () => {
    store([storedAdvanced(CREDENTIAL_ID, 'mine', { signCount: 3 })]);

    expect(updateAdvancedCredentialSignCount('', 4)).toBe(false);
    expect(stored()[0].signCount).toBe(3);
  });

  it('sets the counter of the credential with that id only', () => {
    store([
      storedAdvanced(CREDENTIAL_ID, 'mine', { signCount: 3 }),
      storedAdvanced(OTHER_ID, 'other', { signCount: 5 }),
      { type: 'simple', credentialId: 'c2ltcGxlLWlk', email: 'bob@example.com', signCount: 8 },
    ]);

    expect(updateAdvancedCredentialSignCount(CREDENTIAL_ID, 12)).toBe(true);
    expect(stored().map(record => record.signCount)).toEqual([12, 5, 8]);
  });

  it('sets the counter of the copy with the given storage id only', () => {
    store([
      storedAdvanced(CREDENTIAL_ID, 'first', { signCount: 3 }),
      storedAdvanced(CREDENTIAL_ID, 'second', { signCount: 3 }),
    ]);

    expect(updateAdvancedCredentialSignCount('', 4, 'second')).toBe(true);
    expect(stored().map(record => record.signCount)).toEqual([3, 4]);
  });

  it('reports that no credential has the id', () => {
    store([storedAdvanced(OTHER_ID, 'other', { signCount: 5 })]);

    expect(updateAdvancedCredentialSignCount(CREDENTIAL_ID, 6)).toBe(false);
    expect(stored()[0].signCount).toBe(5);
  });
});


describe("stored credentials: simple", () => {
  beforeEach(() => {
    window.localStorage.clear();
    seedUnifiedCredentialRecords([]);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("counts a sign-in held in the simple partition", async () => {
    saveAdvancedCredential({
          credentialId: 'shared-counter',
          publicKey: 'cHVibGlj',
          storageId: 'shared-counter::storage',
        });
    saveSimpleCredential({
          credentialId: 'simple-counter',
          email: 'simple@example.com',
          publicKey: 'cHVibGlj',
          signCount: 2,
        });
    expect(updateAdvancedCredentialSignCount('simple-counter')).toBe(true);
    expect(getAllSimpleCredentials()[0].signCount).toBe(3);
  });
});


describe("stored credentials: artifacts", () => {
  beforeEach(() => {
    window.localStorage.clear();
    seedUnifiedCredentialRecords([]);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("reports false when an advanced removal names no credential", async () => {
    expect(removeAdvancedCredential('', null)).toBe(false);
  });
});


describe("stored credentials: advanced", () => {
  beforeEach(() => {
    window.localStorage.clear();
    seedUnifiedCredentialRecords([]);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("stores, prepares, updates, and removes advanced credentials", async () => {
    saveSimpleCredential({
          credentialId: 'adv-1',
          email: 'advanced@example.com',
          publicKey: 'cHVibGlj',
          signCount: 1,
        });
    const saved = saveAdvancedCredential({
          credentialId: 'adv-1',
          publicKey: 'cHVibGlj',
          signCount: 4,
          authenticatorAttachment: 'platform',
          residentKey: true,
        });
    expect(saved.storageId).toContain('adv-1');
    expect(getAllSimpleCredentials()).toHaveLength(0);
    expect(getAllAdvancedCredentials()).toHaveLength(1);
    const prepared = prepareAdvancedCredentialsForServer();
    expect(prepareAdvancedCredentialsForServer([])).toEqual([]);
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
    expect(updateAdvancedCredentialSignCount('adv-1', undefined, saved.storageId)).toBe(true);
    expect(getAllAdvancedCredentials()[0].signCount).toBe(5);
    expect(removeAdvancedCredential('adv-1', saved.storageId)).toBe(true);
    expect(getAllAdvancedCredentials()).toHaveLength(0);
  });

  it("merges simple credential data into advanced saves and updates/removes by storageId", async () => {
    saveSimpleCredential({
          credentialId: 'advanced-merge',
          email: 'advanced-merge@example.com',
          publicKey: 'cHVibGlj',
          signCount: 6,
        });
    const savedAdvanced = saveAdvancedCredential({
          credentialId: 'advanced-merge',
          publicKey: 'cHVibGlj',
          authenticatorAttachment: 'cross-platform',
        });
    expect(savedAdvanced).not.toBeNull();
    expect(savedAdvanced.storageId).toContain('advanced-merge');
    expect(getAllSimpleCredentials()).toHaveLength(0);
    const advanced = getAllAdvancedCredentials();
    expect(advanced).toHaveLength(1);
    expect(advanced[0].email).toBe('advanced-merge@example.com');
    expect(advanced[0].signCount).toBe(6);
    expect(updateAdvancedCredentialSignCount('', 19, savedAdvanced.storageId)).toBe(true);
    expect(getAllAdvancedCredentials()[0].signCount).toBe(19);
    expect(removeAdvancedCredential('', savedAdvanced.storageId)).toBe(true);
    expect(getAllAdvancedCredentials()).toHaveLength(0);
  });

  it("keeps simple credentials and replaces a matching advanced record", async () => {
    saveSimpleCredential({
          credentialId: 'simple-ready',
          email: 'simple@example.com',
          publicKey: 'cHVibGlj',
          signCount: 1,
          algorithm: -7,
        });
    saveAdvancedCredential({
          credentialId: 'advanced-ready',
          publicKey: 'cHVibGlj',
          signCount: 2,
          aaguidHex: '00112233445566778899aabbccddeeff',
          authenticatorAttachment: 'platform',
          residentKey: true,
          algorithm: -257,
        });
    saveAdvancedCredential({
          credentialId: 'advanced-ready',
          publicKey: 'cHVibGlj',
          signCount: 9,
          authenticatorAttachment: 'cross-platform',
          resident: false,
          algorithm: -257,
        });
    expect(getAllSimpleCredentials()[0].credentialId).toBe('simple-ready');
    expect(getAllAdvancedCredentials()).toHaveLength(1);
    expect(getAllAdvancedCredentials()[0]).toMatchObject({ signCount: 9, email: '', authenticatorAttachment: 'cross-platform', resident: false });
  });
});
