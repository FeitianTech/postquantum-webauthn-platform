import { readFileSync } from 'node:fs';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import {
  clearAdvancedCredentials,
  getAllAdvancedCredentials,
  removeAdvancedCredential,
  saveAdvancedCredential,
  updateAdvancedCredentialSignCount,
} from './advanced-credentials.js';
import { seedUnifiedCredentialRecords } from './storage-core.js';
import { repoFile } from '@/test/logic/repo-file.js';

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

describe('clearAdvancedCredentials', () => {
  it('removes every advanced credential and keeps the simple ones', () => {
    store([storedAdvanced(CREDENTIAL_ID, 'mine'), { type: 'simple', credentialId: OTHER_ID, email: 'bob@example.com' }]);

    clearAdvancedCredentials();

    expect(stored().map(record => record.type)).toEqual(['simple']);
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
