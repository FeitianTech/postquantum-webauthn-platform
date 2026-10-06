import { readFileSync } from 'node:fs';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { clearSimpleCredentials, getAllSimpleCredentials, getSimpleCredentialsForEmail, prepareCredentialsForServer, removeSimpleCredential, saveSimpleCredential, updateSimpleCredentialSignCount } from './simple-credentials.js';
import { seedUnifiedCredentialRecords } from './storage-core.js';
import { repoFile } from '@/test/logic/repo-file.js';
import { getAllAdvancedCredentials, saveAdvancedCredential } from './advanced-credentials.js';

const SHARED_STORAGE_KEY = 'postquantum-webauthn.credentials';

// The storedCredential register-complete answers (characterization goldens).
function registered(scenario) {
  const path = `tests/app/characterization/golden/routes/${scenario}.json`;
  return JSON.parse(readFileSync(repoFile(path), 'utf8')).requests[1].body.storedCredential;
}

const ES256 = registered('simple-register-es256');
const ED25519 = registered('simple-register-ed25519');
const ADVANCED = registered('advanced-register-none-es256');
const ES256_ID = ES256.credentialIdBase64Url;
const ED25519_ID = ED25519.credentialIdBase64Url;

// An advanced record saved before it had a credential id.
const ADVANCED_WITHOUT_ID = {
  type: 'advanced',
  storageId: 'draft::1a0c4506c00::abb1b052d88044e486bb1446aa6a1e87',
  userName: 'bob@example.com',
};

// The record with its account fields (email, userName, username) replaced by `account`.
function withAccount(record, account) {
  const { email, userName, username, ...rest } = record;
  return { ...rest, ...account };
}

function store(records) {
  window.localStorage.setItem(SHARED_STORAGE_KEY, JSON.stringify(records));
}

function stored() {
  return JSON.parse(window.localStorage.getItem(SHARED_STORAGE_KEY));
}

function savedIdsAndCounts() {
  return getAllSimpleCredentials().map(record => [record.credentialIdBase64Url, record.signCount]);
}

beforeEach(() => {
  window.localStorage.clear();
  seedUnifiedCredentialRecords(null);
});

describe('simple credentials for an email', () => {
  it('are none without an email', () => {
    store([ES256]);

    expect(getSimpleCredentialsForEmail('')).toEqual([]);
  });

  it('include a record saved without an email, by its userName', () => {
    store([withAccount(ES256, { userName: 'user@example.com' })]);

    const found = getSimpleCredentialsForEmail('User@Example.com');

    expect(found.map(record => record.credentialIdBase64Url)).toEqual([ES256_ID]);
  });

  it('include a record saved with only a username, by it', () => {
    store([withAccount(ES256, { username: 'user@example.com' })]);

    const found = getSimpleCredentialsForEmail('user@example.com');

    expect(found.map(record => record.credentialIdBase64Url)).toEqual([ES256_ID]);
  });
});

describe('saving a simple credential', () => {
  it('saves nothing that is not a record', () => {
    expect(saveSimpleCredential(null)).toBeNull();
    expect(window.localStorage.getItem(SHARED_STORAGE_KEY)).toBeNull();
  });

  it('takes the email from the userName when none is given', () => {
    const saved = saveSimpleCredential(withAccount(ES256, { userName: 'user@example.com' }));

    expect(saved.email).toBe('user@example.com');
  });

  it('takes the email from the username when there is no userName', () => {
    const saved = saveSimpleCredential(withAccount(ES256, { username: 'alice@example.com' }));

    expect(saved.email).toBe('alice@example.com');
  });

  it('leaves the email empty when the credential names no account', () => {
    const saved = saveSimpleCredential(withAccount(ES256, {}));

    expect(saved.email).toBe('');
  });

  it('refuses a credential without an id', () => {
    const { credentialId, credentialIdBase64Url, ...withoutId } = ES256;

    expect(saveSimpleCredential(withoutId)).toBeNull();
    expect(window.localStorage.getItem(SHARED_STORAGE_KEY)).toBeNull();
  });

  it('starts the signature counter at zero when none is given', () => {
    const { signCount, ...withoutCount } = ES256;

    expect(saveSimpleCredential(withoutCount).signCount).toBe(0);
  });

  it('replaces the stored copy of the same credential and keeps the others', () => {
    store([ES256, ED25519]);

    saveSimpleCredential({ ...ES256, signCount: 9 });

    expect(savedIdsAndCounts()).toEqual([[ES256_ID, 9], [ED25519_ID, ED25519.signCount]]);
  });

  it('answers null when the browser refuses to store it', () => {
    const setItem = vi.spyOn(window.localStorage, 'setItem').mockImplementation(() => {
      throw new DOMException('full', 'QuotaExceededError');
    });
    try {
      expect(saveSimpleCredential(ES256)).toBeNull();
    } finally {
      setItem.mockRestore();
    }
  });

  it('leaves an advanced record without a credential id as it was', () => {
    store([ADVANCED_WITHOUT_ID]);

    saveSimpleCredential(ES256);

    const [advanced, simple] = stored();
    expect(advanced.storageId).toBe(ADVANCED_WITHOUT_ID.storageId);
    expect(advanced).not.toHaveProperty('email');
    expect(simple.credentialIdBase64Url).toBe(ES256_ID);
  });
});

describe('removing a simple credential', () => {
  it('removes nothing without a credential id', () => {
    store([ES256]);

    expect(removeSimpleCredential('', 'user@example.com')).toBe(false);
    expect(getAllSimpleCredentials()).toHaveLength(1);
  });

  it('removes it whatever its account when no email is given, keeping the others', () => {
    store([ES256, ED25519]);

    expect(removeSimpleCredential(ES256_ID)).toBe(true);
    expect(savedIdsAndCounts()).toEqual([[ED25519_ID, ED25519.signCount]]);
  });

  it('matches the account by userName when the record has no email', () => {
    store([withAccount(ES256, { userName: 'user@example.com' })]);

    expect(removeSimpleCredential(ES256_ID, 'USER@example.com')).toBe(true);
  });

  it('matches the account by username when the record has neither email nor userName', () => {
    store([withAccount(ES256, { username: 'user@example.com' })]);

    expect(removeSimpleCredential(ES256_ID, 'user@example.com')).toBe(true);
  });

  it('keeps a record that names no account when an email is given', () => {
    store([withAccount(ES256, {})]);

    expect(removeSimpleCredential(ES256_ID, 'user@example.com')).toBe(false);
  });
});

describe('updating a simple credential\'s signature counter', () => {
  it('updates nothing without a credential id', () => {
    store([ES256]);

    expect(updateSimpleCredentialSignCount('user@example.com', '', 8)).toBe(false);
    expect(savedIdsAndCounts()).toEqual([[ES256_ID, ES256.signCount]]);
  });

  it('updates it whatever its account when no email is given, leaving the others', () => {
    store([ES256, ED25519]);

    expect(updateSimpleCredentialSignCount(null, ES256_ID, 8)).toBe(true);
    expect(savedIdsAndCounts()).toEqual([[ES256_ID, 8], [ED25519_ID, ED25519.signCount]]);
  });

  it('matches the account by userName when the record has no email', () => {
    store([withAccount(ES256, { userName: 'user@example.com' })]);

    expect(updateSimpleCredentialSignCount('user@example.com', ES256_ID, 8)).toBe(true);
    expect(savedIdsAndCounts()).toEqual([[ES256_ID, 8]]);
  });

  it('matches the account by username when the record has neither email nor userName', () => {
    store([withAccount(ES256, { username: 'user@example.com' })]);

    expect(updateSimpleCredentialSignCount('user@example.com', ES256_ID, 8)).toBe(true);
    expect(savedIdsAndCounts()).toEqual([[ES256_ID, 8]]);
  });

  it('leaves a record that names no account when an email is given', () => {
    store([withAccount(ES256, {})]);

    expect(updateSimpleCredentialSignCount('user@example.com', ES256_ID, 8)).toBe(false);
  });

  it('leaves the advanced records of other credentials alone', () => {
    store([ES256, ADVANCED, ADVANCED_WITHOUT_ID]);

    updateSimpleCredentialSignCount(null, ES256_ID, 8);

    const advanced = stored().filter(record => record.type === 'advanced');
    expect(advanced.map(record => record.signCount)).toEqual([ADVANCED.signCount, undefined]);
  });
});

describe('credentials prepared for the server', () => {
  it('are none for an empty or missing list', () => {
    expect(prepareCredentialsForServer([])).toEqual([]);
    expect(prepareCredentialsForServer(undefined)).toEqual([]);
  });

  it('carry the algorithm the record names as its publicKeyAlgorithm', () => {
    expect(prepareCredentialsForServer([ES256])).toEqual([{
      credentialId: ES256_ID,
      aaguid: ES256.aaguid,
      publicKey: ES256.publicKeyBase64Url,
      signCount: ES256.signCount,
      algorithm: ES256.publicKeyAlgorithm,
    }]);
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

  it("stores, updates, prepares, and removes simple credentials", async () => {
    const saved = saveSimpleCredential({
          credentialId: 'cred-1',
          email: 'user@example.com',
          publicKey: 'cHVibGlj',
          signCount: 2,
          aaguid: 'aaguid-1',
        });
    expect(saved.credentialIdBase64Url).toBe('cred-1');
    expect(getSimpleCredentialsForEmail('USER@example.com')).toHaveLength(1);
    expect(prepareCredentialsForServer(getAllSimpleCredentials())).toEqual([
          {
            credentialId: 'cred-1',
            aaguid: 'aaguid-1',
            publicKey: 'cHVibGlj',
            signCount: 2,
            algorithm: undefined,
          },
        ]);
    expect(updateSimpleCredentialSignCount('user@example.com', 'cred-1')).toBe(true);
    expect(getAllSimpleCredentials()[0].signCount).toBe(3);
    expect(removeSimpleCredential('cred-1', 'user@example.com')).toBe(true);
    expect(getAllSimpleCredentials()).toHaveLength(0);
  });

  it("updates advanced records when saving matching simple credentials", async () => {
    seedUnifiedCredentialRecords(null);
    localStorage.setItem(SHARED_STORAGE_KEY, JSON.stringify([
          {
            type: 'advanced',
            credentialId: 'shared-id',
            storageId: 'shared-id::storage',
            publicKey: 'cHVibGlj',
            signCount: 3,
          },
        ]));
    const saved = saveSimpleCredential({
          credentialId: 'shared-id',
          email: 'merged@example.com',
          userName: 'merged@example.com',
          publicKey: 'cHVibGlj',
          signCount: 9,
        });
    expect(saved).not.toBeNull();
    expect(getAllSimpleCredentials()).toHaveLength(0);
    expect(getAllAdvancedCredentials()).toHaveLength(1);
    expect(getAllAdvancedCredentials()[0].email).toBe('merged@example.com');
    expect(getAllAdvancedCredentials()[0].signCount).toBe(9);
  });

  it("applies strict email matching for simple updates/removal and handles explicit sign counts", async () => {
    saveSimpleCredential({
          credentialId: 'simple-email-1',
          email: 'owner@example.com',
          publicKey: 'cHVibGlj',
          signCount: 4,
        });
    expect(updateSimpleCredentialSignCount('other@example.com', 'simple-email-1')).toBe(false);
    expect(getAllSimpleCredentials()[0].signCount).toBe(4);
    expect(updateSimpleCredentialSignCount('owner@example.com', 'simple-email-1', 11)).toBe(true);
    expect(getAllSimpleCredentials()[0].signCount).toBe(11);
    expect(removeSimpleCredential('simple-email-1', 'wrong@example.com')).toBe(false);
    expect(removeSimpleCredential('simple-email-1', 'owner@example.com')).toBe(true);
    expect(getAllSimpleCredentials()).toHaveLength(0);
  });

  it("clears simple credentials while keeping the advanced partition", async () => {
    seedUnifiedCredentialRecords([
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
        ]);
    clearSimpleCredentials();
    expect(getAllSimpleCredentials()).toHaveLength(0);
    expect(getAllAdvancedCredentials()).toHaveLength(1);
  });

  it("counts a sign-in held in the advanced partition", async () => {
    const savedAdvanced = saveAdvancedCredential({
          credentialId: 'shared-counter',
          publicKey: 'cHVibGlj',
          storageId: 'shared-counter::storage',
        });
    expect(savedAdvanced).not.toBeNull();
    expect(updateSimpleCredentialSignCount('', 'shared-counter')).toBe(true);
    expect(getAllAdvancedCredentials()[0].signCount).toBe(1);
  });
});
