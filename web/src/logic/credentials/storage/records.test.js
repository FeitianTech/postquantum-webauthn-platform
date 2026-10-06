import { beforeEach, describe, expect, it, vi } from 'vitest';
import { loadStorage, seedRecords } from '@/test/logic/credentials/storage/seed.js';

import { ADVANCED_RECORD, SIMPLE_RECORD } from '@/test/logic/credentials/storage/standard-base64-records.js';
import { base64ToBytes, base64UrlToBytes } from '../../shared/base64.js';
import { getCredentialIdHex, getCredentialUserHandleHex } from '../record-fields.js';

vi.mock('./artifacts-client.js', () => ({
  fetchCredentialArtifactsBulk: vi.fn(),
  updateCredentialSnapshot: vi.fn(),
  uploadCredentialArtifact: vi.fn(),
}));

import {
  fetchCredentialArtifactsBulk,
  updateCredentialSnapshot,
  uploadCredentialArtifact,
} from './artifacts-client.js';

// The saved credentials as both tabs read and write them, through the storage's
// modules (credentials/storage/records.js and local/), with the server's
// artifacts answered by stand-ins.

const SHARED_STORAGE_KEY = 'postquantum-webauthn.credentials';

// The storage over what a page saved: no boot records, so it reads localStorage.
async function loadStored(records) {
  if (records) {
    localStorage.setItem(SHARED_STORAGE_KEY, JSON.stringify(records));
  }
  seedRecords(null);
  return loadStorage();
}

const MARKUP = '<section><img src=x onerror="window.__xss=1"></section>';

// A record saved by an earlier version: registration detail stored as composed
// HTML in the snapshot.
function savedRecord() {
  return {
    type: 'advanced',
    credentialId: 'AQID',
    storageId: 'AQID::storage',
    userName: 'alice',
    registrationDetailSnapshot: {
      schemaVersion: 1,
      html: MARKUP,
      attestationSectionHtml: MARKUP,
      combinedHtml: MARKUP,
      state: { authenticatorDataHex: '0a0b' },
    },
  };
}

function bytesOf(value) {
  return Array.from(value.includes('-') || value.includes('_') || !/[+/=]/.test(value)
    ? base64UrlToBytes(value)
    : base64ToBytes(value));
}

beforeEach(() => {
  window.localStorage.clear();
  seedRecords([]);
  fetchCredentialArtifactsBulk.mockReset();
  updateCredentialSnapshot.mockReset();
  uploadCredentialArtifact.mockReset();
});

describe('advanced credentials', () => {
  it('stores, prepares, updates, and removes advanced credentials', async () => {
    const storage = await loadStorage();

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

  it('merges simple credential data into advanced saves and updates/removes by storageId', async () => {
    const storage = await loadStorage();

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

  it('prepares server payloads with dedupe, filtering, and best sign count', async () => {
    const storage = await loadStorage();

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

  it('builds advanced server payloads with the COSE key\'s algorithm and keeps highest signCount variant', async () => {
    const storage = await loadStorage();

    const payload = storage.prepareAdvancedCredentialsForServer([
      {
        credentialId: 'cose-derived',
        publicKey: 'pQE',
        publicKeyCose: { 1: 2, 3: -8 },
        signCount: 3,
        relyingParty: { residentKey: true },
      },
      {
        credentialId: 'cose-derived',
        publicKey: 'pQE',
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
    expect(payload[0].publicKey).toBe('pQE');
    expect(payload[0].resident).toBe(false);
  });
});

describe('storage keys of an earlier version', () => {
  it('migrates legacy storage keys into unified records and removes legacy keys', async () => {
    seedRecords(null);

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

    const storage = await loadStorage();

    const ordered = storage.getAllStoredCredentialsInOrder();
    expect(ordered).toHaveLength(2);
    expect(ordered.find((record) => record.type === 'simple')?.credentialId).toBe('simple-legacy');
    expect(ordered.find((record) => record.type === 'advanced')?.credentialId).toBe('advanced-legacy');

    expect(localStorage.getItem('postquantum-webauthn.simpleCredentials')).toBeNull();
    expect(localStorage.getItem('postquantum-webauthn.advancedCredentials')).toBeNull();

    const unified = JSON.parse(localStorage.getItem(SHARED_STORAGE_KEY));
    expect(unified).toHaveLength(2);
  });
});

describe('credential records saved before base64url', () => {
  beforeEach(() => {
    window.localStorage.clear();
  });

  it('are read back in base64url, holding the same bytes', async () => {
    const storage = await loadStored([SIMPLE_RECORD, ADVANCED_RECORD]);

    const [simple] = storage.getAllSimpleCredentials();
    const [advanced] = storage.getAllAdvancedCredentials();

    expect(simple.credentialId).toBe(SIMPLE_RECORD.credentialIdBase64Url);
    expect(simple.publicKey).toBe(SIMPLE_RECORD.publicKeyBase64Url);
    expect(simple.publicKeyBytes).toBe(SIMPLE_RECORD.publicKeyBase64Url);
    expect(advanced.publicKey).toBe(ADVANCED_RECORD.publicKeyBase64Url);
    expect(advanced.userHandle).toBe(ADVANCED_RECORD.userHandleBase64Url);

    const pairs = [
      [SIMPLE_RECORD.publicKeyCose['-2'], simple.publicKeyCose['-2']],
      [SIMPLE_RECORD.publicKeyCose['-3'], simple.publicKeyCose['-3']],
      [SIMPLE_RECORD.attestationStatement.sig, simple.attestationStatement.sig],
      [SIMPLE_RECORD.attestationStatement.x5c[0], simple.attestationStatement.x5c[0]],
      [ADVANCED_RECORD.publicKeyCose['-2'], advanced.publicKeyCose['-2']],
    ];
    for (const [saved, read] of pairs) {
      expect(read).toMatch(/^[A-Za-z0-9_-]+$/);
      expect(bytesOf(read)).toEqual(bytesOf(saved));
    }
  });

  it('keep fields named for base64, extension outputs and text as they were', async () => {
    const statement = { ...SIMPLE_RECORD.attestationStatement, ver: '2.0' };
    const storage = await loadStored([
      { ...SIMPLE_RECORD, attestationStatement: statement },
      ADVANCED_RECORD,
    ]);

    const [simple] = storage.getAllSimpleCredentials();
    const [advanced] = storage.getAllAdvancedCredentials();
    expect(simple.attestationStatement.ver).toBe('2.0');
    expect(simple.attestationStatement.alg).toBe(-7);
    expect(simple.publicKeyCose['-1']).toBe(1);
    expect(simple.clientExtensionOutputs).toEqual(SIMPLE_RECORD.clientExtensionOutputs);
    expect(advanced.publicKeyBase64).toBe(ADVANCED_RECORD.publicKeyBase64);
    expect(advanced.userHandleBase64).toBe(ADVANCED_RECORD.userHandleBase64);
    expect(advanced.credentialIdHex).toBe(ADVANCED_RECORD.credentialIdHex);
  });

  it('are saved once in the new spelling, and read again without another save', async () => {
    const storage = await loadStored([SIMPLE_RECORD]);
    const setItem = vi.spyOn(window.localStorage, 'setItem');

    storage.getAllSimpleCredentials();
    const [saved] = JSON.parse(localStorage.getItem(SHARED_STORAGE_KEY));
    expect(saved.publicKey).toBe(SIMPLE_RECORD.publicKeyBase64Url);

    vi.resetModules();
    const again = await import('./local/simple-credentials.js');
    setItem.mockClear();
    again.getAllSimpleCredentials();
    expect(setItem).not.toHaveBeenCalled();
    setItem.mockRestore();
  });

  it('a simple record saved without credentialIdBase64Url is found by the ID the server reports', async () => {
    const legacy = { ...SIMPLE_RECORD };
    delete legacy.credentialIdBase64Url;
    const storage = await loadStored([legacy]);

    const updated = storage.updateSimpleCredentialSignCount(
      'user@example.com',
      SIMPLE_RECORD.credentialIdBase64Url,
      5,
    );

    expect(updated).toBe(true);
    expect(storage.getAllSimpleCredentials()[0].signCount).toBe(5);
  });

  it('still name the same credential and user handle', async () => {
    const storage = await loadStored([SIMPLE_RECORD, ADVANCED_RECORD]);

    const [simple] = storage.getAllSimpleCredentials();
    const [advanced] = storage.getAllAdvancedCredentials();
    expect(getCredentialIdHex({ credentialId: simple.credentialId })).toBe(SIMPLE_RECORD.credentialIdHex);
    expect(getCredentialIdHex({ credentialId: advanced.credentialId })).toBe(ADVANCED_RECORD.credentialIdHex);
    expect(getCredentialUserHandleHex({ userHandle: advanced.userHandle })).toBe(ADVANCED_RECORD.userHandleHex);
  });
});

describe('registration markup saved by an earlier version', () => {
  beforeEach(() => {
    window.localStorage.clear();
  });

  it('is dropped when the record is read, and the record saved without it', async () => {
    localStorage.setItem(SHARED_STORAGE_KEY, JSON.stringify([savedRecord()]));

    const storage = await loadStored();
    const [record] = storage.getAllAdvancedCredentials();

    expect(record.registrationDetailSnapshot).toEqual({ schemaVersion: 1, state: { authenticatorDataHex: '0a0b' } });
    expect(record.userName).toBe('alice');

    const [saved] = JSON.parse(localStorage.getItem(SHARED_STORAGE_KEY));
    expect(JSON.stringify(saved)).not.toContain('<section>');
    expect(saved.registrationDetailSnapshot.state).toEqual({ authenticatorDataHex: '0a0b' });
  });

  it('takes the snapshot away when markup was all it held', async () => {
    const record = savedRecord();
    delete record.registrationDetailSnapshot.state;
    localStorage.setItem(SHARED_STORAGE_KEY, JSON.stringify([record]));

    const storage = await loadStored();

    expect(storage.getAllAdvancedCredentials()[0].registrationDetailSnapshot).toBeUndefined();
  });

  it('leaves a record without markup as it is', async () => {
    const record = { type: 'advanced', credentialId: 'AQID', storageId: 'AQID::storage', userName: 'bob' };
    localStorage.setItem(SHARED_STORAGE_KEY, JSON.stringify([record]));
    const before = localStorage.getItem(SHARED_STORAGE_KEY);

    const storage = await loadStored();
    storage.getAllAdvancedCredentials();

    expect(localStorage.getItem(SHARED_STORAGE_KEY)).toBe(before);
  });
});
