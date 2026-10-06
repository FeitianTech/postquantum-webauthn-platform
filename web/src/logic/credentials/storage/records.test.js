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
