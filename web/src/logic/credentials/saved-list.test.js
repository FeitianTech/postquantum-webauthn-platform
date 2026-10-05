import { afterEach, describe, expect, it, vi } from 'vitest';

import {
  CREDENTIAL_CHECKS,
  SAVED_LIST_TEXT,
  credentialFlashKey,
  credentialKey,
  describeCredentialCard,
  describeCredentialRows,
  listSavedCredentials,
  readSavedCredentials,
  warmSavedCredentials,
} from './saved-list.js';
import {
  ensureAdvancedCredentialArtifactsSynced,
  ensureAdvancedCredentialSnapshotsPrefetched,
} from './storage/local/advanced-sync.js';
import { seedUnifiedCredentialRecords } from './storage/local/storage-core.js';
import { goldenAnswers } from '@/test/logic/simple/ceremony-answers.js';

// The saved-credential list both tabs show (credentials/saved-list.js).

// The warm-up's two syncs with the server, as each test says they went.
vi.mock('./storage/local/advanced-sync.js', () => ({
  ensureAdvancedCredentialArtifactsSynced: vi.fn(),
  ensureAdvancedCredentialSnapshotsPrefetched: vi.fn(),
}));

const STORED = goldenAnswers('simple-register-es256')[1].body.storedCredential;
// The golden's user handle, "user@example.com", in hex.
const USER_HANDLE_HEX = '75736572406578616d706c652e636f6d';
const AAGUID = '00112233-4455-6677-8899-AABBCCDDEEFF';

const INDICATORS = {
  signatureStatus: true,
  rootStatus: false,
  rpidStatus: null,
  aaguidStatus: true,
  metadataAvailable: false,
  aaguidGuid: 'F1D0F1D0-0000-4000-8000-000000000001',
};

afterEach(() => {
  vi.restoreAllMocks();
  seedUnifiedCredentialRecords(null);
});

describe('the records the list holds', () => {
  it('gives a simple record its type and its identifiers in hex', () => {
    const [record] = listSavedCredentials([{ ...STORED, type: 'simple' }]);
    expect(record).toMatchObject({
      type: 'simple',
      credentialIdHex: STORED.credentialIdHex,
      userHandleHex: USER_HANDLE_HEX,
      email: STORED.email,
    });
  });

  it('gives an advanced record its storage ids and a normalised AAGUID', () => {
    const [record] = listSavedCredentials([{ type: 'advanced', storageId: 's-1', aaguid: AAGUID }]);
    expect(record).toMatchObject({ type: 'advanced', storageId: 's-1', localStorageId: 's-1', aaguidHex: STORED.aaguidHex });
  });

  it('takes an advanced record\'s storage id from its local one, or has none', () => {
    const [local, none] = listSavedCredentials([{ type: 'advanced', localStorageId: 'l-1' }, { type: 'advanced' }]);
    expect([local.storageId, local.localStorageId]).toEqual(['l-1', 'l-1']);
    expect([none.storageId, none.localStorageId, none.aaguidHex]).toEqual([null, null, null]);
  });

  it('takes an advanced record\'s AAGUID from its relying party when it has none of its own', () => {
    const [record] = listSavedCredentials([{ type: 'advanced', relyingParty: { aaguid: AAGUID } }]);
    expect(record.aaguidHex).toBe(STORED.aaguidHex);
  });

  it('keeps an advanced record\'s AAGUID as stored when it does not normalise', () => {
    const [record] = listSavedCredentials([{ type: 'advanced', aaguidHex: 'AB-CD', relyingParty: 'none' }]);
    expect(record.aaguidHex).toBe('AB-CD');
  });

  it('reads every saved record, in the order stored', () => {
    seedUnifiedCredentialRecords([STORED, { type: 'advanced', storageId: 's-1' }]);
    expect(readSavedCredentials().map((record) => [record.type, record.credentialIdHex])).toEqual([
      ['simple', STORED.credentialIdHex],
      ['advanced', ''],
    ]);
  });
});

describe('a credential\'s key', () => {
  it('is its storage id, else its credential id', () => {
    expect(credentialKey({ storageId: 's-1', credentialId: 'AQ' })).toBe('storage:s-1');
    expect(credentialKey(STORED)).toBe(`id:${STORED.credentialIdBase64Url}`);
  });
});

describe('what a card shows', () => {
  const card = (credential, inputs = {}) =>
    describeCredentialCard(credential, { indicators: INDICATORS, algorithmTag: 'ES256', credentialIdHex: 'B744', ...inputs });

  it('names the account, falling back to "Unknown User"', () => {
    expect(card({ userName: 'alice', username: 'a', email: 'e' }).name).toBe('alice');
    expect(card({ username: 'a', email: 'e' }).name).toBe('a');
    expect(card({ email: 'e' }).name).toBe('e');
    expect(card({}).name).toBe(SAVED_LIST_TEXT.unknownUser);
  });

  it('gives the four checks in order, each true, false or unknown', () => {
    expect(card({}).checks).toEqual([
      { label: 'Signature', value: true },
      { label: 'Root', value: false },
      { label: 'RPID', value: null },
      { label: 'AAGUID', value: true },
    ]);
    expect(CREDENTIAL_CHECKS.map((check) => check.label)).toEqual(['Signature', 'Root', 'RPID', 'AAGUID']);
  });

  it('tags the algorithm, a discoverable credential and large blob support', () => {
    expect(card({ residentKey: true, largeBlob: true }).tags).toEqual(['ES256', 'Discoverable', 'Large blob']);
    expect(card({ residentKey: true, largeBlob: true }, { algorithmTag: '' }).tags).toEqual(['Discoverable', 'Large blob']);
    // No record says it is discoverable under any other name.
    expect(card({ discoverable: true }, { algorithmTag: '' }).tags).toEqual([]);
    expect(card({ residentKey: false }).tags).toEqual(['ES256']);
  });

  it('links to FIDO MDS only with an AAGUID and a valid root or known metadata', () => {
    expect(card({}).mdsAaguid).toBe('');
    expect(card({}, { indicators: { ...INDICATORS, rootStatus: true } }).mdsAaguid).toBe('f1d0f1d0-0000-4000-8000-000000000001');
    expect(card({}, { indicators: { ...INDICATORS, metadataAvailable: true } }).mdsAaguid).toBe('f1d0f1d0-0000-4000-8000-000000000001');
    expect(card({}, { indicators: { ...INDICATORS, rootStatus: true, aaguidGuid: '' } }).mdsAaguid).toBe('');
  });

  it('gives the credential id in base64url and hex, and the AAGUID dashed, in lower case', () => {
    const shown = card({ credentialId: 'AQIDBA==' });
    expect([shown.credentialId, shown.credentialIdHex, shown.aaguid]).toEqual([
      'AQIDBA',
      'b744',
      'f1d0f1d0-0000-4000-8000-000000000001',
    ]);
    const bare = card({}, { credentialIdHex: '', indicators: { ...INDICATORS, aaguidGuid: '' } });
    expect([bare.credentialId, bare.credentialIdHex, bare.aaguid, bare.aaguidUnreadable]).toEqual(['', '', '', '']);
  });

  it('gives a stored AAGUID no spelling reads as it is stored, and no FIDO MDS', () => {
    const shown = card({}, { indicators: { ...INDICATORS, rootStatus: true, aaguidGuid: '', aaguidUnreadable: 'abcde' } });
    expect([shown.aaguid, shown.aaguidUnreadable, shown.mdsAaguid]).toEqual(['', 'abcde', '']);
  });
});

describe('the rows', () => {
  it('give each record its key and what its card shows', () => {
    const [row] = describeCredentialRows([STORED]);
    expect(row).toMatchObject({
      key: `id:${STORED.credentialIdBase64Url}`,
      credential: STORED,
      name: STORED.userName,
      credentialIdHex: STORED.credentialIdHex,
      tags: ['ES256'],
    });
  });
});

describe('the key a flash after a ceremony matches a card by', () => {
  it('is the credential id in lower-case hex', () => {
    expect(credentialFlashKey(' AQID ')).toBe('010203');
    expect(credentialFlashKey('ABCDEF')).toBe('abcdef');
  });

  it('is empty for a value that is no credential id', () => {
    expect(credentialFlashKey(null)).toBe('');
    expect(credentialFlashKey('   ')).toBe('');
  });
});

describe('the warm-up after the list is drawn', () => {
  it('reads the list again when the sync changed something', async () => {
    vi.mocked(ensureAdvancedCredentialArtifactsSynced).mockResolvedValue(false);
    vi.mocked(ensureAdvancedCredentialSnapshotsPrefetched).mockResolvedValue(true);
    const reload = vi.fn();
    expect(await warmSavedCredentials(reload)).toBe(true);
    expect(reload).toHaveBeenCalledTimes(1);
  });

  it('leaves the list alone when nothing changed', async () => {
    vi.mocked(ensureAdvancedCredentialArtifactsSynced).mockResolvedValue(false);
    vi.mocked(ensureAdvancedCredentialSnapshotsPrefetched).mockResolvedValue(false);
    const reload = vi.fn();
    expect(await warmSavedCredentials(reload)).toBe(false);
    expect(reload).not.toHaveBeenCalled();
  });

  // The syncs never reject (each answers false when it cannot sync); what can fail is reading the list again.
  it('says nothing changed when the list cannot be read again', async () => {
    vi.mocked(ensureAdvancedCredentialArtifactsSynced).mockResolvedValue(true);
    vi.mocked(ensureAdvancedCredentialSnapshotsPrefetched).mockResolvedValue(false);
    const reload = vi.fn().mockRejectedValue(new Error('storage unreadable'));
    expect(await warmSavedCredentials(reload)).toBe(false);
    expect(reload).toHaveBeenCalledTimes(1);
  });
});
