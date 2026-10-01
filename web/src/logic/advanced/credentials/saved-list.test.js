import { afterEach, describe, expect, it, vi } from 'vitest';

import {
  CREDENTIAL_CHECKS,
  SAVED_LIST_TEXT,
  credentialFlashKey,
  credentialKey,
  describeCredentialCard,
  listSavedCredentials,
  warmSavedCredentials,
} from './saved-list.js';
import { goldenAnswers } from '@/test/logic/simple/ceremony-answers.js';

// The saved-credential list both tabs show (advanced/credentials/saved-list.js).

const STORED = goldenAnswers('simple-register-es256')[1].body.storedCredential;

const helpers = {
  normaliseAaguidValue: vi.fn((value) => (typeof value === 'string' ? value.replace(/-/g, '').toLowerCase() : '')),
  getCredentialIdHex: vi.fn(() => 'b744'),
  getCredentialUserHandleHex: vi.fn(() => '7573'),
};

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
});

describe('the records the list holds', () => {
  it('gives a simple record its type and its identifiers in hex', () => {
    const [record] = listSavedCredentials([{ ...STORED, type: 'simple' }], helpers);
    expect(record).toMatchObject({ type: 'simple', credentialIdHex: 'b744', userHandleHex: '7573', email: STORED.email });
  });

  it('gives an advanced record its storage ids and a normalised AAGUID', () => {
    const [record] = listSavedCredentials([{ type: 'advanced', storageId: 's-1', aaguid: 'F1D0-AA' }], helpers);
    expect(record).toMatchObject({ type: 'advanced', storageId: 's-1', localStorageId: 's-1', aaguidHex: 'f1d0aa' });
  });

  it('takes an advanced record\'s storage id from its local one, or has none', () => {
    const [local, none] = listSavedCredentials(
      [{ type: 'advanced', localStorageId: 'l-1' }, { type: 'advanced' }],
      helpers,
    );
    expect([local.storageId, local.localStorageId]).toEqual(['l-1', 'l-1']);
    expect([none.storageId, none.localStorageId, none.aaguidHex]).toEqual([null, null, null]);
  });

  it('takes an advanced record\'s AAGUID from its relying party when it has none of its own', () => {
    const [record] = listSavedCredentials([{ type: 'advanced', relyingParty: { aaguid: 'AB-CD' } }], helpers);
    expect(record.aaguidHex).toBe('abcd');
  });

  it('keeps an advanced record\'s AAGUID as stored when it does not normalise', () => {
    const [record] = listSavedCredentials([{ type: 'advanced', aaguidHex: 'not hex', relyingParty: 'none' }], {
      ...helpers,
      normaliseAaguidValue: () => '',
    });
    expect(record.aaguidHex).toBe('not hex');
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
    expect(card({ discoverable: true, largeBlobSupported: true }, { algorithmTag: '' }).tags).toEqual(['Discoverable', 'Large blob']);
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
    const reload = vi.fn();
    const changed = await warmSavedCredentials({ syncArtifacts: async () => false, prefetchSnapshots: async () => true, reload });
    expect(changed).toBe(true);
    expect(reload).toHaveBeenCalledTimes(1);
  });

  it('leaves the list alone when nothing changed', async () => {
    const reload = vi.fn();
    expect(await warmSavedCredentials({ syncArtifacts: async () => false, prefetchSnapshots: async () => false, reload })).toBe(false);
    expect(reload).not.toHaveBeenCalled();
  });

  it('changes nothing when warming up fails', async () => {
    const failure = new Error('offline');
    const changed = await warmSavedCredentials({
      syncArtifacts: async () => {
        throw failure;
      },
      prefetchSnapshots: async () => true,
      reload: vi.fn(),
    });
    expect(changed).toBe(false);
  });
});
