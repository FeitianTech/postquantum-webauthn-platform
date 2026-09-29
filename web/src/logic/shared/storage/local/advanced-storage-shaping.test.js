import { beforeEach, describe, expect, it } from 'vitest';

import {
  cloneAdvancedCredential,
  cloneAdvancedStoredRecord,
  prepareAdvancedCredentialForStorage,
  pruneAdvancedCredentialPayload,
  readAdvancedCredentialPartitions,
  recordHasHeavyData,
  summariseAdvancedCredentialForLocal,
} from './advanced-storage-shaping.js';
import { seedUnifiedCredentialRecords } from './storage-core.js';

const SHARED_STORAGE_KEY = 'postquantum-webauthn.credentials';
const CREDENTIAL_ID = 'THBi3GyG-MexchMynbz3x5NvGe5iGSPJDYpBGvL7i9Y';

// The registration as data, as the advanced tab records it (schemaVersion 2).
function registrationSnapshot() {
  return {
    schemaVersion: 2,
    capturedAt: '2026-09-21T14:13:20Z',
    state: { authenticatorDataHex: '49960de5880e8c687434170f6476605b' },
  };
}

function advancedRecord(overrides = {}) {
  return {
    type: 'advanced',
    credentialId: CREDENTIAL_ID,
    credentialIdBase64Url: CREDENTIAL_ID,
    storageId: `${CREDENTIAL_ID}::1a0c4506c00::abb1b052`,
    userName: 'alice',
    signCount: 7,
    ...overrides,
  };
}

describe('summariseAdvancedCredentialForLocal', () => {
  it('summarises nothing when given no record', () => {
    expect(summariseAdvancedCredentialForLocal(null, 'storage-1')).toBeNull();
  });

  it('keeps a registration snapshot that still holds the registration', () => {
    const summary = summariseAdvancedCredentialForLocal(
      advancedRecord({ registrationDetailSnapshot: registrationSnapshot() }),
      'storage-1',
    );

    expect(summary.registrationDetailSnapshot).toEqual(registrationSnapshot());
  });

  it('drops properties that held only the attestation certificates', () => {
    const summary = summariseAdvancedCredentialForLocal(
      advancedRecord({ properties: { attestationCertificates: [{ subject: 'CN=Batch' }] } }),
      'storage-1',
    );

    expect(summary).not.toHaveProperty('properties');
  });

  it('drops a relying-party view that held only registration data', () => {
    const summary = summariseAdvancedCredentialForLocal(
      advancedRecord({ relyingParty: { registrationData: { clientDataJSON: 'eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0' } } }),
      'storage-1',
    );

    expect(summary).not.toHaveProperty('relyingParty');
  });

  it("keeps the record's own storage id when given a blank one", () => {
    const record = advancedRecord();

    const summary = summariseAdvancedCredentialForLocal(record, '   ');

    expect(summary.storageId).toBe(record.storageId);
    expect(summary).not.toHaveProperty('localStorageId');
  });
});

describe('recordHasHeavyData', () => {
  it.each([
    ['no record', null, false],
    ['a summary with nothing heavy', advancedRecord(), false],
    ['attestation checks in the properties', advancedRecord({ properties: { attestationChecks: { errors: [] } } }), true],
    [
      'certificates in the relying-party view',
      advancedRecord({ properties: { residentKey: false }, relyingParty: { attestationCertificates: [] } }),
      true,
    ],
    [
      'light properties and a light relying-party view',
      advancedRecord({ properties: { residentKey: false }, relyingParty: { attestationFmt: 'none' } }),
      false,
    ],
  ])('finds heavy data only where it is: %s', (_label, record, expected) => {
    expect(recordHasHeavyData(record)).toBe(expected);
  });
});

describe('cloning advanced records', () => {
  it('clones nothing from something that is not a record', () => {
    expect(cloneAdvancedCredential(null)).toBeNull();
    expect(cloneAdvancedStoredRecord('advanced')).toBeNull();
  });

  it('types a stored record without a type as advanced', () => {
    const clone = cloneAdvancedStoredRecord({ credentialId: CREDENTIAL_ID, storageId: 'storage-1' });

    expect(clone).toEqual({ type: 'advanced', credentialId: CREDENTIAL_ID, storageId: 'storage-1' });
  });
});

describe('pruneAdvancedCredentialPayload', () => {
  it('leaves nothing to prune when given no record', () => {
    expect(() => pruneAdvancedCredentialPayload(null)).not.toThrow();
  });

  it('keeps the registration snapshot, sanitised', () => {
    const record = advancedRecord({
      registrationDetailSnapshot: { ...registrationSnapshot(), html: '<section>old markup</section>' },
    });

    pruneAdvancedCredentialPayload(record);

    expect(record.registrationDetailSnapshot).toEqual(registrationSnapshot());
  });

  it('drops a snapshot that holds only markup', () => {
    const record = advancedRecord({ registrationDetailSnapshot: { html: '<section>old markup</section>' } });

    pruneAdvancedCredentialPayload(record);

    expect(record).not.toHaveProperty('registrationDetailSnapshot');
  });

  it('keeps the state of a snapshot that does not serialise as JSON', () => {
    const snapshot = registrationSnapshot();
    snapshot.self = snapshot;
    const record = advancedRecord({ registrationDetailSnapshot: snapshot });

    pruneAdvancedCredentialPayload(record);

    expect(record.registrationDetailSnapshot).toEqual(registrationSnapshot());
  });

  it('drops the attestation statement and the registration response when aggressive', () => {
    const record = advancedRecord({
      attestationStatement: { alg: -7, sig: 'MEUCIQ' },
      registrationResponse: { id: CREDENTIAL_ID, type: 'public-key' },
      attestationFormat: 'packed',
    });

    pruneAdvancedCredentialPayload(record, { aggressive: true });

    expect(record).not.toHaveProperty('attestationStatement');
    expect(record).not.toHaveProperty('registrationResponse');
    expect(record.attestationFormat).toBe('packed');
  });
});

describe('prepareAdvancedCredentialForStorage', () => {
  it('prepares nothing from something that is not a record', () => {
    expect(prepareAdvancedCredentialForStorage(undefined)).toBeNull();
  });
});

describe('readAdvancedCredentialPartitions', () => {
  beforeEach(() => {
    window.localStorage.clear();
    seedUnifiedCredentialRecords(null);
  });

  it('gives a stored advanced record without a storage id one, and saves it', () => {
    const { storageId: _none, ...withoutStorageId } = advancedRecord();
    window.localStorage.setItem(SHARED_STORAGE_KEY, JSON.stringify([withoutStorageId]));

    const { advancedRecords } = readAdvancedCredentialPartitions();

    const saved = JSON.parse(window.localStorage.getItem(SHARED_STORAGE_KEY));
    expect(advancedRecords[0].storageId).toMatch(new RegExp(`^${CREDENTIAL_ID}::`));
    expect(saved.map(record => record.storageId)).toEqual([advancedRecords[0].storageId]);
  });
});
