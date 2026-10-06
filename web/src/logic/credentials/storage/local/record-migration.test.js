import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { migrateStoredRecord } from './record-migration.js';
import { ADVANCED_RECORD, SIMPLE_RECORD } from '@/test/logic/credentials/storage/standard-base64-records.js';
import { bytesOf } from '@/test/logic/credentials/storage/bytes.js';
import { seedUnifiedCredentialRecords } from './storage-core.js';

const CREDENTIAL_ID = SIMPLE_RECORD.credentialIdBase64Url;

describe('migrateStoredRecord', () => {
  it('passes something that is not a record through unchanged', () => {
    expect(migrateStoredRecord(null)).toEqual({ record: null, changed: false });
  });

  it('keeps a byte field that does not decode as base64, such as a user handle saved as text', () => {
    const record = { type: 'simple', credentialId: CREDENTIAL_ID, userHandle: 'user+tag@example.com' };

    const migrated = migrateStoredRecord(record);

    expect(migrated.changed).toBe(false);
    expect(migrated.record).toBe(record);
  });

  it('re-spells the signature of a self-attestation statement, which has no certificate chain', () => {
    const record = {
      type: 'simple',
      credentialId: CREDENTIAL_ID,
      attestationStatement: { alg: -7, sig: SIMPLE_RECORD.attestationStatement.sig },
    };

    const { record: migrated } = migrateStoredRecord(record);

    expect(migrated.attestationStatement).toEqual({
      alg: -7,
      sig: 'MEQCIEZ1L8aEroaidBeW3olMX7L40gXum3cwIP6C-67xSoESAiBxs1BzKjh71rsPpurSuC7YIK0YihBJwK2WcNQo-U0EYw',
    });
  });
});


describe("stored credentials: base64", () => {
  beforeEach(() => {
    window.localStorage.clear();
    seedUnifiedCredentialRecords([]);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("are read back in base64url, holding the same bytes", async () => {

    const simple = migrateStoredRecord(SIMPLE_RECORD).record;
    const advanced = migrateStoredRecord(ADVANCED_RECORD).record;
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

  it("keep fields named for base64, extension outputs and text as they were", async () => {
    const statement = { ...SIMPLE_RECORD.attestationStatement, ver: '2.0' };

    const simple = migrateStoredRecord({ ...SIMPLE_RECORD, attestationStatement: statement }).record;
    const advanced = migrateStoredRecord(ADVANCED_RECORD).record;
    expect(simple.attestationStatement.ver).toBe('2.0');
    expect(simple.attestationStatement.alg).toBe(-7);
    expect(simple.publicKeyCose['-1']).toBe(1);
    expect(simple.clientExtensionOutputs).toEqual(SIMPLE_RECORD.clientExtensionOutputs);
    expect(advanced.publicKeyBase64).toBe(ADVANCED_RECORD.publicKeyBase64);
    expect(advanced.userHandleBase64).toBe(ADVANCED_RECORD.userHandleBase64);
    expect(advanced.credentialIdHex).toBe(ADVANCED_RECORD.credentialIdHex);
  });
});
