import { describe, expect, it } from 'vitest';

import { migrateStoredRecord } from './record-migration.js';
import { SIMPLE_RECORD } from '@/test/logic/shared/storage/pre-phase-23-records.js';

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
