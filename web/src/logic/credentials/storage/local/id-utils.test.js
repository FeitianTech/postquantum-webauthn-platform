import { afterEach, describe, expect, it, vi } from 'vitest';

import {
  buildRecordKey,
  ensureAdvancedCredentialStorageId,
  ensureBase64Url,
  ensureRecordType,
  getRecordIdentifier,
  normaliseAdvancedCredentialId,
  normaliseCredentialId,
} from './id-utils.js';
import { ADVANCED_RECORD } from '@/test/logic/credentials/storage/standard-base64-records.js';

const CREDENTIAL_ID = ADVANCED_RECORD.credentialIdBase64Url;
const UUID = '1b4e28ba-2fa1-41d2-883f-0016d3cca427';

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe('normaliseCredentialId', () => {
  it('reads nothing from a missing record', () => {
    expect(normaliseCredentialId(null)).toBe('');
  });

  it('falls back to the credential JSON id when no credential id was saved', () => {
    expect(normaliseCredentialId({ id: CREDENTIAL_ID, type: 'public-key' })).toBe(CREDENTIAL_ID);
  });
});

describe('normaliseAdvancedCredentialId', () => {
  it('reads nothing from a missing record', () => {
    expect(normaliseAdvancedCredentialId(undefined)).toBe('');
  });
});

describe('ensureAdvancedCredentialStorageId', () => {
  it('gives nothing for a record that is not an object', () => {
    expect(ensureAdvancedCredentialStorageId('AQID')).toBe('');
  });

  it('builds a missing storage id from the credential id, the time and a random segment', () => {
    vi.stubGlobal('crypto', { randomUUID: () => UUID });
    vi.spyOn(Date, 'now').mockReturnValue(1790631838901);
    const record = { credentialId: CREDENTIAL_ID, createdAt: 1790631838.9 };

    const storageId = ensureAdvancedCredentialStorageId(record);

    expect(storageId).toBe(`${CREDENTIAL_ID}::mulrypit::${UUID}`);
    expect(record.storageId).toBe(storageId);
  });

  it('keeps a saved storage id, trimmed', () => {
    const record = { credentialId: CREDENTIAL_ID, storageId: ' saved::id ' };

    expect(ensureAdvancedCredentialStorageId(record)).toBe('saved::id');
    expect(record.storageId).toBe('saved::id');
  });
});

describe('ensureRecordType', () => {
  it('gives null for a record that is not an object', () => {
    expect(ensureRecordType(null)).toBeNull();
  });
});

describe('getRecordIdentifier', () => {
  it('gives nothing for a record that is not an object', () => {
    expect(getRecordIdentifier(undefined)).toBe('');
  });

  it('names a record by a whitespace-only credential id rather than by nothing', () => {
    expect(getRecordIdentifier({ credentialId: '  ' })).toBe('id:  ');
  });
});

describe('buildRecordKey', () => {
  it('gives no key for a record that is not an object', () => {
    expect(buildRecordKey(null)).toBe('');
  });

  it('generates a key for a record with no identifier', () => {
    vi.stubGlobal('crypto', { randomUUID: () => UUID });

    expect(buildRecordKey({ type: 'advanced', userName: 'user@example.com' })).toBe(`advanced:generated:${UUID}`);
  });
});

describe('ensureBase64Url', () => {
  it.each([
    ['base64url, as it is', 'FPhff9VVh1_mDEjMl0iusO-dKpqIUox-_4tcBas7neE', 'FPhff9VVh1_mDEjMl0iusO-dKpqIUox-_4tcBas7neE'],
    ['standard base64, re-spelled', 'FPhff9VVh1/mDEjMl0iusO+dKpqIUox+/4tcBas7neE=', 'FPhff9VVh1_mDEjMl0iusO-dKpqIUox-_4tcBas7neE'],
    ['nothing, as empty', '   ', ''],
    ['not a string, as empty', 42, ''],
  ])('takes %s', (_label, value, expected) => {
    expect(ensureBase64Url(value)).toBe(expected);
  });

  it('keeps text that is neither base64 nor hex as written', () => {
    expect(ensureBase64Url('not base64!')).toBe('not base64!');
  });

  it('refuses standard base64 whose last character carries stray bits', () => {
    // atob() read "Zh==" as "f"; the strict decoder does not, and it is not hex.
    expect(ensureBase64Url('Zh==')).toBe('Zh==');
  });
});
