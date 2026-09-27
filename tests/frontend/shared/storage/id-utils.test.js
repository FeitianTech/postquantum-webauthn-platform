import { afterEach, describe, expect, it, vi } from 'vitest';

import {
  buildRecordKey,
  ensureAdvancedCredentialStorageId,
  ensureRecordType,
  generateRandomIdSegment,
  getRecordIdentifier,
  normaliseAdvancedCredentialId,
  normaliseCredentialId,
} from '../../../../frontend/static/scripts/shared/storage/local/id-utils.js';
import { ADVANCED_RECORD } from './pre-phase-23-records.js';

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

describe('generateRandomIdSegment', () => {
  it('uses Math.random where crypto has no randomUUID, as in an insecure context', () => {
    vi.stubGlobal('crypto', {});
    vi.spyOn(Math, 'random').mockReturnValueOnce(0.5).mockReturnValueOnce(0.25);

    expect(generateRandomIdSegment()).toBe('i9');
  });
});

describe('ensureAdvancedCredentialStorageId', () => {
  it('gives nothing for a record that is not an object', () => {
    expect(ensureAdvancedCredentialStorageId('AQID')).toBe('');
  });

  it('replaces the saved storage id when asked for a new one', () => {
    vi.stubGlobal('crypto', { randomUUID: () => UUID });
    const record = { credentialId: CREDENTIAL_ID, createdAt: '2026-09-25T00:00:00Z', storageId: 'old::id' };

    const storageId = ensureAdvancedCredentialStorageId(record, { forceNew: true });

    expect(storageId).toBe(`${CREDENTIAL_ID}::2026-09-25T00:00:00Z::${UUID}`);
    expect(record.storageId).toBe(storageId);
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
