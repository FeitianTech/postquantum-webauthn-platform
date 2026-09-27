import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import {
  persistStoredCredentials,
  persistUnifiedCredentialRecords,
  readStoredCredentials,
  readUnifiedCredentialRecords,
  seedUnifiedCredentialRecords,
} from '../../../../frontend/static/scripts/shared/storage/local/storage-core.js';
import { getAllStoredCredentialsInOrder } from '../../../../frontend/static/scripts/shared/storage/records.js';

// The one read and write of the saved credentials both interfaces share
// (local/storage-core.js) and the ordered list they show (records.js), over the
// browser's storage: this module reads no page, so nothing is seeded here.

const SHARED = 'postquantum-webauthn.credentials';
const LEGACY_SIMPLE = 'postquantum-webauthn.simpleCredentials';
const LEGACY_ADVANCED = 'postquantum-webauthn.advancedCredentials';

const simple = { type: 'simple', credentialId: 'AQID', email: 'alice' };
const advanced = { type: 'advanced', credentialId: 'BAUG', storageId: 'BAUG::1::a' };

beforeEach(() => {
  window.localStorage.clear();
  seedUnifiedCredentialRecords(null);
});

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe('reading the saved credentials', () => {
  it('reads the browser\'s storage when nothing is seeded, and then keeps what it read', () => {
    window.localStorage.setItem(SHARED, JSON.stringify([simple]));
    expect(readUnifiedCredentialRecords()).toEqual([simple]);

    window.localStorage.setItem(SHARED, JSON.stringify([]));
    expect(readUnifiedCredentialRecords()).toEqual([simple]);
  });

  it('reads the seeded records instead of the browser\'s storage, and only the objects among them', () => {
    window.localStorage.setItem(SHARED, JSON.stringify([simple]));
    seedUnifiedCredentialRecords([advanced, 'not a record', null]);
    expect(readUnifiedCredentialRecords()).toEqual([advanced]);
  });

  it('reads the browser\'s storage again once the seed is taken away', () => {
    seedUnifiedCredentialRecords([advanced]);
    seedUnifiedCredentialRecords(null);
    window.localStorage.setItem(SHARED, JSON.stringify([simple]));
    expect(readUnifiedCredentialRecords()).toEqual([simple]);
  });

  it('leaves out a record without an identifier and a second copy of one', () => {
    window.localStorage.setItem(SHARED, JSON.stringify([{ type: 'simple', email: 'bob' }, simple, { ...simple }]));
    expect(readUnifiedCredentialRecords()).toEqual([simple]);
  });

  it('reads nothing when the browser refuses to read its storage', () => {
    vi.spyOn(window.localStorage, 'getItem').mockImplementation(() => {
      throw new DOMException('denied', 'SecurityError');
    });
    expect(readStoredCredentials(SHARED)).toEqual([]);
  });

  it('merges the old keys\' records in, typed by the key, and saves them under the one key', () => {
    window.localStorage.setItem(LEGACY_ADVANCED, JSON.stringify([{ credentialId: 'BAUG', storageId: 'BAUG::1::a' }]));
    window.localStorage.setItem(LEGACY_SIMPLE, JSON.stringify([{ credentialId: 'AQID', email: 'alice' }]));

    expect(readUnifiedCredentialRecords()).toEqual([advanced, simple]);
    expect(JSON.parse(window.localStorage.getItem(SHARED))).toEqual([advanced, simple]);
    expect(window.localStorage.getItem(LEGACY_SIMPLE)).toBeNull();
    expect(window.localStorage.getItem(LEGACY_ADVANCED)).toBeNull();
  });
});

describe('saving the saved credentials', () => {
  it('saves only objects, and reads back what it saved without the browser\'s storage', () => {
    expect(persistUnifiedCredentialRecords([simple, 7])).toBe(true);
    expect(JSON.parse(window.localStorage.getItem(SHARED))).toEqual([simple]);

    window.localStorage.clear();
    expect(readUnifiedCredentialRecords()).toEqual([simple]);
  });

  it('saves an empty list for something that is not a list', () => {
    expect(persistUnifiedCredentialRecords('records')).toBe(true);
    expect(window.localStorage.getItem(SHARED)).toBe('[]');
  });

  it('says so when the browser refuses the write, and keeps the old keys and what it had read', () => {
    window.localStorage.setItem(LEGACY_SIMPLE, JSON.stringify([simple]));
    seedUnifiedCredentialRecords([advanced]);
    vi.spyOn(window.localStorage, 'setItem').mockImplementation(() => {
      throw new DOMException('full', 'QuotaExceededError');
    });

    expect(persistStoredCredentials(SHARED, [simple])).toBe(false);
    expect(persistUnifiedCredentialRecords([simple])).toBe(false);
    expect(window.localStorage.getItem(LEGACY_SIMPLE)).not.toBeNull();
    expect(readUnifiedCredentialRecords()).toEqual([advanced]);
  });

  it('saves even when the browser refuses to remove the old keys', () => {
    vi.spyOn(window.localStorage, 'removeItem').mockImplementation(() => {
      throw new DOMException('denied', 'SecurityError');
    });
    expect(persistUnifiedCredentialRecords([simple])).toBe(true);
    expect(JSON.parse(window.localStorage.getItem(SHARED))).toEqual([simple]);
  });
});

describe('without a window', () => {
  // The new UI's pages are rendered once at build time, in Node, where there is
  // no browser storage: nothing is read or written.
  it('reads nothing and saves nothing', () => {
    vi.stubGlobal('window', undefined);
    expect(readStoredCredentials(SHARED)).toEqual([]);
    expect(persistStoredCredentials(SHARED, [])).toBe(false);
    expect(persistUnifiedCredentialRecords([simple])).toBe(false);
  });
});

describe('the ordered list both interfaces show', () => {
  it('lists every record in the order stored, as copies', () => {
    seedUnifiedCredentialRecords([advanced, simple]);
    const [first, second] = getAllStoredCredentialsInOrder();

    expect(first).toMatchObject(advanced);
    expect(second).toEqual(simple);
    second.email = 'changed';
    expect(readUnifiedCredentialRecords()[1].email).toBe('alice');
  });

  it('lists nothing when nothing is saved', () => {
    expect(getAllStoredCredentialsInOrder()).toEqual([]);
  });
});
