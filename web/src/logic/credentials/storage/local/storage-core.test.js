import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { followStoredCredentialChanges, persistStoredCredentials, persistUnifiedCredentialRecords, readStoredCredentials, readUnifiedCredentialRecords, seedUnifiedCredentialRecords } from './storage-core.js';
import { getAllStoredCredentialsInOrder } from '../records.js';
import { SIMPLE_RECORD } from '@/test/logic/credentials/storage/standard-base64-records.js';

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

  it('follows no other tab', () => {
    vi.stubGlobal('window', undefined);
    const stop = followStoredCredentialChanges(() => {});
    expect(stop()).toBeUndefined();
  });
});

describe('another tab\'s changes', () => {
  // What the browser does when another page of this origin writes: this page's
  // storage already holds the other tab's value, and a storage event says which key.
  function anotherTabSaves(key, records) {
    if (records === null) window.localStorage.clear();
    else window.localStorage.setItem(key, JSON.stringify(records));
    window.dispatchEvent(new StorageEvent('storage', { key }));
  }

  it('reads the browser\'s storage again after another tab saves, and says so', () => {
    persistUnifiedCredentialRecords([simple]);
    const changed = vi.fn();
    const stop = followStoredCredentialChanges(changed);

    anotherTabSaves(SHARED, [simple, advanced]);

    expect(changed).toHaveBeenCalledTimes(1);
    expect(readUnifiedCredentialRecords().map((record) => record.credentialId)).toEqual(['AQID', 'BAUG']);
    stop();
  });

  it('follows the old keys and a cleared storage too', () => {
    const changed = vi.fn();
    const stop = followStoredCredentialChanges(changed);

    anotherTabSaves(LEGACY_SIMPLE, [{ credentialId: 'AQID' }]);
    anotherTabSaves(LEGACY_ADVANCED, [{ credentialId: 'BAUG' }]);
    anotherTabSaves(null, null);

    expect(changed).toHaveBeenCalledTimes(3);
    expect(readUnifiedCredentialRecords()).toEqual([]);
    stop();
  });

  it('keeps what it read when another key changes, and stops when told', () => {
    persistUnifiedCredentialRecords([simple]);
    const changed = vi.fn();
    const stop = followStoredCredentialChanges(changed);

    anotherTabSaves('something-else', [advanced]);
    window.localStorage.setItem(SHARED, JSON.stringify([advanced]));
    expect(readUnifiedCredentialRecords()).toEqual([simple]);

    stop();
    anotherTabSaves(SHARED, [advanced]);
    expect(changed).not.toHaveBeenCalled();
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


describe("stored credentials: simple", () => {
  beforeEach(() => {
    window.localStorage.clear();
    seedUnifiedCredentialRecords([]);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("filters non-record values from seeded credentials", async () => {
    seedUnifiedCredentialRecords([
          null,
          'not-an-object',
          {
            type: 'simple',
            credentialId: 'boot-simple',
            email: 'boot@example.com',
            publicKey: 'cHVibGlj',
          },
          {
            type: 'advanced',
            credentialId: 'boot-advanced',
            storageId: 'boot-advanced::storage',
            publicKey: 'cHVibGlj',
          },
        ]);
    const ordered = readUnifiedCredentialRecords();
    expect(ordered).toHaveLength(2);
  });
});


describe("stored credentials: keys", () => {
  const SHARED_STORAGE_KEY = 'postquantum-webauthn.credentials';
  beforeEach(() => {
    window.localStorage.clear();
    seedUnifiedCredentialRecords([]);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("migrates legacy storage keys into unified records and removes legacy keys", async () => {
    seedUnifiedCredentialRecords(null);
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
    const ordered = readUnifiedCredentialRecords();
    expect(ordered).toHaveLength(2);
    expect(ordered.find((record) => record.type === 'simple')?.credentialId).toBe('simple-legacy');
    expect(ordered.find((record) => record.type === 'advanced')?.credentialId).toBe('advanced-legacy');
    expect(localStorage.getItem('postquantum-webauthn.simpleCredentials')).toBeNull();
    expect(localStorage.getItem('postquantum-webauthn.advancedCredentials')).toBeNull();
    const unified = JSON.parse(localStorage.getItem(SHARED_STORAGE_KEY));
    expect(unified).toHaveLength(2);
  });
});


describe("stored credentials: base64", () => {
  const SHARED_STORAGE_KEY = 'postquantum-webauthn.credentials';
  beforeEach(() => {
    window.localStorage.clear();
    seedUnifiedCredentialRecords([]);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("are saved once in the new spelling, and read again without another save", async () => {
    localStorage.setItem(SHARED_STORAGE_KEY, JSON.stringify([SIMPLE_RECORD]));
    seedUnifiedCredentialRecords(null);
    const setItem = vi.spyOn(window.localStorage, 'setItem');
    readUnifiedCredentialRecords();
    const [saved] = JSON.parse(localStorage.getItem(SHARED_STORAGE_KEY));
    expect(saved.publicKey).toBe(SIMPLE_RECORD.publicKeyBase64Url);
    vi.resetModules();
    const again = await import('./storage-core.js');
    setItem.mockClear();
    again.readUnifiedCredentialRecords();
    expect(setItem).not.toHaveBeenCalled();
    setItem.mockRestore();
  });
});
