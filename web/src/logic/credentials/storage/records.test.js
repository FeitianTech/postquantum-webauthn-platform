import { beforeEach, describe, expect, it } from 'vitest';
import { getAllStoredCredentialsInOrder } from './records.js';
import { readUnifiedCredentialRecords, seedUnifiedCredentialRecords } from './local/storage-core.js';

const simple = { type: 'simple', credentialId: 'AQID', email: 'alice' };
const advanced = { type: 'advanced', credentialId: 'BAUG', storageId: 'BAUG::1::a' };

beforeEach(() => {
  window.localStorage.clear();
  seedUnifiedCredentialRecords(null);
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
