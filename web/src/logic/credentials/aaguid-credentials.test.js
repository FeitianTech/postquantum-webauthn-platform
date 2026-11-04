import { describe, expect, it } from 'vitest';

import { credentialsWithAaguid } from './aaguid-credentials.js';
import { describeCredentialRows } from './saved-list.js';

// The saved credentials an MDS entry lists (credentials/aaguid-credentials.js).

const ENTRY = 'f1d0f1d0-0000-4000-8000-000000000001';

/** The saved list's rows for records each keeping the AAGUID in one spelling. */
function rows(...records) {
  return describeCredentialRows(records.map((record, index) => ({ type: 'simple', credentialId: `AQI${index}`, userName: `user${index}`, ...record })));
}

describe('credentialsWithAaguid', () => {
  it('lists the rows whose AAGUID reads as the entry\'s, whatever spelling the record keeps, in the list\'s order', () => {
    const list = rows(
      { aaguidHex: 'f1d0f1d0000040008000000000000001' },
      { aaguid: '8dDx0AAAQACAAAAAAAAAAQ' },
      { aaguidHex: 'f1d0f1d0000040008000000000000002' },
      { aaguidGuid: 'F1D0F1D0-0000-4000-8000-000000000001' },
    );
    expect(credentialsWithAaguid(list, ENTRY).map(({ name }) => name)).toEqual(['user0', 'user1', 'user3']);
  });

  it('reads the entry\'s AAGUID in its other spellings too', () => {
    const list = rows({ aaguidHex: 'f1d0f1d0000040008000000000000001' });
    expect(credentialsWithAaguid(list, 'F1D0F1D0000040008000000000000001')).toHaveLength(1);
  });

  it('lists none for an entry without an AAGUID, and none of the rows without one', () => {
    const list = rows({}, { aaguid: 'abcde' });
    expect(credentialsWithAaguid(list, '')).toEqual([]);
    expect(credentialsWithAaguid(list, undefined)).toEqual([]);
    expect(credentialsWithAaguid(list, 'f1d0')).toEqual([]);
    expect(credentialsWithAaguid(list, ENTRY)).toEqual([]);
  });
});
