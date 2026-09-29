import { describe, expect, it } from 'vitest';

import { MAX_SNAPSHOT_RESPONSE_LENGTH } from './constants.js';
import { sanitiseRegistrationDetailSnapshot } from './snapshot-sanitize.js';

const CREDENTIAL = {
  id: 'AQID',
  rawId: 'AQID',
  type: 'public-key',
  response: { clientDataJSON: 'eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0', attestationObject: 'o2NmbXRkbm9uZQ' },
};

describe('registration snapshot sanitising', () => {
  it('keeps the registration response and the relying party view as data', () => {
    const snapshot = sanitiseRegistrationDetailSnapshot({
      schemaVersion: 2,
      capturedAt: '2026-09-25T00:00:00.000Z',
      state: { authenticatorDataHex: '0a0b' },
      response: { credential: CREDENTIAL, relyingParty: { rpName: 'Example' } },
    });

    expect(snapshot).toEqual({
      schemaVersion: 2,
      capturedAt: '2026-09-25T00:00:00.000Z',
      state: { authenticatorDataHex: '0a0b' },
      response: { credential: CREDENTIAL, relyingParty: { rpName: 'Example' } },
    });
  });

  it('keeps a detail preparation\'s values, and none it lacks', () => {
    const snapshot = sanitiseRegistrationDetailSnapshot({
      schemaVersion: 2,
      state: { detailPreparation: { authenticatorDataValue: 'SZYN5YgO' } },
    });

    expect(snapshot.state.detailPreparation).toEqual({
      attestationObjectValue: '',
      attestationDecodeError: '',
      authenticatorDataValue: 'SZYN5YgO',
      authenticatorDecodeError: '',
    });
  });

  it('leaves out a part that is too long instead of cutting it', () => {
    const long = 'A'.repeat(MAX_SNAPSHOT_RESPONSE_LENGTH);
    const snapshot = sanitiseRegistrationDetailSnapshot({
      schemaVersion: 2,
      response: {
        credential: { ...CREDENTIAL, response: { attestationObject: long } },
        relyingParty: { rpName: 'Example' },
      },
    });

    expect(snapshot.response).toEqual({ relyingParty: { rpName: 'Example' } });
  });

  it('keeps no response part that is not an object', () => {
    const snapshot = sanitiseRegistrationDetailSnapshot({
      schemaVersion: 2,
      state: { authenticatorDataHex: '0a0b' },
      response: { credential: 'AQID', relyingParty: [1, 2] },
    });

    expect(snapshot.response).toBeUndefined();
    expect(sanitiseRegistrationDetailSnapshot({ response: null })).toBeNull();
  });
});
