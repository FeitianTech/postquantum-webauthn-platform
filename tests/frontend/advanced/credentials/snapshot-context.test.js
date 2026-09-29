import { afterEach, describe, expect, it } from 'vitest';

import {
  readSnapshotResponse,
  resolveRegistrationSnapshotContext,
} from '../../../../frontend/static/scripts/advanced/credential-display/credential-detail-runtime/snapshot-context.js';
import {
  EMPTY_DETAIL_PREPARATION,
  captureRegistrationState,
  createRegistrationState,
  prepareRegistrationState,
  resetRegistrationState,
} from '../../../../frontend/static/scripts/advanced/credential-display/registration-state.js';
import { sanitizeRelyingPartyInfo } from '../../../../frontend/static/scripts/advanced/credential-display/sanitize-common.js';
import { registrationDetailState } from '../../../../frontend/static/scripts/advanced/credential-display/state.js';
import { goldenDecode, registration } from './registration-detail-answers.js';

// A saved registration snapshot read back (credential-detail-runtime/snapshot-context.js).

/**
 * The snapshot the registration view saves for a registration (schemaVersion 2):
 * its state as data, and the browser's response with the relying party's view.
 */
async function savedSnapshot(name = 'packedX5c') {
  const entry = registration(name);
  const state = createRegistrationState();
  const preparation = await prepareRegistrationState(state, {
    attestationObjectValue: entry.attestationObject,
    authenticatorDataValue: entry.authenticatorData,
  }, { decode: goldenDecode(entry) });
  return {
    entry,
    state,
    preparation,
    snapshot: {
      schemaVersion: 2,
      capturedAt: '2026-09-21T14:13:20.000Z',
      state: captureRegistrationState(state, preparation),
      response: {
        credential: entry.storedCredential.registrationResponse,
        relyingParty: sanitizeRelyingPartyInfo(entry.relyingParty, {
          authenticatorDataHex: state.authenticatorDataHex,
          authenticatorDataHash: state.authenticatorDataHash,
        }),
      },
    },
  };
}

afterEach(() => {
  resetRegistrationState(registrationDetailState);
});

describe('readSnapshotResponse', () => {
  it('reads the response a version 2 snapshot keeps', async () => {
    const { snapshot } = await savedSnapshot();
    expect(readSnapshotResponse(snapshot)).toEqual(snapshot.response);
  });

  it('reads a response that kept only one of its parts', async () => {
    const { snapshot } = await savedSnapshot();
    const { credential, relyingParty } = snapshot.response;
    expect(readSnapshotResponse({ schemaVersion: '2', response: { credential, relyingParty: 'none' } }))
      .toEqual({ credential, relyingParty: null });
    expect(readSnapshotResponse({ schemaVersion: 3, response: { relyingParty } }))
      .toEqual({ credential: null, relyingParty });
  });

  it('has no response for an older snapshot', async () => {
    const { snapshot } = await savedSnapshot();
    expect(readSnapshotResponse({ ...snapshot, schemaVersion: 1 })).toBeNull();
    expect(readSnapshotResponse({ response: snapshot.response })).toBeNull();
  });

  it('has no response without a snapshot', () => {
    expect(readSnapshotResponse(null)).toBeNull();
    expect(readSnapshotResponse('snapshot')).toBeNull();
  });

  it('has no response for a snapshot that kept none', () => {
    expect(readSnapshotResponse({ schemaVersion: 2 })).toBeNull();
    expect(readSnapshotResponse({ schemaVersion: 2, response: 'response' })).toBeNull();
    expect(readSnapshotResponse({ schemaVersion: 2, response: { credential: 'AQID', relyingParty: 5 } })).toBeNull();
  });
});

describe('resolveRegistrationSnapshotContext', () => {
  it('applies a saved snapshot to the state it is given', async () => {
    const { snapshot, state, preparation } = await savedSnapshot();
    const target = createRegistrationState();
    const context = resolveRegistrationSnapshotContext({ registrationDetailSnapshot: snapshot }, target);
    expect(context).toEqual({
      detailPreparation: preparation,
      snapshotState: snapshot.state,
      snapshotResponse: snapshot.response,
    });
    expect(context.snapshotState).toBe(snapshot.state);
    expect(target).toEqual({ ...state, visibleAttestationCertificateIndices: [0] });
  });

  it("applies it to the current interface's state by default", async () => {
    const { snapshot, state } = await savedSnapshot();
    resolveRegistrationSnapshotContext({ registrationDetailSnapshot: snapshot });
    expect(registrationDetailState.attestationObject).toEqual(state.attestationObject);
  });

  it('finds the snapshot under each name records have used', async () => {
    const { snapshot } = await savedSnapshot('es256');
    for (const key of ['registration_detail_snapshot', 'registrationDetailCopy', 'registration_detail_copy']) {
      const context = resolveRegistrationSnapshotContext({ registrationDetailSnapshot: 'markup', [key]: snapshot }, createRegistrationState());
      expect(context.snapshotState).toBe(snapshot.state);
    }
  });

  it('reads a snapshot that is its own state', async () => {
    const { snapshot, preparation } = await savedSnapshot('es256');
    const context = resolveRegistrationSnapshotContext({ registrationDetailSnapshot: snapshot.state }, createRegistrationState());
    expect(context).toEqual({ detailPreparation: preparation, snapshotState: snapshot.state, snapshotResponse: null });
  });

  it('gives empty sentences for a snapshot that kept none', () => {
    const context = resolveRegistrationSnapshotContext({ registrationDetailSnapshot: { schemaVersion: 2 } }, createRegistrationState());
    expect(context.detailPreparation).toEqual(EMPTY_DETAIL_PREPARATION);
  });

  it('has nothing for a record without a snapshot, and leaves the state alone', () => {
    const target = createRegistrationState();
    expect(resolveRegistrationSnapshotContext({ registrationDetailHtml: '<div></div>' }, target)).toEqual({
      detailPreparation: null,
      snapshotState: null,
      snapshotResponse: null,
    });
    expect(target).toEqual(createRegistrationState());
  });
});
