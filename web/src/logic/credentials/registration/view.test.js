import { afterEach, describe, expect, it, vi } from 'vitest';

import {
  composeRegistration,
  registrationResultInput,
  registrationSnapshotPayload,
} from './view.js';
import {
  REGISTRATION_TEXT,
  describeAttestationCertificate,
  describeAuthenticatorData,
} from './describe.js';
import { createRegistrationState } from './state.js';
import { sanitiseRegistrationDetailSnapshot } from '../storage/local/snapshot-sanitize.js';
import {
  advancedArtifact,
  advancedCompleteAnswer,
  attestationDecodeAnswer,
  completeAnswer,
  recordedDecoder,
  simpleRecord,
} from '@/test/logic/credentials/registration-detail-answers.js';

// What the registration view shows, as data (credentials/registration/view.js).

afterEach(() => {
  vi.restoreAllMocks();
});

const ISSUER_LINE = 'Issuer: CN=Characterization Test CA';

/** A Simple registration's view as the registration's own answer gives it. */
function registrationOptions(name) {
  const answer = completeAnswer(name);
  const credentialJson = answer.storedCredential.registrationResponse;
  return {
    credentialJson,
    relyingPartyInfo: answer.relyingParty,
    ...registrationResultInput(credentialJson, answer.relyingParty),
  };
}

async function compose(options, decode = recordedDecoder()) {
  const state = createRegistrationState();
  const composed = await composeRegistration(options, { state, decode });
  return { state, decode, composed };
}

/** A registration kept as a saved snapshot, as the app saves one. */
async function savedSnapshot(name) {
  const options = registrationOptions(name);
  const { composed } = await compose(options);
  return sanitiseRegistrationDetailSnapshot(registrationSnapshotPayload({
    stateSnapshot: composed.stateSnapshot,
    credentialJson: options.credentialJson,
    relyingPartyCopy: composed.relyingPartyCopy,
  }, '2026-09-21T14:13:20.000Z'));
}


describe('composeRegistration', () => {
  it('decodes a Simple registration once, and shows its response, client data and relying party', async () => {
    const options = registrationOptions('es256');
    const { decode, composed } = await compose(options);

    expect(decode).toHaveBeenCalledTimes(1);
    expect(decode).toHaveBeenCalledWith(options.attestationObjectValue);
    expect(JSON.parse(composed.response.credential)).toEqual(options.credentialJson);
    expect(JSON.parse(composed.response.clientData)).toMatchObject({ type: 'webauthn.create' });
    const relyingParty = JSON.parse(composed.response.relyingParty);
    expect(relyingParty).not.toHaveProperty('attestationFmt');
    expect(relyingParty.aaguid).toEqual(options.relyingPartyInfo.aaguid);
    expect(composed.relyingPartyCopy).toEqual(relyingParty);
  });

  it('shows the decoded attestation object, with its authenticator data and no certificates', async () => {
    const { composed } = await compose(registrationOptions('es256'));
    expect(composed.attestation).toEqual({
      body: { kind: 'json', text: expect.stringContaining('"fmt": "none"') },
      certificates: [],
      certificateMessage: REGISTRATION_TEXT.noCertificates,
      hasAuthenticatorData: true,
      authenticatorError: '',
    });
  });

  it('hashes the authenticator data the attestation object held once its base64url is known, and keeps both in the snapshot', async () => {
    const record = simpleRecord('es256');
    const { state, composed } = await compose({ ...registrationOptions('es256'), authenticatorDataValue: record.authenticatorData });
    expect([state.authenticatorDataHex, state.authenticatorDataHash]).toEqual([record.authenticatorDataHex, record.authenticatorDataHash]);
    expect(composed.stateSnapshot).toMatchObject({
      authenticatorDataHex: record.authenticatorDataHex,
      authenticatorDataHash: record.authenticatorDataHash,
    });
  });

  it('keeps the record\'s authenticator data beside the decoded one', async () => {
    const record = simpleRecord('es256');
    const { decode, state } = await compose({ ...registrationOptions('es256'), authenticatorDataValue: record.authenticatorData });
    expect(decode).toHaveBeenCalledTimes(1);
    expect(state.authenticatorData.base64url).toBe(record.authenticatorData);
    expect(state.authenticatorData.credential.aaguid.raw).toBe('00112233445566778899aabbccddeeff');
  });

  it('lists a packed registration\'s certificate, and gives it its own view', async () => {
    const { state, composed } = await compose(registrationOptions('packedX5c'));
    expect(composed.attestation.certificates).toEqual([{ index: 0, title: 'Attestation Certificate' }]);
    expect(composed.attestation.certificateMessage).toBe('');
    expect(JSON.parse(composed.attestation.body.text).fmt).toBe('packed');
    expect(describeAttestationCertificate(state, 0).text).toContain(ISSUER_LINE);
  });

  it('keeps the registration\'s decoded state for its snapshot', async () => {
    const { composed } = await compose(registrationOptions('packedX5c'));
    expect(composed.stateSnapshot.detailPreparation).toEqual({
      attestationObjectValue: simpleRecord('packedX5c').attestationObject,
      attestationDecodeError: '',
      authenticatorDataValue: '',
      authenticatorDecodeError: '',
    });
    expect(composed.stateSnapshot.visibleAttestationCertificateIndices).toEqual([0]);
    expect(composed.stateSnapshot.attestationObject.fmt).toBe('packed');
  });

  it('shows a saved snapshot as it is, without asking the decoder', async () => {
    const snapshot = await savedSnapshot('packedX5c');
    const decode = vi.fn();
    const { state, composed } = await compose({
      credentialJson: snapshot.response.credential,
      relyingPartyInfo: snapshot.response.relyingParty,
      snapshotState: snapshot.state,
    }, decode);

    expect(decode).not.toHaveBeenCalled();
    expect(composed.attestation.certificates).toEqual([{ index: 0, title: 'Attestation Certificate' }]);
    expect(describeAttestationCertificate(state, 0).text).toContain(ISSUER_LINE);
    expect(state.authenticatorData).toEqual(attestationDecodeAnswer('packedX5c').data.authenticatorData);
  });

  it('says what a snapshot recorded about a decode that failed', async () => {
    const { composed } = await compose({
      snapshotState: {
        detailPreparation: { attestationObjectValue: 'o2NmbXRk', attestationDecodeError: 'The payload is not valid CBOR.' },
      },
    });
    expect(composed.attestation.body).toEqual({ kind: 'error', text: 'The payload is not valid CBOR.' });
  });

  it('fills the authenticator data from what a saved snapshot says was decoded', async () => {
    const value = simpleRecord('es256').authenticatorData;
    const { state } = await compose({
      authenticatorDataHex: 'ab',
      snapshotState: { detailPreparation: { authenticatorDataValue: value } },
    });
    expect(state.authenticatorData).toEqual({ base64url: value, raw: 'ab' });
  });

  it('keeps the authenticator data\'s bytes without hex when only a snapshot\'s value is known', async () => {
    const value = simpleRecord('es256').authenticatorData;
    const { state } = await compose({ snapshotState: { detailPreparation: { authenticatorDataValue: value } } });
    expect(state.authenticatorData).toEqual({ base64url: value });
  });

  it('keeps the authenticator data\'s hex when that is all there is', async () => {
    const { state, composed } = await compose({ authenticatorDataHex: 'abcd' });
    expect(state.authenticatorData).toEqual({ raw: 'abcd' });
    expect(composed.attestation).toBeNull();
    expect(describeAuthenticatorData(state).text).toBe(JSON.stringify({ raw: 'abcd' }, null, 2));
  });

  it('adds the authenticator data\'s hex to decoded data that has none, and leaves hex it has', async () => {
    const record = simpleRecord('es256');
    const withoutHex = await compose({ ...registrationOptions('es256'), authenticatorDataHex: record.authenticatorDataHex });
    expect(withoutHex.state.authenticatorData.raw).toBe(record.authenticatorDataHex);

    const withHex = await compose({ authenticatorDataValue: record.authenticatorData, authenticatorDataHex: 'ab' });
    expect(withHex.state.authenticatorData.raw).toBe(record.authenticatorDataHex);
    expect(withHex.state.authenticatorData.base64url).toBe(record.authenticatorData);
  });

  it('leaves a snapshot\'s authenticator data as it was saved', async () => {
    const { state } = await compose({
      snapshotState: { authenticatorData: { base64url: 'kept', raw: 'cafe' } },
      authenticatorDataHex: 'ab',
    });
    expect(state.authenticatorData).toEqual({ base64url: 'kept', raw: 'cafe' });
  });

  it('decodes the authenticator data alone when there is no attestation object, and hashes its bytes', async () => {
    const record = simpleRecord('es256');
    const { decode, composed, state } = await compose({ authenticatorDataValue: record.authenticatorData });
    expect(decode).toHaveBeenCalledWith(record.authenticatorData);
    expect(composed.attestation).toBeNull();
    expect(state.authenticatorData.credential.aaguid.raw).toBe('00112233445566778899aabbccddeeff');
    expect(state.authenticatorData.base64url).toBe(record.authenticatorData);
    expect(composed.stateSnapshot.authenticatorDataHex).toBe(record.authenticatorDataHex);
    expect(composed.stateSnapshot.authenticatorDataHash).toBe(record.authenticatorDataHash);
    expect(JSON.parse(composed.response.relyingParty)).toEqual({
      authenticatorData: record.authenticatorDataHex,
      authenticatorDataHash: record.authenticatorDataHash,
    });
  });

  it('says why the attestation object is missing when the decoder refused it', async () => {
    const { composed } = await compose({ attestationObjectValue: 'o2NmbXRk' });
    expect(composed.attestation.body).toEqual({ kind: 'error', text: 'The payload is not valid CBOR.' });
  });

  it('counts the statement of a decoded object the record keeps when the snapshot holds no attestation object', async () => {
    const decoded = attestationDecodeAnswer('packedX5c').data.attestationObject;
    const { composed } = await compose({
      attestationObjectDecoded: decoded,
      snapshotState: { detailPreparation: {} },
    });
    expect(composed.attestation.body).toEqual({ kind: 'placeholder', text: REGISTRATION_TEXT.noAttestationObject });
    expect(composed.attestation.certificateMessage).toBe(REGISTRATION_TEXT.noCertificates);
  });

  it('reads the decoded object\'s format when the attestation object shown has none', async () => {
    const decoded = attestationDecodeAnswer('es256').data.attestationObject;
    const { composed } = await compose({
      attestationObjectDecoded: decoded,
      snapshotState: { attestationObject: { authData: 'x' } },
    });
    expect(JSON.parse(composed.attestation.body.text)).toEqual({ fmt: 'none', authData: 'x' });
  });

  it('ignores a decoded object the record keeps without a format or a statement', async () => {
    const { composed } = await compose({
      attestationObjectDecoded: { authData: 'x' },
      snapshotState: { attestationObject: { authData: 'y' } },
    });
    expect(JSON.parse(composed.attestation.body.text)).toEqual({ authData: 'y' });
  });

  it('shows no credential, client data or relying party when there are none', async () => {
    const { composed } = await compose();
    expect(composed.response).toEqual({ credential: '', clientData: '', relyingParty: '' });
    expect(composed.attestation).toBeNull();
    expect(composed.relyingPartyCopy).toBeNull();
  });

  it('composes an empty view when given no options at all', async () => {
    const state = createRegistrationState();
    const composed = await composeRegistration(undefined, { state, decode: vi.fn() });
    expect(composed.response).toEqual({ credential: '', clientData: '', relyingParty: '' });
  });
});

describe('registrationResultInput', () => {
  it('takes the browser\'s attestation object and authenticator data, and the relying party\'s certificates', () => {
    const answer = advancedCompleteAnswer();
    const { storedCredential } = advancedArtifact();
    // The response as the browser's toJSON() gives it: the server keeps its authenticator data beside it.
    const credentialJson = {
      ...storedCredential.registrationResponse,
      response: { ...storedCredential.registrationResponse.response, authenticatorData: storedCredential.authenticatorData },
    };
    const input = registrationResultInput(credentialJson, answer.relyingParty);
    expect(input.attestationObjectValue).toBe(storedCredential.registrationResponse.response.attestationObject);
    expect(input.authenticatorDataValue).toBe(storedCredential.authenticatorData);
    expect(input.fallbackCertificates).toEqual([
      answer.relyingParty.attestationCertificate,
      ...answer.relyingParty.attestationCertificates,
    ]);
  });

  it('takes the certificates in the registration data too, leaving out empty ones', () => {
    const [a, b, c] = ['a', 'b', 'c'].map((name) => ({ name }));
    const input = registrationResultInput({}, {
      attestationCertificates: [a, null],
      registrationData: { attestationCertificate: b, attestationCertificates: [c] },
    });
    expect(input.fallbackCertificates).toEqual([a, b, c]);
  });

  it('gives nothing to decode without a response or a relying party', () => {
    expect(registrationResultInput(null, null)).toEqual({
      attestationObjectValue: '',
      authenticatorDataValue: '',
      fallbackCertificates: [],
    });
  });
});

describe('registrationSnapshotPayload', () => {
  it('keeps the decoded state, the browser\'s response and the relying party\'s view, as data', async () => {
    const options = registrationOptions('es256');
    const { composed } = await compose(options);
    const payload = registrationSnapshotPayload({
      stateSnapshot: composed.stateSnapshot,
      credentialJson: options.credentialJson,
      relyingPartyCopy: composed.relyingPartyCopy,
    }, '2026-09-21T14:13:20.000Z');
    expect(payload).toEqual({
      schemaVersion: 2,
      capturedAt: '2026-09-21T14:13:20.000Z',
      state: composed.stateSnapshot,
      response: { credential: options.credentialJson, relyingParty: composed.relyingPartyCopy },
    });
  });

  it('keeps an empty state and no relying party when there are none', () => {
    expect(registrationSnapshotPayload({ credentialJson: null }, 'now')).toEqual({
      schemaVersion: 2,
      capturedAt: 'now',
      state: {},
      response: { credential: null, relyingParty: null },
    });
  });
});
