import { afterEach, describe, expect, it, vi } from 'vitest';

import {
  REGISTRATION_TEXT,
  attestationObjectJson,
  certificateTitle,
  composeRegistration,
  describeAttestationCertificate,
  describeAttestationSection,
  describeAuthenticatorData,
  describeClientData,
  registrationResultInput,
  registrationSnapshotPayload,
} from './registration-view.js';
import { createRegistrationState } from './registration-state.js';
import { sanitiseRegistrationDetailSnapshot } from '../../credentials/storage/local/snapshot-sanitize.js';
import {
  advancedArtifact,
  advancedCompleteAnswer,
  attestationDecodeAnswer,
  completeAnswer,
  recordedDecoder,
  simpleRecord,
} from '@/test/logic/credentials/registration-detail-answers.js';

// What the registration view shows, as data (credential-display/registration-view.js).

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

/** The packed registration's attestation certificate as the server parsed it. */
const parsedCertificate = () => simpleRecord('packedX5c').properties.attestationCertificates[0];

describe('certificateTitle', () => {
  it('names a single certificate without a number', () => {
    expect(certificateTitle(0, 1)).toBe('Attestation Certificate');
  });

  it('numbers each of several certificates from 1', () => {
    expect([0, 1].map((index) => certificateTitle(index, 2))).toEqual([
      'Attestation Certificate 1',
      'Attestation Certificate 2',
    ]);
  });
});

describe('attestationObjectJson', () => {
  it('writes the decoded attestation object as indented JSON, the format first and the raw bytes left out', () => {
    const decoded = attestationDecodeAnswer('es256').data.attestationObject;
    const text = attestationObjectJson(decoded, '', []);
    expect(text).toBe(JSON.stringify({ fmt: 'none' }, null, 2));
  });

  it('puts the relying party\'s format in place of the object\'s own', () => {
    expect(JSON.parse(attestationObjectJson({ fmt: 'none', authData: {} }, 'packed', []))).toEqual({ fmt: 'packed', authData: {} });
  });

  it('shows each x5c certificate as what the view knows of it', () => {
    const decoded = attestationDecodeAnswer('packedX5c').data.attestationObject;
    const shown = JSON.parse(attestationObjectJson(decoded, 'packed', decoded.attStmt.x5c));
    expect(shown.fmt).toBe('packed');
    expect(shown.attStmt.x5c).toHaveLength(1);
    expect(shown.attStmt.x5c[0].certificateIndex).toBe(1);
    expect(shown.attStmt.x5c[0].details.issuer).toBe('CN=Characterization Test CA');
    expect(shown.attStmt.x5c[0].details).not.toHaveProperty('derBase64');
  });

});

describe('describeAttestationSection', () => {
  it('has no section when the registration has no attestation', () => {
    expect(describeAttestationSection(createRegistrationState())).toBeNull();
  });

  it('reads a state that keeps no certificate list as one without certificates', () => {
    const state = { ...createRegistrationState(), attestationCertificates: undefined };
    expect(describeAttestationSection(state)).toBeNull();
    expect(state.visibleAttestationCertificateIndices).toEqual([]);
  });

  it('shows a decoded attestation object as JSON and says there are no certificates', () => {
    const state = createRegistrationState();
    state.attestationObject = attestationDecodeAnswer('es256').data.attestationObject;
    expect(describeAttestationSection(state)).toEqual({
      body: { kind: 'json', text: JSON.stringify({ fmt: 'none' }, null, 2) },
      certificates: [],
      certificateMessage: REGISTRATION_TEXT.noCertificates,
      hasAuthenticatorData: false,
      authenticatorError: '',
    });
  });

  it('lists each certificate that parsed, records which ones, and skips those that did not', () => {
    const state = createRegistrationState();
    state.attestationObject = attestationDecodeAnswer('packedX5c').data.attestationObject;
    state.attestationCertificates = [
      { parsedX5c: { parseError: 'error parsing asn1 value', raw: 'aa' } },
      { parsedX5c: parsedCertificate() },
    ];
    state.authenticatorData = { counter: 0 };
    const section = describeAttestationSection(state, { attestationFormatRaw: 'packed' });
    expect(section.certificates).toEqual([{ index: 0, title: 'Attestation Certificate' }]);
    expect(section.certificateMessage).toBe('');
    expect(section.hasAuthenticatorData).toBe(true);
    expect(state.visibleAttestationCertificateIndices).toEqual([1]);
  });

  it('shows the section for certificates alone, with no attestation object to show', () => {
    const state = createRegistrationState();
    state.attestationCertificates = [{ parsedX5c: parsedCertificate() }, { parsedX5c: parsedCertificate() }];
    const section = describeAttestationSection(state);
    expect(section.body).toEqual({ kind: 'placeholder', text: REGISTRATION_TEXT.noAttestationObject });
    expect(section.certificates.map(({ title }) => title)).toEqual(['Attestation Certificate 1', 'Attestation Certificate 2']);
    expect(section.certificateMessage).toBe('');
  });

  it('says why an attestation object that did not decode is missing', () => {
    const section = describeAttestationSection(createRegistrationState(), {
      attestationObjectValue: 'o2NmbXRk',
      attestationDecodeError: 'The payload is not valid CBOR.',
    });
    expect(section.body).toEqual({ kind: 'error', text: 'The payload is not valid CBOR.' });
    expect(section.certificateMessage).toBe(REGISTRATION_TEXT.noCertificates);
  });

  it('says the attestation object could not be decoded when the decoder gave no reason', () => {
    const section = describeAttestationSection(createRegistrationState(), { attestationObjectValue: 'o2NmbXRk' });
    expect(section.body).toEqual({ kind: 'error', text: REGISTRATION_TEXT.undecodable });
  });

  it('does not count a value that is not text, or only spaces, as an attestation object', () => {
    expect(describeAttestationSection(createRegistrationState(), { attestationObjectValue: null })).toBeNull();
    expect(describeAttestationSection(createRegistrationState(), { attestationObjectValue: '  ' })).toBeNull();
  });

  it('shows the section for an attestation statement alone', () => {
    const section = describeAttestationSection(createRegistrationState(), { attestationStatement: { alg: -7 } });
    expect(section.body).toEqual({ kind: 'placeholder', text: REGISTRATION_TEXT.noAttestationObject });
    expect(section.certificateMessage).toBe(REGISTRATION_TEXT.noCertificates);
  });

  it('takes the statement from the attestation object when none is given', () => {
    const state = createRegistrationState();
    state.attestationObject = { attStmt: { alg: -7 } };
    expect(describeAttestationSection(state).certificateMessage).toBe(REGISTRATION_TEXT.noCertificates);
  });

  it('does not count an empty statement or an empty attestation object as an attestation', () => {
    const state = createRegistrationState();
    state.attestationObject = {};
    expect(describeAttestationSection(state, { attestationStatement: {} })).toBeNull();
  });

  it('reads an attestation object whose statement is null as one without a statement', () => {
    const state = createRegistrationState();
    state.attestationObject = { attStmt: null };
    const section = describeAttestationSection(state);
    expect(section.body.kind).toBe('json');
    expect(section.certificateMessage).toBe(REGISTRATION_TEXT.noCertificates);
  });

  it('gives the authenticator data\'s decode error when the data was sent but not decoded', () => {
    const section = describeAttestationSection(createRegistrationState(), {
      attestationObjectValue: 'o2NmbXRk',
      authenticatorDataValue: 'SZYN5YgO',
      authenticatorDecodeError: 'The payload is not valid CBOR.',
    });
    expect(section.authenticatorError).toBe('The payload is not valid CBOR.');
  });

  it('gives no authenticator data error when the data is there, or was never sent', () => {
    const state = createRegistrationState();
    state.authenticatorData = { counter: 0 };
    const decoded = describeAttestationSection(state, {
      attestationObjectValue: 'o2NmbXRk',
      authenticatorDataValue: 'SZYN5YgO',
      authenticatorDecodeError: 'The payload is not valid CBOR.',
    });
    const unsent = describeAttestationSection(createRegistrationState(), {
      attestationObjectValue: 'o2NmbXRk',
      authenticatorDecodeError: 'The payload is not valid CBOR.',
    });
    expect([decoded.authenticatorError, unsent.authenticatorError]).toEqual(['', '']);
  });
});

describe('describeClientData', () => {
  const record = () => simpleRecord('es256');

  it('shows the browser\'s client data parsed, as indented JSON', () => {
    const text = describeClientData(record().registrationResponse);
    expect(JSON.parse(text)).toMatchObject({ type: 'webauthn.create', origin: 'http://localhost' });
    expect(text).toContain('\n  "type"');
  });

  it('shows client data that is not base64url of anything as it is stored, rather than throwing', () => {
    expect(describeClientData({ response: { clientDataJSON: 'abcde' } })).toBe('abcde');
    expect(describeClientData({ response: {} }, 'not base64!')).toBe('not base64!');
  });

  it('reads the record\'s client data when the response has none', () => {
    const text = describeClientData({ response: {} }, record().clientDataJSON);
    expect(JSON.parse(text)).toMatchObject({ type: 'webauthn.create' });
  });

  it('reads client data kept as standard base64', () => {
    const base64 = btoa('{"type":"webauthn.create"}');
    expect(JSON.parse(describeClientData(null, ` ${base64} `))).toEqual({ type: 'webauthn.create' });
  });

  it('shows client data that is not JSON as its text', () => {
    expect(describeClientData({ response: { clientDataJSON: 'aGVsbG8' } })).toBe('hello');
  });

  it('shows client data that decodes to nothing as it was given', () => {
    expect(describeClientData({ response: { clientDataJSON: ' ' } })).toBe(' ');
  });

  it('shows the record\'s client data as it is when it spells no bytes', () => {
    expect(describeClientData(null, '==')).toBe('==');
  });

  it('shows the parsed client data the record keeps when there is no encoded one', () => {
    expect(JSON.parse(describeClientData(null, null, { type: 'webauthn.create' }))).toEqual({ type: 'webauthn.create' });
  });

  it('prefers the parsed client data the record keeps to text that is not JSON', () => {
    expect(JSON.parse(describeClientData(null, 'aGVsbG8', { type: 'webauthn.create' }))).toEqual({ type: 'webauthn.create' });
  });

  it('shows nothing without client data', () => {
    expect(describeClientData(null, 42, 'not an object')).toBe('');
    expect(describeClientData(undefined, '   ')).toBe('');
  });
});

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

describe('describeAttestationCertificate', () => {
  function stateWith(entries) {
    const state = createRegistrationState();
    state.attestationCertificates = entries;
    describeAttestationSection(state);
    return state;
  }

  it('gives a listed certificate\'s title, its text and its decoded details', () => {
    const certificate = parsedCertificate();
    const view = describeAttestationCertificate(stateWith([certificate]), 0);
    expect(view.title).toBe('Attestation Certificate');
    expect(view.details).toEqual(certificate);
    expect(view.text).toContain(ISSUER_LINE);
    expect(view.error).toBe('');
    expect(view.placeholder).toBe('');
  });

  it('numbers the certificate when the view lists several', () => {
    const state = stateWith([{ parsedX5c: parsedCertificate() }, { parsedX5c: { summary: 'Second' } }]);
    expect(describeAttestationCertificate(state, 1)).toMatchObject({ title: 'Attestation Certificate 2', text: 'Second' });
  });

  it('gives the parser\'s error when the certificate has no text', () => {
    const view = describeAttestationCertificate(stateWith([{ parsedX5c: { error: ' Unsupported certificate. ' } }]), 0);
    expect(view).toMatchObject({ text: '', error: 'Unsupported certificate.', placeholder: '' });
  });

  it('says there are no details when the certificate has neither text nor an error', () => {
    const view = describeAttestationCertificate(stateWith([{ parsedX5c: { error: 42 } }]), 0);
    expect(view).toMatchObject({ text: '', error: '', placeholder: REGISTRATION_TEXT.noCertificateDetails });
  });

  it('has no view for a certificate the view does not list', () => {
    expect(describeAttestationCertificate(stateWith([]), 0)).toBeNull();
  });
});

describe('describeAuthenticatorData', () => {
  it('has no view without authenticator data', () => {
    expect(describeAuthenticatorData(createRegistrationState())).toBeNull();
  });

  it('shows the decoded authenticator data as indented JSON', async () => {
    const { state } = await compose(registrationOptions('es256'));
    const view = describeAuthenticatorData(state);
    expect(view.title).toBe('Authenticator Data');
    expect(JSON.parse(view.text)).toEqual(state.authenticatorData);
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
