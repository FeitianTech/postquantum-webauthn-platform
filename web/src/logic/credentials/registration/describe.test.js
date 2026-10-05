import { describe, expect, it } from 'vitest';

import {
  REGISTRATION_TEXT,
  attestationObjectJson,
  certificateTitle,
  describeAttestationCertificate,
  describeAttestationSection,
  describeAuthenticatorData,
  describeClientData,
} from './describe.js';
import { createRegistrationState } from './state.js';
import { attestationDecodeAnswer, simpleRecord } from '@/test/logic/credentials/registration-detail-answers.js';

// What each part of the registration view shows, as data (credentials/registration/describe.js).

const ISSUER_LINE = 'Issuer: CN=Characterization Test CA';

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

  it('shows nothing without client data', () => {
    expect(describeClientData(null, 42, 'not an object')).toBe('');
    expect(describeClientData(undefined, '   ')).toBe('');
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

  it('shows the decoded authenticator data as indented JSON', () => {
    const state = createRegistrationState();
    state.authenticatorData = attestationDecodeAnswer('packedX5c').data.authenticatorData;
    const view = describeAuthenticatorData(state);
    expect(view.title).toBe('Authenticator Data');
    expect(JSON.parse(view.text)).toEqual(state.authenticatorData);
  });
});
