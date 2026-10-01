import { describe, expect, it } from 'vitest';

import { buildRegistrationContext } from './registration-context.js';
import {
  attestationObjectDecodedCandidates,
  attestationObjectStringCandidates,
  authenticatorDataHexCandidates,
  authenticatorDataStringCandidates,
  resolveStoredRegistrationResponse,
} from './registration-candidates.js';
import {
  pickFirstObject,
  pickFirstString,
} from './helpers.js';
import { advancedArtifact, attestationDecodeAnswer, simpleRecord } from '@/test/logic/credentials/registration-detail-answers.js';

// What a saved credential's registration view is built from, read from the
// record under each name it may use (credentials/detail/registration-context.js
// over registration-candidates.js and helpers.js).

const AAGUID = '00112233445566778899aabbccddeeff';

describe('buildRegistrationContext', () => {
  it('reads a Simple registration\'s attestation object, authenticator data, client data and relying party', () => {
    const record = simpleRecord('es256');
    const context = buildRegistrationContext(record);
    expect(context).toMatchObject({
      attestationObjectValue: record.attestationObject,
      attestationObjectDecoded: null,
      authenticatorDataHex: record.authenticatorDataHex,
      fallbackCertificates: [],
      certificateAaguidHex: '',
      authDataAaguidHex: AAGUID,
      relyingPartyInfo: record.relyingParty,
      fallbackClientDataString: record.clientDataJSON,
      fallbackClientDataObject: null,
      authenticatorDataForDetail: record.authenticatorData,
    });
  });

  it('completes the browser\'s response the record kept with what the record holds', () => {
    const record = simpleRecord('es256');
    const { registrationCredential } = buildRegistrationContext(record);
    expect(registrationCredential).toEqual({
      ...record.registrationResponse,
      response: { ...record.registrationResponse.response, authenticatorData: record.authenticatorData },
      clientExtensionResults: {},
    });
    expect(record.registrationResponse.response).not.toHaveProperty('authenticatorData');
  });

  it('reads a packed registration\'s certificates and the AAGUID in them', () => {
    const record = simpleRecord('packedX5c');
    const context = buildRegistrationContext(record);
    expect(context.fallbackCertificates).toEqual(record.properties.attestationCertificates);
    expect(context.certificateAaguidHex).toBe(AAGUID);
  });

  it('reads the certificates under each name the record may keep them', () => {
    const [a, b, c, d, e, f] = 'abcdef'.split('').map((name) => ({ name }));
    const { fallbackCertificates } = buildRegistrationContext({
      attestationCertificate: a,
      attestationCertificates: [b, null],
      properties: { attestationCertificate: c, attestationCertificates: [d] },
      relyingParty: { attestationCertificate: e, attestationCertificates: [f] },
    });
    expect(fallbackCertificates).toEqual([a, b, c, d, e, f]);
  });

  it('takes the decoded attestation object, certificates and authenticator data hex from a saved snapshot', () => {
    const decoded = attestationDecodeAnswer('packedX5c').data.attestationObject;
    const certificates = [{ parsedX5c: simpleRecord('packedX5c').properties.attestationCertificates[0] }];
    const context = buildRegistrationContext(simpleRecord('es256'), {
      snapshotState: { attestationObject: decoded, attestationCertificates: certificates, authenticatorDataHex: 'cafe' },
    });
    expect(context.attestationObjectDecoded).toEqual(decoded);
    expect(context.attestationObjectDecoded).not.toBe(decoded);
    expect(context.fallbackCertificates).toEqual(certificates);
    expect(context.certificateAaguidHex).toBe(AAGUID);
    expect(context.authenticatorDataHex).toBe('cafe');
    expect(context.registrationCredential.response.attestationObjectDecoded).toEqual(decoded);
  });

  it('keeps the record\'s own values where the snapshot holds none', () => {
    const record = simpleRecord('packedX5c');
    const context = buildRegistrationContext(record, { snapshotState: { attestationCertificates: 'none', authenticatorDataHex: 1 } });
    expect(context.attestationObjectDecoded).toBeNull();
    expect(context.fallbackCertificates).toEqual(record.properties.attestationCertificates);
    expect(context.authenticatorDataHex).toBe(record.authenticatorDataHex);
  });

  it('takes the values a snapshot says were decoded before the record\'s own', () => {
    const record = simpleRecord('es256');
    const decoded = buildRegistrationContext(record, {
      detailPreparation: { attestationObjectValue: 'from-snapshot', authenticatorDataValue: 'auth-from-snapshot' },
    });
    expect([decoded.attestationObjectValue, decoded.authenticatorDataForDetail]).toEqual(['from-snapshot', 'auth-from-snapshot']);

    const empty = buildRegistrationContext(record, { detailPreparation: { attestationObjectValue: '', authenticatorDataValue: '' } });
    expect([empty.attestationObjectValue, empty.authenticatorDataForDetail]).toEqual([record.attestationObject, record.authenticatorData]);
  });

  it('reads an advanced artifact\'s record the same way', () => {
    const { storedCredential } = advancedArtifact();
    const context = buildRegistrationContext(storedCredential);
    expect(context.attestationObjectValue).toBe(storedCredential.attestationObject);
    expect(context.authDataAaguidHex).toBe(AAGUID);
    expect(context.registrationCredential.id).toBe(storedCredential.registrationResponse.id);
    expect(context.registrationCredential.clientExtensionResults).toEqual(storedCredential.registrationResponse.clientExtensionResults);
  });

  it('builds a response from the record\'s own fields when it kept none', () => {
    const record = simpleRecord('es256');
    delete record.registrationResponse;
    const { registrationCredential } = buildRegistrationContext(record);
    expect(registrationCredential).toEqual({
      response: {
        attestationObject: record.attestationObject,
        clientDataJSON: record.clientDataJSON,
        authenticatorData: record.authenticatorData,
      },
      id: record.credentialId,
      rawId: record.credentialId,
      type: 'public-key',
      clientExtensionResults: {},
    });
  });

  it('spells a credential id kept as standard base64 in base64url', () => {
    const { registrationCredential } = buildRegistrationContext({ credentialId: 'TfLEvM/Z+yTXAA==' });
    expect([registrationCredential.id, registrationCredential.rawId]).toEqual(['TfLEvM_Z-yTXAA', 'TfLEvM_Z-yTXAA']);
  });

  it('gives a bare response with only its type when the record holds nothing', () => {
    const context = buildRegistrationContext({});
    expect(context).toEqual({
      attestationObjectValue: '',
      attestationObjectDecoded: null,
      authenticatorDataHex: '',
      fallbackCertificates: [],
      certificateAaguidHex: '',
      authDataAaguidHex: '',
      relyingPartyInfo: null,
      fallbackClientDataString: '',
      fallbackClientDataObject: null,
      registrationCredential: { response: {}, type: 'public-key' },
      authenticatorDataForDetail: '',
    });
  });

  it('reads the relying party under each name the record may keep it', () => {
    const rp = { id: 'localhost' };
    expect([
      { registrationRelyingParty: rp },
      { properties: { relyingParty: rp } },
    ].map((cred) => buildRegistrationContext(cred).relyingPartyInfo)).toEqual([rp, rp]);
  });

  it('reads the client data as text or as an object, under each name the record may keep it', () => {
    const parsed = { type: 'webauthn.create' };
    expect([
      { clientDataJson: 'eyJ9' },
      { clientData: 'eyJ9' },
    ].map((cred) => buildRegistrationContext(cred).fallbackClientDataString)).toEqual(['eyJ9', 'eyJ9']);
    expect([
      { clientDataParsed: parsed },
      { clientDataObject: parsed },
    ].map((cred) => buildRegistrationContext(cred).fallbackClientDataObject)).toEqual([parsed, parsed]);
  });

  it('puts the record\'s client data in the response, in base64url', () => {
    const { registrationCredential } = buildRegistrationContext({ clientData: 'eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0=' });
    expect(registrationCredential.response.clientDataJSON).toBe('eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0');
  });

  it('keeps what the kept response already holds', () => {
    const kept = {
      id: 'kept-id',
      rawId: 'kept-raw',
      type: 'kept-type',
      authenticatorAttachment: 'platform',
      clientExtensionResults: { credProps: { rk: true } },
      response: {
        attestationObject: 'kept-att',
        attestationObjectDecoded: { fmt: 'kept' },
        clientDataJSON: 'kept-cd',
        authenticatorData: 'kept-ad',
      },
    };
    const { registrationCredential } = buildRegistrationContext({
      registrationResult: kept,
      credentialId: 'AQID',
      attestationObject: 'record-att',
      attestationObjectDecoded: { fmt: 'record' },
      clientDataJSON: 'record-cd',
      authenticatorData: 'record-ad',
      authenticatorAttachment: 'cross-platform',
      clientExtensionOutputs: { credProps: { rk: false } },
    });
    expect(registrationCredential).toEqual(kept);
  });

  it('adds the record\'s attachment and extension outputs to a response without them', () => {
    const { registrationCredential } = buildRegistrationContext({
      registrationResponse: {},
      authenticatorAttachment: 'platform',
      clientExtensionOutputs: { credProps: { rk: true } },
    });
    expect(registrationCredential).toMatchObject({
      authenticatorAttachment: 'platform',
      clientExtensionResults: { credProps: { rk: true } },
    });
  });

  it('reads a response kept flat, without a nested response', () => {
    const decoded = { fmt: 'none' };
    const context = buildRegistrationContext({
      registrationResult: {
        attestationObjectRaw: 'flat-att',
        attestationObjectDecoded: decoded,
        authenticatorDataRaw: 'flat-ad',
        authenticatorDataHex: 'abcd',
      },
    });
    expect(context).toMatchObject({
      attestationObjectValue: 'flat-att',
      attestationObjectDecoded: decoded,
      authenticatorDataHex: 'abcd',
      authenticatorDataForDetail: 'flat-ad',
    });
    expect(context.registrationCredential.response).toEqual({
      attestationObject: 'flat-att',
      attestationObjectDecoded: decoded,
      authenticatorData: 'flat-ad',
    });
  });

  it('reads the kept response\'s own fields before the credential\'s', () => {
    const decoded = { fmt: 'none' };
    const context = buildRegistrationContext({
      registrationResponse: {
        attestationObject: 'top-att',
        attestationObjectDecoded: { fmt: 'top' },
        authenticatorDataBase64Url: 'top-ad',
        authenticatorDataHex: 'top-hex',
        response: {
          attestationObject: decoded,
          attestationObjectBase64: 'nested-att',
          authenticatorData: 'nested-ad',
          authenticatorDataHex: 'beef',
        },
      },
    });
    expect(context).toMatchObject({
      attestationObjectValue: 'nested-att',
      attestationObjectDecoded: decoded,
      authenticatorDataHex: 'beef',
      authenticatorDataForDetail: 'nested-ad',
    });
  });

  it('falls back to the credential\'s own fields when its nested response holds none', () => {
    const decoded = { fmt: 'none' };
    const context = buildRegistrationContext({
      registrationResponse: {
        attestationObjectBase64: 'top-att',
        attestationObject: decoded,
        authenticatorDataBase64: 'top-ad',
        authenticatorDataHex: 'cafe',
        response: {},
      },
    });
    expect(context).toMatchObject({
      attestationObjectValue: 'top-att',
      attestationObjectDecoded: decoded,
      authenticatorDataHex: 'cafe',
      authenticatorDataForDetail: 'top-ad',
    });
  });

  it('uses the authenticator data\'s hex for the view when there is no other spelling', () => {
    expect(buildRegistrationContext({ authenticatorDataHex: 'abcd' }).authenticatorDataForDetail).toBe('abcd');
  });
});

describe('the candidates a registration is read from', () => {
  it('names the attestation object\'s spellings in the order they are read', () => {
    const source = {
      attestationObjectRaw: 1,
      attestationObject: 2,
      attestationObjectBase64: 3,
    };
    expect(attestationObjectStringCandidates(source)).toEqual([1, 2, 3]);
  });

  it('names the decoded attestation object\'s places, the encoded ones only when they hold an object', () => {
    const [a, b] = [{}, {}];
    expect(attestationObjectDecodedCandidates({ attestationObjectDecoded: a, attestationObject: b })).toEqual([a, b]);
    expect(attestationObjectDecodedCandidates({ attestationObject: 'text' })).toEqual([undefined, null]);
  });

  it('names the authenticator data\'s spellings, and its hex\'s', () => {
    const source = {
      authenticatorDataRaw: 1,
      authenticatorData: 2,
      authenticatorDataBase64: 3,
      authenticatorDataBase64Url: 4,
      authenticatorDataHex: 5,
    };
    expect(authenticatorDataStringCandidates(source)).toEqual([1, 2, 3, 4]);
    expect(authenticatorDataHexCandidates(source)).toEqual([5]);
  });

  it('names nothing for a source that is not an object', () => {
    [null, undefined, 'text'].forEach((source) => {
      expect(attestationObjectStringCandidates(source)).toEqual([]);
      expect(attestationObjectDecodedCandidates(source)).toEqual([]);
      expect(authenticatorDataStringCandidates(source)).toEqual([]);
      expect(authenticatorDataHexCandidates(source)).toEqual([]);
    });
  });

  it('reads a kept response\'s nested response, else the response itself', () => {
    const nested = { attestationObject: 'x' };
    expect(resolveStoredRegistrationResponse({ response: nested })).toBe(nested);
    const flat = { attestationObject: 'x', response: 'not an object' };
    expect(resolveStoredRegistrationResponse(flat)).toBe(flat);
    expect(resolveStoredRegistrationResponse(null)).toBeNull();
    expect(resolveStoredRegistrationResponse('text')).toBeNull();
  });
});

describe('pickFirstString and pickFirstObject', () => {
  it('pick the first text that is not blank, trimmed', () => {
    expect(pickFirstString(null, 42, '  ', ' packed ', 'none')).toBe('packed');
    expect(pickFirstString(undefined, '')).toBe('');
    expect(pickFirstString()).toBe('');
  });

  it('pick the first object', () => {
    const object = { a: 1 };
    expect(pickFirstObject(null, 'text', 0, object, {})).toBe(object);
    expect(pickFirstObject(undefined, 'text')).toBeNull();
  });
});
