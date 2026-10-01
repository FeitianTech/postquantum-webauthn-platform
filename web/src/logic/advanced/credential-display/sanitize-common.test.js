import { describe, expect, it } from 'vitest';

import {
  removeKeysCaseInsensitive,
  removeKeysFromObject,
  sanitiseRegistrationData,
  sanitizeParsedCertificateDetails,
  sanitizeRelyingPartyInfo,
  stripCertificateCollections,
  stripSignatureFormatting,
} from './sanitize-common.js';
import { advancedComplete, registration } from '@/test/logic/advanced/credentials/registration-detail-answers.js';

// What the registration view leaves out of the data it shows
// (advanced/credential-display/sanitize-common.js).

/** The advanced registration's relying party, as register-complete answers it (with its certificates). */
const advancedRelyingParty = () => advancedComplete().relyingParty;

describe('stripCertificateCollections', () => {
  it('removes the certificate lists at every depth', () => {
    const target = {
      attestationCertificate: {},
      attestationCertificates: [],
      nested: { attestationCertificate: 'MIIB', keep: 1 },
      list: [{ attestationCertificates: [] }, 'MIIB'],
    };
    stripCertificateCollections(target);
    expect(target).toEqual({ nested: { keep: 1 }, list: [{}, 'MIIB'] });
  });

  it('leaves alone what is not a map', () => {
    expect(() => stripCertificateCollections(null)).not.toThrow();
  });
});

describe('removeKeysFromObject', () => {
  it('removes the keys at every depth, in lists too', () => {
    const target = [{ summary: 'Version: 3', raw: 'o2Nm', a: { raw: 1, b: [{ summary: 2, c: 3 }, 'raw'] } }];
    removeKeysFromObject(target, ['summary', 'raw']);
    expect(target).toEqual([{ a: { b: [{ c: 3 }, 'raw'] } }]);
  });

  it('matches the keys exactly', () => {
    const target = { Summary: 'Version: 3' };
    removeKeysFromObject(target, ['summary']);
    expect(target).toEqual({ Summary: 'Version: 3' });
  });

  it('does nothing without keys or a map', () => {
    const target = { raw: 'o2Nm' };
    removeKeysFromObject(target, []);
    removeKeysFromObject(target, 'raw');
    removeKeysFromObject(null, ['raw']);
    expect(target).toEqual({ raw: 'o2Nm' });
  });
});

describe('removeKeysCaseInsensitive', () => {
  it('removes the keys whatever their case, at every depth, in lists too', () => {
    const target = [{ PublicKeyHex: 'a5', nested: [{ publickeyhexlines: ['a5'], keep: 3 }, 'publicKeyHex'] }];
    removeKeysCaseInsensitive(target, ['publicKeyHex', 'publicKeyHexLines']);
    expect(target).toEqual([{ nested: [{ keep: 3 }, 'publicKeyHex'] }]);
  });

  it('does nothing without keys or a map', () => {
    const target = { publicKeyHex: 'a5' };
    removeKeysCaseInsensitive(target, []);
    removeKeysCaseInsensitive(target, 'publicKeyHex');
    removeKeysCaseInsensitive('publicKeyHex', ['publicKeyHex']);
    expect(target).toEqual({ publicKeyHex: 'a5' });
  });
});

describe('stripSignatureFormatting', () => {
  it("removes a certificate signature's colon text and lines, keeping its bytes", () => {
    const certificate = advancedRelyingParty().attestationCertificate;
    const target = { attStmt: { x5c: [{ parsedX5c: certificate }] } };
    stripSignatureFormatting(target);
    const { colon, lines, ...rest } = advancedRelyingParty().attestationCertificate.signature;
    expect(colon).toBeTruthy();
    expect(lines).toHaveLength(4);
    expect(target.attStmt.x5c[0].parsedX5c.signature).toEqual(rest);
  });

  it('does the same under sig, and leaves a signature that is not a map', () => {
    const target = { sig: { colon: '30:45', lines: [], hex: '3045' }, signature: 'MEUC' };
    stripSignatureFormatting(target);
    expect(target).toEqual({ sig: { hex: '3045' }, signature: 'MEUC' });
  });

  it('keeps a signature map without formatting as it is', () => {
    const target = { signature: { hex: '3045' } };
    stripSignatureFormatting(target);
    expect(target).toEqual({ signature: { hex: '3045' } });
  });

  it('leaves alone what is not a map', () => {
    expect(() => stripSignatureFormatting(undefined)).not.toThrow();
  });
});

describe('sanitizeParsedCertificateDetails', () => {
  it("leaves out a certificate's encodings, summary and error", () => {
    const certificate = advancedRelyingParty().attestationCertificate;
    const { pem, derBase64, summary, ...rest } = certificate;
    expect([pem, derBase64, summary].every(Boolean)).toBe(true);
    expect(sanitizeParsedCertificateDetails({ ...certificate, der: 'MIIB', raw: '3082', error: 'x' })).toEqual(rest);
  });

  it("leaves out each extension's raw bytes", () => {
    const extension = {
      oid: '2.5.29.19', raw: '3000', hex: '3000', rawHex: '3000', der: 'MAA=', derBase64: 'MAA=', valueHex: '3000',
      value: { CA: 'FALSE' },
    };
    expect(sanitizeParsedCertificateDetails({ extensions: [extension] })).toEqual({
      extensions: [{ oid: '2.5.29.19', value: { CA: 'FALSE' } }],
    });
  });

  it('drops the extensions that are not maps', () => {
    expect(sanitizeParsedCertificateDetails({ extensions: [null, '2.5.29.19', { oid: '2.5.29.19' }] })).toEqual({
      extensions: [{ oid: '2.5.29.19' }],
    });
  });

  it('has no details for what is not a map', () => {
    expect(sanitizeParsedCertificateDetails(null)).toBeNull();
    expect(sanitizeParsedCertificateDetails('MIIB')).toBeNull();
  });
});

describe('sanitiseRegistrationData', () => {
  it('leaves out the raw attestation and client data, the certificates and the signature formatting', () => {
    const raw = {
      attestationObject: 'o2Nm',
      attStmt: {},
      rawClientDataJSON: 'eyJ0',
      nested: { RawAuthenticatorData: 'SZYN', ATTESTATIONSTATEMENT: {}, keep: 1 },
      attestationCertificates: [],
      signature: { colon: '30:45', lines: [], hex: '3045' },
    };
    expect(sanitiseRegistrationData(raw)).toEqual({ nested: { keep: 1 }, signature: { hex: '3045' } });
  });

  it('works on a copy', () => {
    const raw = { attestationObject: 'o2Nm' };
    sanitiseRegistrationData(raw);
    expect(raw).toEqual({ attestationObject: 'o2Nm' });
  });

  it('has no data for what is not a map', () => {
    expect(sanitiseRegistrationData(null)).toBeNull();
    expect(sanitiseRegistrationData('SZYN')).toBeNull();
  });
});

describe("sanitizeRelyingPartyInfo: a registration's relying party", () => {
  const NO_SUMMARY = { authenticatorDataHex: '', authenticatorDataHash: '' };

  it('leaves out what the registration view shows elsewhere', () => {
    const copy = sanitizeRelyingPartyInfo(advancedRelyingParty(), NO_SUMMARY);
    expect(Object.keys(copy).sort()).toEqual([
      'aaguid', 'attestationSummary', 'authenticatorData', 'authenticatorDataHash', 'createdAt', 'credentialId',
      'largeBlob', 'publicKeyAlgorithm', 'registrationData', 'rpIdHash', 'rpIdHashBase64', 'rpIdHashExpected',
      'rpIdHashExpectedBase64', 'rpIdHashMatch',
    ]);
    expect(Object.keys(copy.registrationData).sort()).toEqual([
      'attestationChecks', 'attestationSummary', 'authenticatorData', 'authenticatorDataHash',
    ]);
    expect(copy.registrationData.attestationChecks).not.toHaveProperty('signature_valid');
    expect(copy.registrationData.attestationChecks).not.toHaveProperty('root_valid');
    expect(copy.registrationData.attestationChecks).not.toHaveProperty('rp_id_hash_valid');
  });

  it("takes the attestation summary and the authenticator data from the registration data", () => {
    const relyingParty = advancedRelyingParty();
    const copy = sanitizeRelyingPartyInfo(relyingParty, NO_SUMMARY);
    expect(copy.attestationSummary).toEqual(relyingParty.registrationData.attestationSummary);
    expect(copy.authenticatorData).toBe(relyingParty.registrationData.authenticatorData);
    expect(copy.authenticatorDataHash).toBe(relyingParty.authenticatorDataHash);
  });

  it('works on a copy', () => {
    const relyingParty = advancedRelyingParty();
    sanitizeRelyingPartyInfo(relyingParty, NO_SUMMARY);
    expect(relyingParty).toEqual(advancedRelyingParty());
  });

  it("puts the view's hex and hash in place of the relying party's, keeping the registration data's", () => {
    const relyingParty = registration('es256').relyingParty;
    const copy = sanitizeRelyingPartyInfo(relyingParty, { authenticatorDataHex: ' abcd ', authenticatorDataHash: ' ef01 ' });
    expect([copy.authenticatorData, copy.authenticatorDataHash]).toEqual(['abcd', 'ef01']);
    expect(copy.registrationData.authenticatorData).toBe(relyingParty.registrationData.authenticatorData);
    expect(copy.registrationData.authenticatorDataHash).toBe(relyingParty.registrationData.authenticatorDataHash);
  });

  it("gives the registration data the view's hex and hash when it has none", () => {
    const copy = sanitizeRelyingPartyInfo({ registrationData: { signatureCounter: 0 } }, { authenticatorDataHex: 'abcd', authenticatorDataHash: 'ef01' });
    expect(copy).toEqual({
      registrationData: { authenticatorData: 'abcd', authenticatorDataHash: 'ef01' },
      authenticatorData: 'abcd',
      authenticatorDataHash: 'ef01',
    });
  });

  it('reads the hex the relying party holds, without its spaces, in lower case', () => {
    expect(sanitizeRelyingPartyInfo({ authenticatorData: 'AB CD\nEF 01' })).toEqual({ authenticatorData: 'abcdef01' });
  });

  it("passes over blank authenticator data for the registration data's", () => {
    const copy = sanitizeRelyingPartyInfo({ authenticatorData: '  ', registrationData: { authenticatorData: 'abcd', signatureCounter: 0 } });
    expect(copy).toEqual({ registrationData: { authenticatorData: 'abcd' }, authenticatorData: 'abcd' });
  });

  it('keeps authenticator data that is not hex as it is', () => {
    const base64url = registration('es256').authenticatorData;
    expect(sanitizeRelyingPartyInfo({ authenticatorData: base64url, registrationData: { authenticatorData: 5 } })).toMatchObject({ authenticatorData: base64url });
    expect(sanitizeRelyingPartyInfo({ authenticatorData: 'abc' })).toEqual({ authenticatorData: 'abc' });
  });

  it('drops registration data that is not a map', () => {
    expect(sanitizeRelyingPartyInfo({ registrationData: 'SZYN', rpIdHashMatch: true })).toEqual({ rpIdHashMatch: true });
  });

  it('keeps its own attestation summary over the registration data\'s', () => {
    const info = {
      attestationSummary: { verified: true },
      registrationData: { attestationSummary: { verified: false } },
    };
    expect(sanitizeRelyingPartyInfo(info)).toEqual(info);
  });

  it('leaves out the errors about the AAGUID from a list', () => {
    const copy = sanitizeRelyingPartyInfo({ errors: ['AAGUID mismatch', 'signature failed', { code: 1 }] });
    expect(copy.errors).toEqual(['signature failed', { code: 1 }]);
  });

  it('drops a list of errors left empty', () => {
    expect(sanitizeRelyingPartyInfo({ errors: ['aaguid mismatch'], rpIdHashMatch: true })).toEqual({ rpIdHashMatch: true });
  });

  it('leaves out the errors about the AAGUID from a map', () => {
    const copy = sanitizeRelyingPartyInfo({
      errors: { aaguid: 'AAGUID mismatch', signature: 'bad', list: ['aaguid x', 'other'], gone: ['AAGUID y'], count: 3 },
    });
    expect(copy.errors).toEqual({ signature: 'bad', list: ['other'], count: 3 });
  });

  it('drops a map of errors left empty, and keeps errors that are text', () => {
    expect(sanitizeRelyingPartyInfo({ errors: { aaguid: 'AAGUID mismatch' }, rpIdHashMatch: true })).toEqual({ rpIdHashMatch: true });
    expect(sanitizeRelyingPartyInfo({ errors: 'AAGUID mismatch' })).toEqual({ errors: 'AAGUID mismatch' });
  });
});

describe('sanitizeRelyingPartyInfo without a relying party', () => {
  it('has nothing without a relying party or a hash', () => {
    expect(sanitizeRelyingPartyInfo(null)).toBeNull();
    expect(sanitizeRelyingPartyInfo('relying party', { authenticatorDataHex: 5, authenticatorDataHash: null })).toBeNull();
  });

  it("gives the view's hex and hash alone", () => {
    expect(sanitizeRelyingPartyInfo(null, { authenticatorDataHex: 'abcd', authenticatorDataHash: 'ef01' })).toEqual({
      authenticatorData: 'abcd',
      authenticatorDataHash: 'ef01',
    });
    expect(sanitizeRelyingPartyInfo(undefined, { authenticatorDataHash: 'ef01' })).toEqual({ authenticatorDataHash: 'ef01' });
    expect(sanitizeRelyingPartyInfo(undefined, { authenticatorDataHex: 'abcd' })).toEqual({ authenticatorData: 'abcd' });
  });
});
