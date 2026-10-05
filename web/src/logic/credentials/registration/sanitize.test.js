import { describe, expect, it } from 'vitest';

import {
  removeKeysCaseInsensitive,
  removeKeysFromObject,
  sanitiseRegistrationData,
  sanitizeParsedCertificateDetails,
  stripCertificateCollections,
  stripSignatureFormatting,
} from './sanitize.js';
import { advancedComplete } from '@/test/logic/credentials/registration-detail-answers.js';

// What the registration view leaves out of the data it shows
// (credentials/registration/sanitize.js).

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
