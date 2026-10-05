import { describe, expect, it } from 'vitest';

import { sanitizeRelyingPartyInfo } from './relying-party.js';
import { advancedComplete, registration } from '@/test/logic/credentials/registration-detail-answers.js';

// The relying party's view of a registration as the registration view shows it
// (credentials/registration/relying-party.js).


describe("sanitizeRelyingPartyInfo: a registration's relying party", () => {
  const NO_SUMMARY = { authenticatorDataHex: '', authenticatorDataHash: '' };

  it('leaves out what the registration view shows elsewhere', () => {
    const copy = sanitizeRelyingPartyInfo(advancedComplete().relyingParty, NO_SUMMARY);
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
    const relyingParty = advancedComplete().relyingParty;
    const copy = sanitizeRelyingPartyInfo(relyingParty, NO_SUMMARY);
    expect(copy.attestationSummary).toEqual(relyingParty.registrationData.attestationSummary);
    expect(copy.authenticatorData).toBe(relyingParty.registrationData.authenticatorData);
    expect(copy.authenticatorDataHash).toBe(relyingParty.authenticatorDataHash);
  });

  it('works on a copy', () => {
    const relyingParty = advancedComplete().relyingParty;
    sanitizeRelyingPartyInfo(relyingParty, NO_SUMMARY);
    expect(relyingParty).toEqual(advancedComplete().relyingParty);
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
