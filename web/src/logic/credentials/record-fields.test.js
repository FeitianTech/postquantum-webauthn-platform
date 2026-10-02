import { describe, expect, it } from 'vitest';

import {
  deriveAaguidFromCredentialData,
  extractAaguidFromAuthDataHex,
  extractAuthenticatorDataHex,
  getCredentialIdHex,
  getCredentialUserHandleHex,
  getStoredCredentialAttachment,
  normalizeAttachmentValue,
  normalizeToHex,
} from './record-fields.js';
import { goldenAnswers } from '@/test/logic/simple/ceremony-answers.js';

// A saved credential's fields as the pages compare them (credentials/record-fields.js).

// The saved record register-complete answers, as the characterization goldens hold it.
function storedCredential(scenario) {
  return goldenAnswers(scenario).find(({ body }) => body && body.storedCredential).body.storedCredential;
}

const ES256 = storedCredential('simple-register-es256');
const AAGUID = '00112233445566778899aabbccddeeff';
const ATTESTED = `${'00'.repeat(32)}40${'00'.repeat(4)}${AAGUID}`;

describe('getCredentialIdHex', () => {
  it('reads the credential id in hex from its base64url spelling', () => {
    expect(getCredentialIdHex({ credentialId: 'QUJD' })).toBe('414243');
  });

  it('finds none without a record or an id', () => {
    expect(getCredentialIdHex(null)).toBe('');
    expect(getCredentialIdHex({})).toBe('');
  });
});

describe('getCredentialUserHandleHex', () => {
  it('reads the user handle in hex from each spelling a record keeps', () => {
    expect(getCredentialUserHandleHex({ userHandleHex: '414243' })).toBe('414243');
    expect(getCredentialUserHandleHex({ userHandle: 'QUJD' })).toBe('414243');
    expect(getCredentialUserHandleHex({ userHandleBase64: 'QUJD' })).toBe('414243');
    expect(getCredentialUserHandleHex({ userHandleBase64Url: 'QUJD' })).toBe('414243');
  });

  it('reads no credential id or user handle from names no record uses', () => {
    expect(getCredentialIdHex({ credentialID: 'QUJD', rawId: 'QUJD' })).toBe('');
    expect(getCredentialUserHandleHex({ userId: 'AQID' })).toBe('');
  });

  it('finds none without a record or a handle', () => {
    expect(getCredentialUserHandleHex(null)).toBe('');
    expect(getCredentialUserHandleHex({})).toBe('');
  });
});

describe('the authenticator attachment', () => {
  it('is compared trimmed and in lower case', () => {
    expect(normalizeAttachmentValue(' Platform ')).toBe('platform');
  });

  it('is read from the record, else from its properties', () => {
    expect(getStoredCredentialAttachment({ authenticatorAttachment: 'cross-platform' })).toBe('cross-platform');
    expect(getStoredCredentialAttachment({ properties: { authenticatorAttachment: 'platform' } })).toBe('platform');
    expect(getStoredCredentialAttachment({ properties: { authenticatorAttachment: 'cross-platform' } })).toBe('cross-platform');
  });

  it('is none without a record, or in a record without one and without properties', () => {
    expect(getStoredCredentialAttachment(null)).toBe('');
    expect(getStoredCredentialAttachment({ ...ES256, properties: undefined })).toBe('');
  });
});

describe('extractAuthenticatorDataHex', () => {
  it('reads hex, base64 and base64url text', () => {
    expect(extractAuthenticatorDataHex('  aaBB  ')).toBe('aabb');
    expect(extractAuthenticatorDataHex('QUJD')).toBe('414243');
    expect(extractAuthenticatorDataHex('_w')).toBe('ff');
  });

  it('finds no bytes in text it cannot read, or in anything but text', () => {
    expect(extractAuthenticatorDataHex('   ')).toBe('');
    expect(extractAuthenticatorDataHex('@@@')).toBe('');
    expect(extractAuthenticatorDataHex(37)).toBe('');
    expect(extractAuthenticatorDataHex(new Uint8Array([1, 2, 3]))).toBe('');
    expect(extractAuthenticatorDataHex({ $hex: 'aa55' })).toBe('');
  });
});

describe('the AAGUID in the authenticator data', () => {
  it('is read when the attested credential data flag is set', () => {
    expect(extractAaguidFromAuthDataHex(ATTESTED)).toBe(AAGUID);
  });

  it('is none without the flag, or in data too short to hold one', () => {
    expect(extractAaguidFromAuthDataHex(`${'00'.repeat(32)}00${'00'.repeat(4)}${AAGUID}`)).toBe('');
    expect(extractAaguidFromAuthDataHex('00')).toBe('');
  });

  it('is read from the relying party\'s registration data, else from the record\'s authenticator data', () => {
    expect(deriveAaguidFromCredentialData({ relyingParty: { registrationData: { authenticatorData: ATTESTED } } })).toBe(AAGUID);
    expect(deriveAaguidFromCredentialData({ authenticatorData: ES256.authenticatorData })).toBe(AAGUID);
    expect(deriveAaguidFromCredentialData({ authenticatorData: ES256.authenticatorDataHex })).toBe(AAGUID);
  });

  it('is not read from places no record keeps authenticator data', () => {
    expect(deriveAaguidFromCredentialData({ registrationData: { authenticatorData: ATTESTED } })).toBe('');
    expect(deriveAaguidFromCredentialData({ properties: { registrationData: { authenticatorData: ATTESTED } } })).toBe('');
  });

  it('is none without a record or without authenticator data', () => {
    expect(deriveAaguidFromCredentialData(null)).toBe('');
    expect(deriveAaguidFromCredentialData({})).toBe('');
  });
});

describe('normalizeToHex', () => {
  it('reads hex or base64url text as lower-case hex', () => {
    expect(normalizeToHex('414243')).toBe('414243');
    expect(normalizeToHex('ABCD')).toBe('abcd');
    expect(normalizeToHex('QUJD')).toBe('414243');
  });

  it('reads no hex from blank or unreadable text, or from anything but text', () => {
    expect(normalizeToHex('   ')).toBe('');
    expect(normalizeToHex('###not-binary###')).toBe('');
    expect(normalizeToHex(42)).toBe('');
    // No record holds an ID as a JSON byte value.
    expect(normalizeToHex({ $hex: '414243' })).toBe('');
  });
});
