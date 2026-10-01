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
    expect(getCredentialUserHandleHex({ userHandleBase64: 'QUJD' })).toBe('414243');
    expect(getCredentialUserHandleHex({ userId: 'AQID' })).toBe('010203');
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

  it('reads bytes, as an array, a view or a buffer', () => {
    expect(extractAuthenticatorDataHex([255, 0, 1])).toBe('ff0001');
    expect(extractAuthenticatorDataHex(new Uint8Array([1, 2, 3]))).toBe('010203');
    expect(extractAuthenticatorDataHex(new Uint8Array([7, 8]).buffer)).toBe('0708');
  });

  it('reads a JSON byte value, nested or not', () => {
    expect(extractAuthenticatorDataHex({ $hex: 'aa55' })).toBe('aa55');
    expect(extractAuthenticatorDataHex({ value: { $base64: 'QUJD' } })).toBe('414243');
  });

  it('finds no bytes in text it cannot read, a list that is not bytes, a number or an unknown object', () => {
    expect(extractAuthenticatorDataHex('   ')).toBe('');
    expect(extractAuthenticatorDataHex('@@@')).toBe('');
    expect(extractAuthenticatorDataHex([1, Symbol('x')])).toBe('');
    expect(extractAuthenticatorDataHex(37)).toBe('');
    expect(extractAuthenticatorDataHex({ unsupported: true })).toBe('');
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

  it('is read from the record\'s registration data, or from its properties\'', () => {
    expect(deriveAaguidFromCredentialData({ registrationData: { authenticatorData: ATTESTED } })).toBe(AAGUID);
    expect(deriveAaguidFromCredentialData({ properties: { registrationData: { authenticatorData: ATTESTED } } })).toBe(AAGUID);
    expect(deriveAaguidFromCredentialData({
      properties: { registrationData: { authenticatorData: ES256.authenticatorDataHex } },
    })).toBe(AAGUID);
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

  it('reads a JSON byte value', () => {
    expect(normalizeToHex({ $hex: '414243' })).toBe('414243');
    expect(normalizeToHex({ $base64url: 'QUJD' })).toBe('414243');
    expect(normalizeToHex({ $base64: 'QUJD' })).toBe('414243');
    expect(normalizeToHex({ $js: 'new Uint8Array([65, 66])' })).toBe('4142');
  });

  it('reads no hex from blank or unreadable text, a number or an object that spells no bytes', () => {
    expect(normalizeToHex('   ')).toBe('');
    expect(normalizeToHex('###not-binary###')).toBe('');
    expect(normalizeToHex(42)).toBe('');
    expect(normalizeToHex({ unsupported: true })).toBe('');
    expect(normalizeToHex({ $js: 'Uint8Array.from([1, 2])' })).toBe('');
    expect(normalizeToHex({ $js: '' })).toBe('');
  });
});
