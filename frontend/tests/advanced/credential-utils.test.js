import { describe, expect, it } from 'vitest';

import {
  deriveAaguidDisplayValues,
  deriveAaguidFromCredentialData,
  extractAaguidFromAuthDataHex,
  extractAuthenticatorDataHex,
  extractHexFromJsonFormat,
  extractMinPinLengthValue,
  getCoseMapValue,
  getCredentialIdHex,
  getCredentialUserHandleHex,
  getStoredCredentialAttachment,
  normaliseAaguidValue,
  normalizeAttachmentValue,
  normalizeMinPinLengthValue,
} from '../../static/scripts/advanced/credential-utils.js';

describe('credential-utils', () => {
  it('normalizes aaguid values from multiple encodings', () => {
    expect(normaliseAaguidValue('00112233445566778899aabbccddeeff')).toBe('00112233445566778899aabbccddeeff');
    expect(normaliseAaguidValue('ABEiM0RVZneImaq7zN3u/w==')).toBe('00112233445566778899aabbccddeeff');
    expect(normaliseAaguidValue([0, 17, 34, 51])).toBe('00112233');
    expect(normaliseAaguidValue(new Uint8Array([0, 17, 34, 51]))).toBe('00112233');
    expect(normaliseAaguidValue({ guid: '00112233-4455-6677-8899-aabbccddeeff' })).toBe('00112233445566778899aabbccddeeff');
  });

  it('extracts minimum pin length and authenticator metadata', () => {
    expect(normalizeMinPinLengthValue(4.9)).toBe(4);
    expect(normalizeMinPinLengthValue(' 6 ')).toBe(6);
    expect(normalizeMinPinLengthValue(-1)).toBeNull();

    expect(extractMinPinLengthValue({
      properties: { minPinLength: '8' },
    })).toBe(8);
    expect(extractMinPinLengthValue({
      clientExtensionOutputs: { minPinLength: { value: 7 } },
    })).toBe(7);
    expect(extractMinPinLengthValue({
      registrationData: { authenticatorExtensions: { minPinLength: 5 } },
    })).toBe(5);

    expect(extractAuthenticatorDataHex('QUJD')).toBe('414243');
    expect(extractAuthenticatorDataHex(new Uint8Array([1, 2, 3]))).toBe('010203');
    expect(extractAuthenticatorDataHex({ $hex: 'aa55' })).toBe('aa55');
  });

  it('derives AAGUID and credential display values', () => {
    const authDataHex = `${'00'.repeat(32)}40${'00'.repeat(4)}00112233445566778899aabbccddeeff`;
    expect(extractAaguidFromAuthDataHex(authDataHex)).toBe('00112233445566778899aabbccddeeff');
    expect(deriveAaguidFromCredentialData({
      registrationData: { authenticatorData: authDataHex },
    })).toBe('00112233445566778899aabbccddeeff');

    expect(getCoseMapValue({ 1: 'one', '-7': 'alg' }, -7)).toBe('alg');
    expect(getCredentialIdHex({ credentialId: 'QUJD' })).toBe('414243');
    expect(getCredentialUserHandleHex({ userHandleBase64: 'QUJD' })).toBe('414243');
    expect(normalizeAttachmentValue(' Platform ')).toBe('platform');
    expect(getStoredCredentialAttachment({
      properties: { authenticatorAttachment: 'cross-platform' },
    })).toBe('cross-platform');
    expect(extractHexFromJsonFormat({ $base64url: 'QUJD' })).toBe('414243');

    expect(deriveAaguidDisplayValues('00112233445566778899aabbccddeeff')).toEqual({
      aaguidHex: '00112233445566778899aabbccddeeff',
      aaguidB64: 'ABEiM0RVZneImaq7zN3u/w==',
      aaguidB64u: 'ABEiM0RVZneImaq7zN3u_w',
    });
  });

  it('returns empty aaguid when object hex resolver throws', () => {
    const broken = {
      hex() {
        throw new Error('bad hex encoder');
      },
    };

    expect(normaliseAaguidValue(broken)).toBe('');
  });

  it('normalises nested/object aaguid candidates and handles invalid array/object inputs', () => {
    const fromHexProperty = {
      hex: '00112233445566778899aabbccddeeff',
    };
    expect(normaliseAaguidValue(fromHexProperty)).toBe('00112233445566778899aabbccddeeff');

    const fromRawArray = {
      raw: [0, 17, 34, 51],
    };
    expect(normaliseAaguidValue(fromRawArray)).toBe('00112233');

    const fromNestedMetadata = {
      metadata: { aaguid: 'ABEiM0RVZneImaq7zN3u/w==' },
    };
    expect(normaliseAaguidValue(fromNestedMetadata)).toBe('00112233445566778899aabbccddeeff');

    const fromBase64Candidate = {
      base64url: 'ABEiM0RVZneImaq7zN3u_w',
    };
    expect(normaliseAaguidValue(fromBase64Candidate)).toBe('00112233445566778899aabbccddeeff');

    expect(normaliseAaguidValue({ guid: '00112233-4455-6677-8899-aabbccddeeff' })).toBe(
      '00112233445566778899aabbccddeeff',
    );

    expect(normaliseAaguidValue([1, Symbol('x')])).toBe('');
    expect(normaliseAaguidValue('')).toBe('');
    expect(normaliseAaguidValue('  ')).toBe('');
  });

  it('extracts min pin length across nested extension shapes and ignores invalid values', () => {
    expect(extractMinPinLengthValue(null)).toBeNull();
    expect(extractMinPinLengthValue({})).toBeNull();

    expect(extractMinPinLengthValue({
      properties: { min_pin_length: ' 12 ' },
    })).toBe(12);

    expect(extractMinPinLengthValue({
      clientExtensionOutputs: {
        minPinLength: {
          minimumPinLength: '9',
        },
      },
    })).toBe(9);

    expect(extractMinPinLengthValue({
      clientExtensionOutputs: {
        minPinLength: {
          value: 'not-a-number',
        },
      },
    })).toBeNull();

    expect(extractMinPinLengthValue({
      registrationData: {
        authenticatorExtensions: {
          minPinLength: -3,
        },
      },
    })).toBeNull();
  });

  it('handles authenticator data extraction fallbacks and attachment sources', () => {
    expect(extractAuthenticatorDataHex('  aaBB  ')).toBe('aabb');
    expect(extractAuthenticatorDataHex({ value: { $base64: 'QUJD' } })).toBe('414243');
    expect(extractAuthenticatorDataHex([255, 0, 1])).toBe('ff0001');

    const authDataWithoutAttestedFlag = `${'00'.repeat(32)}00${'00'.repeat(4)}00112233445566778899aabbccddeeff`;
    expect(extractAaguidFromAuthDataHex(authDataWithoutAttestedFlag)).toBe('');

    expect(deriveAaguidFromCredentialData({
      properties: {
        registration_data: {
          authenticator_data: `${'00'.repeat(32)}40${'00'.repeat(4)}00112233445566778899aabbccddeeff`,
        },
      },
    })).toBe('00112233445566778899aabbccddeeff');

    expect(getCoseMapValue(null, -7)).toBeUndefined();
    expect(getCoseMapValue({ '-8': 'eddsa' }, -8)).toBe('eddsa');

    expect(getCredentialIdHex(null)).toBe('');
    expect(getCredentialUserHandleHex({ userId: 'AQID' })).toBe('010203');

    expect(getStoredCredentialAttachment({ authenticator_attachment: 'cross-platform' })).toBe('cross-platform');
    expect(getStoredCredentialAttachment({ properties: { authenticator_attachment: 'platform' } })).toBe('platform');

    const bytes = new Uint8Array([0xde, 0xad, 0xbe, 0xef]);
    expect(extractHexFromJsonFormat(bytes)).toBe('deadbeef');
    expect(extractHexFromJsonFormat({ $base64: 'AQID' })).toBe('010203');

    expect(deriveAaguidDisplayValues('abc')).toEqual({
      aaguidHex: 'abc',
      aaguidB64: '',
      aaguidB64u: '',
    });
  });
});
