import { describe, expect, it, vi } from 'vitest';

import { state } from '../../static/scripts/shared/state.js';
import {
  arrayBufferToHex,
  base64ToBase64Url,
  base64ToHex,
  base64ToUint8Array,
  base64UrlToHex,
  base64UrlToHexFixed,
  base64UrlToJson,
  base64UrlToUint8Array,
  base64UrlToUtf8String,
  bufferSourceToUint8Array,
  convertExtensionsForClient,
  convertFormat,
  currentFormatToBase64Url,
  currentFormatToJsonFormat,
  generateRandomHex,
  getCurrentBinaryFormat,
  hexToBase64,
  hexToBase64Url,
  hexToGuid,
  hexToJs,
  hexToUint8Array,
  isValidHex,
  jsToHex,
  jsonValueToArrayBuffer,
  jsonValueToUint8Array,
  normalizeClientExtensionResults,
  normalizeToHex,
  sortObjectKeys,
} from '../../static/scripts/shared/binary-utils.js';

describe('binary-utils', () => {
  it('converts between supported binary formats', () => {
    expect(isValidHex('deadbeef')).toBe(true);
    expect(isValidHex('')).toBe(false);

    expect(hexToBase64('414243')).toBe('QUJD');
    expect(base64ToHex('QUJD')).toBe('414243');
    expect(base64ToBase64Url('QUJD+/==')).toBe('QUJD-_');
    expect(hexToBase64Url('414243')).toBe('QUJD');
    expect(base64UrlToHex('QUJD')).toBe('414243');
    expect(base64UrlToHexFixed('QUJD')).toBe('414243');
    expect(hexToGuid('00112233445566778899aabbccddeeff')).toBe('00112233-4455-6677-8899-aabbccddeeff');
    expect(hexToJs('0a0b')).toBe('new Uint8Array([10, 11])');
    expect(jsToHex('new Uint8Array([10, 11])')).toBe('0a0b');
    expect(convertFormat('414243', 'hex', 'b64u')).toBe('QUJD');
    expect(convertFormat('QUJD', 'b64u', 'hex')).toBe('414243');
    expect(getCurrentBinaryFormat()).toBe('hex');
    expect(currentFormatToJsonFormat('414243')).toEqual({ $hex: '414243' });
    expect(currentFormatToBase64Url('414243')).toBe('QUJD');
  });

  it('handles array and buffer conversions', () => {
    const random = generateRandomHex(4);
    expect(random).toHaveLength(8);

    expect(Array.from(hexToUint8Array('0a0b0c'))).toEqual([10, 11, 12]);
    expect(hexToUint8Array('0a0')).toBeNull();
    expect(Array.from(base64ToUint8Array('QUJD'))).toEqual([65, 66, 67]);
    expect(Array.from(base64UrlToUint8Array('QUJD'))).toEqual([65, 66, 67]);

    const bytes = new Uint8Array([1, 2, 3]);
    const view = bufferSourceToUint8Array(bytes);
    expect(Array.from(view)).toEqual([1, 2, 3]);
    expect(arrayBufferToHex(bytes.buffer)).toBe('010203');
  });

  it('decodes structured values and extension payloads', () => {
    const originalDecoder = state.utf8Decoder;
    state.utf8Decoder = new TextDecoder('utf-8');

    const jsonValue = hexToBase64Url('7b2261223a317d');
    expect(base64UrlToUtf8String(jsonValue)).toBe('{"a":1}');
    expect(base64UrlToJson(jsonValue)).toEqual({ a: 1 });

    expect(jsonValueToUint8Array({ $hex: '0a0b' })).toEqual(new Uint8Array([10, 11]));
    expect(jsonValueToUint8Array({ $base64: 'QUJD' })).toEqual(new Uint8Array([65, 66, 67]));
    expect(jsonValueToUint8Array({ $base64url: 'QUJD' })).toEqual(new Uint8Array([65, 66, 67]));
    expect(jsonValueToUint8Array('4142')).toEqual(new Uint8Array([65, 66]));
    expect(jsonValueToArrayBuffer({ $hex: '4142' })).toBeInstanceOf(ArrayBuffer);

    const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
    expect(jsonValueToUint8Array({ $js: 'not-json' })).toBeNull();
    expect(warnSpy).toHaveBeenCalled();

    const converted = convertExtensionsForClient({
      credProtect: 2,
      enforceCredProtect: 1,
      largeBlob: { support: 'preferred', write: { $hex: '4142' } },
      prf: {
        eval: { first: { $hex: '41424344' } },
        evalByCredential: {
          cred1: { second: { $base64url: 'QUJDRA' } },
        },
      },
      credProps: true,
      custom: 'value',
    });

    expect(converted.credentialProtectionPolicy).toBe('userVerificationOptionalWithCredentialIDList');
    expect(converted.enforceCredentialProtectionPolicy).toBe(true);
    expect(converted.largeBlob.write).toBeInstanceOf(ArrayBuffer);
    expect(converted.prf.eval.first).toBeInstanceOf(ArrayBuffer);
    expect(converted.prf.evalByCredential.cred1.second).toBeInstanceOf(ArrayBuffer);
    expect(converted.credProps).toBe(true);
    expect(converted.custom).toBe('value');

    state.utf8Decoder = originalDecoder;
  });

  it('normalizes nested structures and sorts objects', () => {
    const nested = normalizeClientExtensionResults({
      direct: new Uint8Array([1, 2]),
      list: [new Uint8Array([3, 4]), { value: new Uint8Array([5]) }],
    });
    expect(nested).toEqual({
      direct: { $hex: '0102' },
      list: [{ $hex: '0304' }, { value: { $hex: '05' } }],
    });

    expect(sortObjectKeys({ z: 1, a: { c: 3, b: 2 } })).toEqual({
      a: { b: 2, c: 3 },
      z: 1,
    });

    expect(normalizeToHex('414243')).toBe('414243');
    expect(normalizeToHex('QUJD')).toBe('414243');
    expect(normalizeToHex({ $base64: 'QUJD' })).toBe('414243');
    expect(normalizeToHex({ $js: 'new Uint8Array([65, 66])' })).toBe('4142');
  });
});
