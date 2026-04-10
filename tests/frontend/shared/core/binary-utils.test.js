import { describe, expect, it, vi } from 'vitest';

import { state } from '../../../../frontend/static/scripts/shared/state.js';
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
  bytesToHex,
  bufferSourceToUint8Array,
  convertCredProtectValue,
  convertExtensionsForClient,
  convertFormat,
  convertLargeBlobExtension,
  convertPrfExtension,
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
} from '../../../../frontend/static/scripts/shared/binary-utils.js';

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

    window.__binaryFormat = 'b64';
    expect(getCurrentBinaryFormat()).toBe('b64');
    expect(currentFormatToJsonFormat('QUJD')).toEqual({ $base64: 'QUJD' });

    window.__binaryFormat = 'b64u';
    expect(getCurrentBinaryFormat()).toBe('b64u');
    expect(currentFormatToJsonFormat('QUJD')).toEqual({ $base64url: 'QUJD' });

    window.__binaryFormat = 'js';
    expect(getCurrentBinaryFormat()).toBe('js');
    expect(currentFormatToJsonFormat('new Uint8Array([1,2])')).toEqual({ $js: 'new Uint8Array([1,2])' });

    window.__binaryFormat = 'unexpected-format';
    expect(getCurrentBinaryFormat()).toBe('unexpected-format');
    expect(currentFormatToJsonFormat('414243')).toEqual({ $base64url: '' });

    delete window.__binaryFormat;
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
          cred1: { first: { $hex: '4142' }, second: { $base64url: 'QUJDRA' } },
        },
        passthrough: 'keep-me',
      },
      credProps: true,
      custom: 'value',
    });

    expect(converted.credentialProtectionPolicy).toBe('userVerificationOptionalWithCredentialIDList');
    expect(converted.enforceCredentialProtectionPolicy).toBe(true);
    expect(converted.largeBlob.write).toBeInstanceOf(ArrayBuffer);
    expect(converted.prf.eval.first).toBeInstanceOf(ArrayBuffer);
    expect(converted.prf.evalByCredential.cred1.first).toBeInstanceOf(ArrayBuffer);
    expect(converted.prf.evalByCredential.cred1.second).toBeInstanceOf(ArrayBuffer);
    expect(converted.prf.passthrough).toBe('keep-me');
    expect(converted.credProps).toBe(true);
    expect(converted.custom).toBe('value');
    expect(convertExtensionsForClient(null)).toBeUndefined();

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
    expect(normalizeToHex('   ')).toBe('');
    expect(normalizeToHex('QUJD')).toBe('414243');
    expect(normalizeToHex({ $base64: 'QUJD' })).toBe('414243');
    expect(normalizeToHex({ $hex: '414243' })).toBe('414243');
    expect(normalizeToHex({ $base64url: 'QUJD' })).toBe('414243');
    expect(normalizeToHex({ $js: 'new Uint8Array([65, 66])' })).toBe('4142');
    expect(normalizeToHex('###not-binary###')).toBe('');
    expect(normalizeToHex({ unsupported: true })).toBe('');

    expect(sortObjectKeys([{ z: 1, a: 2 }, { b: { d: 4, c: 3 } }])).toEqual([
      { a: 2, z: 1 },
      { b: { c: 3, d: 4 } },
    ]);
  });

  it('covers conversion and extension fallback branches for malformed or alternate inputs', () => {
    expect(hexToBase64Url('f')).toBe('Dw');
    expect(bytesToHex(null)).toBe('');
    expect(base64UrlToHexFixed('QQ')).toBe('41');

    expect(convertFormat('QUJD', 'b64', 'hex')).toBe('414243');
    expect(convertFormat('new Uint8Array([65, 66])', 'js', 'hex')).toBe('4142');
    expect(convertFormat('4142', 'hex', 'b64')).toBe('QUI=');
    expect(convertFormat('4142', 'hex', 'js')).toBe('new Uint8Array([65, 66])');
    expect(convertFormat('4142', 'hex', 'unknown')).toBe('4142');

    expect(hexToUint8Array('zz')).toBeNull();
    expect(arrayBufferToHex(null)).toBe('');
    expect(arrayBufferToHex({})).toBe('');
    expect(normalizeClientExtensionResults(42)).toBe(42);

    const rawBuffer = new Uint8Array([1, 2, 3]).buffer;
    expect(jsonValueToUint8Array(rawBuffer)).toEqual(new Uint8Array([1, 2, 3]));
    expect(jsonValueToUint8Array('   ')).toBeNull();
    expect(jsonValueToUint8Array('QQ')).toEqual(new Uint8Array([65]));
    expect(jsonValueToUint8Array({ $js: '[1,2,3]' })).toEqual(new Uint8Array([1, 2, 3]));

    expect(convertCredProtectValue('userVerificationRequired')).toBe('userVerificationRequired');
    expect(convertCredProtectValue(true)).toBe(true);

    expect(convertLargeBlobExtension(null)).toBeNull();
    expect(convertLargeBlobExtension('required')).toEqual({ support: 'required' });
    expect(convertLargeBlobExtension(7)).toBe(7);

    const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
    expect(convertLargeBlobExtension({ support: { $js: 'not-json' } })).toEqual({ support: 'not-json' });
    warnSpy.mockRestore();

    expect(convertPrfExtension('not-object')).toBe('not-object');
    const convertedPrf = convertPrfExtension({
      eval: {
        first: { $hex: '41' },
        second: { $base64url: 'Qg' },
      },
      evalByCredential: {
        credA: {
          first: { $hex: '43' },
          second: { $base64: 'RA==' },
        },
      },
      passthrough: 'keep',
    });
    expect(convertedPrf.eval.second).toBeInstanceOf(ArrayBuffer);
    expect(convertedPrf.evalByCredential.credA.second).toBeInstanceOf(ArrayBuffer);
    expect(convertedPrf.passthrough).toBe('keep');
  });

  it('returns null for utf8 and json decode failures without throwing', () => {
    const originalDecoder = state.utf8Decoder;
    state.utf8Decoder = {
      decode() {
        throw new Error('decode failure');
      },
    };

    expect(base64UrlToUtf8String('QQ')).toBeNull();

    state.utf8Decoder = new TextDecoder('utf-8');
    expect(base64UrlToJson('QQ')).toBeNull();

    state.utf8Decoder = originalDecoder;
  });
});
