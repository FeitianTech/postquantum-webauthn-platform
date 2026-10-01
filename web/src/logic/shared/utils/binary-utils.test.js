import { describe, expect, it } from 'vitest';

import { state } from '../state.js';
import { Base64Error } from './base64.js';
import {
  base64ToBase64Url,
  base64ToHex,
  base64UrlToHex,
  base64UrlToJson,
  base64UrlToUtf8String,
  bytesToHex,
  bufferSourceToUint8Array,
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
  normalizeToHex,
  sortObjectKeys,
} from './binary.js';

describe('binary-utils', () => {
  it('converts between supported binary formats', () => {
    expect(isValidHex('deadbeef')).toBe(true);
    expect(isValidHex('')).toBe(false);

    expect(hexToBase64('414243')).toBe('QUJD');
    expect(base64ToHex('QUJD')).toBe('414243');
    expect(base64ToBase64Url('QUJD+/==')).toBe('QUJD-_');
    expect(hexToBase64Url('414243')).toBe('QUJD');
    expect(base64UrlToHex('QUJD')).toBe('414243');
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

    const bytes = new Uint8Array([1, 2, 3]);
    const view = bufferSourceToUint8Array(bytes);
    expect(Array.from(view)).toEqual([1, 2, 3]);
  });

  it('decodes structured values', () => {
    const originalDecoder = state.utf8Decoder;
    state.utf8Decoder = new TextDecoder('utf-8');

    const jsonValue = hexToBase64Url('7b2261223a317d');
    expect(base64UrlToUtf8String(jsonValue)).toBe('{"a":1}');
    expect(base64UrlToJson(jsonValue)).toEqual({ a: 1 });

    state.utf8Decoder = originalDecoder;
  });

  it('normalizes values to hex and sorts objects', () => {
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

  it('reads malformed or alternate inputs as their conversions allow', () => {
    expect(hexToBase64Url('f')).toBe('Dw');
    expect(() => hexToBase64Url('zz')).toThrow(Base64Error);
    expect(() => hexToBase64('abc')).toThrow(Base64Error);
    expect(bytesToHex(null)).toBe('');
    expect(base64UrlToHex('QQ')).toBe('41');

    expect(convertFormat('QUJD', 'b64', 'hex')).toBe('414243');
    expect(convertFormat('new Uint8Array([65, 66])', 'js', 'hex')).toBe('4142');
    expect(convertFormat('4142', 'hex', 'b64')).toBe('QUI=');
    expect(convertFormat('4142', 'hex', 'js')).toBe('new Uint8Array([65, 66])');
    expect(convertFormat('4142', 'hex', 'unknown')).toBe('4142');

    expect(hexToUint8Array('zz')).toBeNull();
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
