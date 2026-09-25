import { describe, expect, it } from 'vitest';

import {
  Base64Error,
  base64ToBytes,
  base64UrlToBytes,
  bytesToBase64,
  bytesToBase64Url,
} from '../../../../frontend/static/scripts/shared/utils/base64.js';

const text = (value) => Uint8Array.from(value, (character) => character.charCodeAt(0));

// RFC 4648 section 10, plus bytes whose spelling differs between the alphabets.
const VECTORS = [
  [text(''), '', ''],
  [text('f'), 'Zg==', 'Zg'],
  [text('fo'), 'Zm8=', 'Zm8'],
  [text('foo'), 'Zm9v', 'Zm9v'],
  [text('foob'), 'Zm9vYg==', 'Zm9vYg'],
  [text('fooba'), 'Zm9vYmE=', 'Zm9vYmE'],
  [text('foobar'), 'Zm9vYmFy', 'Zm9vYmFy'],
  [new Uint8Array([0xfb, 0xff]), '+/8=', '-_8'],
  [new Uint8Array([0xfb, 0xef, 0xbe, 0x01]), '++++AQ==', '----AQ'],
  [Uint8Array.from({ length: 256 }, (_, index) => index), null, null],
];

describe('strict base64 and base64url', () => {
  it.each(VECTORS)('round-trips %s', (bytes, standard, urlSafe) => {
    const encodedStandard = bytesToBase64(bytes);
    const encodedUrl = bytesToBase64Url(bytes);
    if (standard !== null) {
      expect(encodedStandard).toBe(standard);
      expect(encodedUrl).toBe(urlSafe);
    }
    expect(Array.from(base64ToBytes(encodedStandard))).toEqual(Array.from(bytes));
    expect(Array.from(base64UrlToBytes(encodedUrl))).toEqual(Array.from(bytes));
  });

  it('encodes from an ArrayBuffer or an array too', () => {
    expect(bytesToBase64Url(new Uint8Array([0xfb, 0xff]).buffer)).toBe('-_8');
    expect(bytesToBase64([0xfb, 0xff])).toBe('+/8=');
  });

  it.each([
    ['padding', 'Zg=='],
    ['the standard alphabet', '+/8'],
    ['whitespace', 'Zm9v Yg'],
    ['a length no bytes have', 'Zm9vY'],
    ['unused bits set', 'Zh'],
    ['a character from neither alphabet', 'Zm9v*g'],
  ])('base64url refuses %s', (_label, value) => {
    expect(() => base64UrlToBytes(value)).toThrow(Base64Error);
  });

  it.each([
    ['no padding', 'Zg'],
    ['short padding', 'Zg='],
    ['padding in the middle', 'Zg==Zg=='],
    ['too much padding', 'Z==='],
    ['the url-safe alphabet', '-_8='],
    ['whitespace', 'Zm9v Yg=='],
    ['unused bits set', 'Zh=='],
  ])('base64 refuses %s', (_label, value) => {
    expect(() => base64ToBytes(value)).toThrow(Base64Error);
  });

  it('refuses what is not a string, naming the error', () => {
    expect(() => base64UrlToBytes(null)).toThrow('base64url must be a string');
    expect(() => base64ToBytes(new Uint8Array(1))).toThrow('base64 must be a string');
    try {
      base64UrlToBytes('Zm9v*g');
    } catch (error) {
      expect(error.name).toBe('Base64Error');
      expect(error.message).toBe('base64url has "*" at position 4, outside its alphabet');
    }
  });
});
