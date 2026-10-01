import { describe, expect, it } from 'vitest';

import { Base64Error, bytesToBase64Url } from './base64.js';
import {
  base64ToBase64Url,
  base64ToHex,
  base64UrlToHex,
  base64UrlToJson,
  base64UrlToUtf8String,
  bufferSourceToUint8Array,
  bytesToHex,
  generateRandomHex,
  hexToUint8Array,
} from './bytes.js';

// Bytes in their spellings (shared/bytes.js).

describe('hex', () => {
  it('spells bytes, and nothing for none', () => {
    expect(bytesToHex(new Uint8Array([0x41, 0x42, 0x43]))).toBe('414243');
    expect(bytesToHex(null)).toBe('');
  });

  it('is read as bytes, whitespace and case aside', () => {
    expect(Array.from(hexToUint8Array('0a0B 0c'))).toEqual([10, 11, 12]);
  });

  it('reads as no bytes when empty, odd or not hex', () => {
    expect(hexToUint8Array('')).toBeNull();
    expect(hexToUint8Array('0a0')).toBeNull();
    expect(hexToUint8Array('zz')).toBeNull();
  });

  it('is drawn at random, two digits a byte', () => {
    expect(generateRandomHex(4)).toMatch(/^[0-9a-f]{8}$/);
  });
});

describe('base64 and base64url as hex', () => {
  it('reads either alphabet, padded or not', () => {
    expect(base64ToHex('QUJD')).toBe('414243');
    expect(base64UrlToHex('QUJD')).toBe('414243');
    expect(base64UrlToHex('QQ')).toBe('41');
  });

  it('refuses a base64url character in base64', () => {
    expect(() => base64ToHex('_w')).toThrow(Base64Error);
  });

  it('gives nothing for nothing', () => {
    expect(base64ToHex('')).toBe('');
    expect(base64UrlToHex('')).toBe('');
  });

  it('respells base64 as base64url', () => {
    expect(base64ToBase64Url('QUJD+/==')).toBe('QUJD-_');
    expect(base64ToBase64Url('')).toBe('');
  });
});

describe('text and JSON spelled in base64url', () => {
  const json = bytesToBase64Url(new TextEncoder().encode('{"a":1}'));

  it('are decoded', () => {
    expect(base64UrlToUtf8String(json)).toBe('{"a":1}');
    expect(base64UrlToJson(json)).toEqual({ a: 1 });
  });

  it('are none for nothing', () => {
    expect(base64UrlToUtf8String('')).toBeNull();
    expect(base64UrlToJson('')).toBeNull();
    expect(base64UrlToJson(' ')).toBeNull();
  });

  it('read no JSON from text that is not JSON or not base64url, and no text from what is not base64url', () => {
    expect(base64UrlToJson('QQ')).toBeNull();
    expect(base64UrlToJson('not base64url!')).toBeNull();
    expect(() => base64UrlToUtf8String('not base64url!')).toThrow(Base64Error);
  });
});

describe('a buffer source', () => {
  it('is viewed as bytes, from a buffer or any view', () => {
    const bytes = new Uint8Array([1, 2, 3]);
    expect(Array.from(bufferSourceToUint8Array(bytes))).toEqual([1, 2, 3]);
    expect(Array.from(bufferSourceToUint8Array(bytes.buffer))).toEqual([1, 2, 3]);
    expect(Array.from(bufferSourceToUint8Array(new DataView(bytes.buffer, 1)))).toEqual([2, 3]);
  });

  it('is none for anything else', () => {
    expect(bufferSourceToUint8Array([1, 2])).toBeNull();
  });
});
