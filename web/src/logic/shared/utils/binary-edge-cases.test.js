import { afterEach, describe, expect, it, vi } from 'vitest';

import {
  base64ToBase64Url,
  base64UrlToHex,
  base64UrlToJson,
  base64UrlToUtf8String,
  currentFormatToBase64Url,
  currentFormatToJsonFormat,
  getCurrentBinaryFormat,
  hexToBase64,
  hexToGuid,
  hexToJs,
  hexToUint8Array,
  jsToHex,
  normalizeToHex,
} from './binary.js';

describe('the binary helpers given an empty value', () => {
  it.each([
    ['base64UrlToHex', base64UrlToHex],
    ['base64ToBase64Url', base64ToBase64Url],
    ['hexToBase64', hexToBase64],
    ['hexToGuid', hexToGuid],
    ['hexToJs', hexToJs],
    ['jsToHex', jsToHex],
    ['currentFormatToJsonFormat', currentFormatToJsonFormat],
    ['currentFormatToBase64Url', currentFormatToBase64Url],
  ])('%s answers an empty string', (_, convert) => {
    expect(convert('')).toBe('');
  });

  it.each([
    ['hexToUint8Array', hexToUint8Array],
    ['base64UrlToUtf8String', base64UrlToUtf8String],
    ['base64UrlToJson', base64UrlToJson],
  ])('%s answers null', (_, convert) => {
    expect(convert('')).toBeNull();
  });
});

describe('the binary helpers given text they cannot read', () => {
  it('formats no GUID from a value that is not sixteen bytes', () => {
    expect(hexToGuid('00112233')).toBe('');
  });

  it('reads no hex from text that is not a Uint8Array literal', () => {
    expect(jsToHex('Uint8Array.from([1, 2])')).toBe('');
  });

  it('parses no JSON from base64url that holds no bytes', () => {
    expect(base64UrlToJson(' ')).toBeNull();
  });

  it('normalizes a number to no hex', () => {
    expect(normalizeToHex(42)).toBe('');
  });
});

describe('the binary format in use', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('is hex where there is no window', () => {
    vi.stubGlobal('window', undefined);

    expect(getCurrentBinaryFormat()).toBe('hex');
  });
});
