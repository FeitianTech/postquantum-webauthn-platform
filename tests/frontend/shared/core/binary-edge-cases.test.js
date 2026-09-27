import { afterEach, describe, expect, it, vi } from 'vitest';

import { state } from '../../../../frontend/static/scripts/shared/state.js';
import {
  base64ToBase64Url,
  base64ToUint8Array,
  base64UrlToHex,
  base64UrlToJson,
  base64UrlToUtf8String,
  convertCredProtectValue,
  convertExtensionsForClient,
  convertLargeBlobExtension,
  convertPrfExtension,
  currentFormatToBase64Url,
  currentFormatToJsonFormat,
  getCurrentBinaryFormat,
  hexToBase64,
  hexToGuid,
  hexToJs,
  hexToUint8Array,
  jsToHex,
  jsonValueToArrayBuffer,
  jsonValueToUint8Array,
  normalizeClientExtensionResults,
  normalizeToHex,
} from '../../../../frontend/static/scripts/shared/utils/binary.js';

const bytesOf = (buffer) => Array.from(new Uint8Array(buffer));

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
    ['base64ToUint8Array', base64ToUint8Array],
    ['base64UrlToUtf8String', base64UrlToUtf8String],
    ['base64UrlToJson', base64UrlToJson],
    ['jsonValueToUint8Array', jsonValueToUint8Array],
    ['jsonValueToArrayBuffer', jsonValueToArrayBuffer],
  ])('%s answers null', (_, convert) => {
    expect(convert('')).toBeNull();
  });

  it('leaves missing extension results as they were', () => {
    expect(normalizeClientExtensionResults(null)).toBeNull();
    expect(normalizeClientExtensionResults(undefined)).toBeUndefined();
  });

  it('sends no extensions for an empty extensions object', () => {
    expect(convertExtensionsForClient({})).toBeUndefined();
  });
});

describe('the binary helpers given text they cannot read', () => {
  it('formats no GUID from a value that is not sixteen bytes', () => {
    expect(hexToGuid('00112233')).toBe('');
  });

  it('reads no hex from text that is not a Uint8Array literal', () => {
    expect(jsToHex('Uint8Array.from([1, 2])')).toBe('');
  });

  it('decodes no text without a UTF-8 decoder', () => {
    const decoder = state.utf8Decoder;
    state.utf8Decoder = null;
    try {
      expect(base64UrlToUtf8String('e30')).toBeNull();
    } finally {
      state.utf8Decoder = decoder;
    }
  });

  it('parses no JSON from base64url that holds no bytes', () => {
    expect(base64UrlToJson(' ')).toBeNull();
  });

  it('reads no bytes from a number', () => {
    expect(jsonValueToUint8Array(42)).toBeNull();
  });

  it('reads no bytes from an object without a format key', () => {
    expect(jsonValueToUint8Array({ value: '0102' })).toBeNull();
  });

  it('normalizes a number to no hex', () => {
    expect(normalizeToHex(42)).toBe('');
  });
});

describe('the credProtect value sent to the browser', () => {
  it('keeps a number that names no policy', () => {
    expect(convertCredProtectValue(7)).toBe(7);
  });

  it('keeps a string that names no policy', () => {
    expect(convertCredProtectValue('userVerificationSometimes')).toBe('userVerificationSometimes');
  });
});

describe('the largeBlob extension sent to the browser', () => {
  it('keeps a write value that holds no bytes', () => {
    expect(convertLargeBlobExtension({ support: 'required', write: null })).toEqual({ support: 'required', write: null });
  });

  it('keeps a support value that reads as bytes', () => {
    expect(convertLargeBlobExtension({ support: { $hex: '01' } })).toEqual({ support: { $hex: '01' } });
  });
});

describe('the prf extension sent to the browser', () => {
  it('stays empty for an empty input', () => {
    expect(convertPrfExtension({})).toEqual({});
  });

  it('converts an eval that has only a second value', () => {
    const converted = convertPrfExtension({ eval: { second: { $hex: '0203' } } });

    expect(Object.keys(converted.eval)).toEqual(['second']);
    expect(bytesOf(converted.eval.second)).toEqual([2, 3]);
  });

  it('keeps an eval whose values hold no bytes as it was', () => {
    const extension = { eval: { first: {}, second: {} } };

    expect(convertPrfExtension(extension)).toEqual(extension);
  });

  it('converts a credential that has only a first value', () => {
    const converted = convertPrfExtension({ evalByCredential: { credA: { first: { $hex: '04' } } } });

    expect(Object.keys(converted.evalByCredential.credA)).toEqual(['first']);
    expect(bytesOf(converted.evalByCredential.credA.first)).toEqual([4]);
  });

  it('converts a credential that has only a second value', () => {
    const converted = convertPrfExtension({ evalByCredential: { credA: { second: { $hex: '05' } } } });

    expect(Object.keys(converted.evalByCredential.credA)).toEqual(['second']);
    expect(bytesOf(converted.evalByCredential.credA.second)).toEqual([5]);
  });

  it('drops the credentials whose entries hold no bytes', () => {
    const converted = convertPrfExtension({
      evalByCredential: {
        credA: null,
        credB: 'first',
        credC: { first: {}, second: {} },
        credD: { first: { $hex: '06' } },
      },
    });

    expect(Object.keys(converted.evalByCredential)).toEqual(['credD']);
  });

  it('keeps an evalByCredential with no readable entry as it was', () => {
    const extension = { evalByCredential: { credA: null } };

    expect(convertPrfExtension(extension)).toEqual(extension);
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
