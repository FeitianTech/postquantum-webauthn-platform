import { describe, expect, it } from 'vitest';

import { extractHexFromJsonFormat } from './byte-values.js';

// The byte values a request's JSON spells, read as hex (advanced/editor/byte-values.js).

describe('extractHexFromJsonFormat', () => {
  it('reads each JSON spelling of bytes', () => {
    expect(extractHexFromJsonFormat({ $hex: 'aa55' })).toBe('aa55');
    expect(extractHexFromJsonFormat({ $base64url: 'QUJD' })).toBe('414243');
    expect(extractHexFromJsonFormat({ $base64: 'AQID' })).toBe('010203');
    expect(extractHexFromJsonFormat('QUJD')).toBe('414243');
  });

  it('reads a buffer', () => {
    expect(extractHexFromJsonFormat(new Uint8Array([0xde, 0xad, 0xbe, 0xef]))).toBe('deadbeef');
  });

  it('finds no hex in an absent value or an object that spells no bytes', () => {
    expect(extractHexFromJsonFormat(undefined)).toBe('');
    expect(extractHexFromJsonFormat({ unsupported: true })).toBe('');
  });
});
