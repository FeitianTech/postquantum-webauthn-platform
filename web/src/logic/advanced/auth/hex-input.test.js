import { afterEach, describe, expect, it } from 'vitest';

import { hexInputIsValid } from './hex-input.js';

// Whether a byte field's text holds enough bytes (advanced/auth/hex-input.js).

afterEach(() => {
  delete window.__binaryFormat;
});

describe('a byte field in hex, the page\'s format', () => {
  it('is fine empty or blank, whatever it needs', () => {
    expect([hexInputIsValid('', 16), hexInputIsValid('   ', 16), hexInputIsValid(undefined, 16)]).toEqual([true, true, true]);
  });

  it('holds enough bytes with at least twice as many hex digits', () => {
    expect(hexInputIsValid(' 00112233445566778899aabbccddeeff ', 16)).toBe(true);
    expect(hexInputIsValid('00112233', 16)).toBe(false);
    expect(hexInputIsValid('abc')).toBe(true);
  });

  it('is not hex with any other character', () => {
    expect(hexInputIsValid('0011zz', 1)).toBe(false);
  });
});

describe('a byte field in another format', () => {
  it('reads base64, base64url and a Uint8Array literal', () => {
    expect(hexInputIsValid('AAECAw==', 4, 'b64')).toBe(true);
    expect(hexInputIsValid('AAECAw', 5, 'b64u')).toBe(false);
    expect(hexInputIsValid('new Uint8Array([1, 2, 3])', 3, 'js')).toBe(true);
  });

  it('is not valid when it does not decode, or in a format it does not know', () => {
    expect(hexInputIsValid('@@@', 1, 'b64')).toBe(false);
    expect(hexInputIsValid('00ff', 1, 'octal')).toBe(false);
  });

  it('follows the page\'s format when none is given', () => {
    window.__binaryFormat = 'js';
    expect(hexInputIsValid('00ff', 1)).toBe(false);
  });
});
