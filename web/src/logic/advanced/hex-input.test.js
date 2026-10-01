import { describe, expect, it } from 'vitest';

import { hexInputIsValid } from './hex-input.js';

// Whether a byte field's text holds enough bytes (advanced/hex-input.js).

describe('a byte field', () => {
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
    expect(hexInputIsValid('AAECAw==', 1)).toBe(false);
  });
});
