import { describe, expect, it } from 'vitest';

import { hasBinaryConvertibleValue } from './binary.js';

// Whether a value holds bytes the encoder can write (codec/encoding/binary.js).

describe('a value with bytes', () => {
  it('finds no bytes in a blank string, null or an empty list', () => {
    expect(hasBinaryConvertibleValue('   ')).toBe(false);
    expect(hasBinaryConvertibleValue(null)).toBe(false);
    expect(hasBinaryConvertibleValue([])).toBe(false);
    expect(hasBinaryConvertibleValue(12)).toBe(false);
  });
});
