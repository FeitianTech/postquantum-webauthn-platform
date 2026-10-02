import { describe, expect, it } from 'vitest';

import { getCanonicalEncoderFormat } from './format.js';

// The encoder's format, as the server names it (codec/encoding/format.js).

describe('the encoder\'s format', () => {
  it('reads no format from something that is not text', () => {
    expect(getCanonicalEncoderFormat(null)).toBe('');
    expect(getCanonicalEncoderFormat(' EDN (exact bytes) ')).toBe('edn');
  });
});
