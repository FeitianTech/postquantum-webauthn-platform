import { describe, expect, it } from 'vitest';

import { ensureBase64Url } from '../../../../frontend/static/scripts/shared/storage/local/id-utils.js';

describe('ensureBase64Url', () => {
  it.each([
    ['base64url, as it is', 'FPhff9VVh1_mDEjMl0iusO-dKpqIUox-_4tcBas7neE', 'FPhff9VVh1_mDEjMl0iusO-dKpqIUox-_4tcBas7neE'],
    ['standard base64, re-spelled', 'FPhff9VVh1/mDEjMl0iusO+dKpqIUox+/4tcBas7neE=', 'FPhff9VVh1_mDEjMl0iusO-dKpqIUox-_4tcBas7neE'],
    ['nothing, as empty', '   ', ''],
    ['not a string, as empty', 42, ''],
  ])('takes %s', (_label, value, expected) => {
    expect(ensureBase64Url(value)).toBe(expected);
  });

  it('reads text that is neither base64 nor hex as hex, pair by pair, into other bytes', () => {
    // "no" -> 0, "t " -> 0, " b" -> 0x0b, "as" -> 0x0a, ...
    expect(ensureBase64Url('not base64!')).toBe('AAC6AGQA');
  });
});
