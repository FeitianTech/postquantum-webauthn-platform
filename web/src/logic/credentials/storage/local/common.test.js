import { describe, expect, it } from 'vitest';

import {
  computeUpdatedSignCount,
  safeParse,
  truncateString,
} from './common.js';

describe('the storage\'s small helpers', () => {
  it('truncate a value that is not text to an empty string', () => {
    expect(truncateString(48000, 10)).toBe('');
  });

  it('keep the whole text when the limit is not a positive number', () => {
    expect(truncateString('49960de5880e', 0)).toBe('49960de5880e');
    expect(truncateString('49960de5880e', Number.NaN)).toBe('49960de5880e');
  });

  it('read a stored value that is not a list as no records', () => {
    expect(safeParse('{"credentialId":"t0QZievwTqmQrciJwJ-SL9RtBhRiQAlGJwrOmUt4C8I"}')).toEqual([]);
  });

  it('read stored text that is not JSON as no records', () => {
    expect(safeParse('[{"credentialId":')).toEqual([]);
  });

  it('count one use when neither the stored nor the new counter is known', () => {
    expect(computeUpdatedSignCount(undefined, undefined)).toBe(1);
  });
});
