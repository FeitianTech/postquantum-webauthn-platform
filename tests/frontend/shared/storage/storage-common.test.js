import { describe, expect, it } from 'vitest';

import {
  cloneJsonValue,
  computeUpdatedSignCount,
  removeObjectKeys,
  safeParse,
  truncateString,
} from '../../../../frontend/static/scripts/shared/storage/local/common.js';

describe('storage helpers', () => {
  it('copy a record JSON cannot write field by field', () => {
    const record = { credentialId: 't0QZievwTqmQrciJwJ-SL9RtBhRiQAlGJwrOmUt4C8I' };
    record.self = record;

    const clone = cloneJsonValue(record);

    expect(clone).not.toBe(record);
    expect(clone.credentialId).toBe(record.credentialId);
    expect(clone.self).toBe(record);
  });

  it('remove no keys from a target that is not a record, or with keys that are not a list', () => {
    const record = { attestationObject: 'o2NmbXRkbm9uZQ' };

    removeObjectKeys(record, 'attestationObject');

    expect(record).toEqual({ attestationObject: 'o2NmbXRkbm9uZQ' });
    expect(() => removeObjectKeys(null, ['attestationObject'])).not.toThrow();
  });

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
