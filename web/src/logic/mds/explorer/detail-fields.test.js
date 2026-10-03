import { describe, expect, it } from 'vitest';

import { extractList, nameFromKey, rawListValues, valueText } from './detail-fields.js';

describe('a list value', () => {
  it('writes a list value as the metadata does', () => {
    const noJson = Object.assign(Object.create(null), { big: 1n });
    expect(
      rawListValues(['a', 1, 2n, true, false, null, { x: 1 }, [1, 2], () => 1, Symbol('s'), { big: 1n }, noJson, '']),
    // A false or null item is dropped with the empty ones, as the list reader does.
    ).toEqual(['a', '1', '2', 'true', '{"x":1}', '[1,2]', '[object Object]']);
    expect(rawListValues('one')).toEqual(['one']);
    expect(rawListValues(undefined)).toEqual([]);
  });
});

describe('extractList', () => {
  it('lists a value, keeps a list\'s values, and lists nothing for none', () => {
    expect(extractList('single')).toEqual(['single']);
    expect(extractList(['a', '', null, 'b'])).toEqual(['a', 'b']);
    expect(extractList(null)).toEqual([]);
  });
});

describe('a field no MDS version this page knows', () => {
  it('is named from its key', () => {
    expect(nameFromKey('fipsRevision')).toBe('Fips Revision');
    expect(nameFromKey('cxConfigURL')).toBe('Cx Config URL');
    expect(nameFromKey('x')).toBe('X');
  });

  it('shows its value on one line', () => {
    expect(valueText(['a', 2, [true, null], { b: 1 }])).toBe('a, 2, true, —, {"b":1}');
    expect(valueText(false)).toBe('false');
    expect(valueText(null)).toBe('—');
  });
});
