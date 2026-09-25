import { describe, expect, it } from 'vitest';

import { formatKey } from '../../../frontend/static/scripts/decoder/codec/labels.js';

describe('decoder key labels', () => {
  it('keeps the minus sign of a negative COSE label', () => {
    expect(formatKey('-1')).toBe('-1');
    expect(formatKey('-2')).toBe('-2');
    expect(formatKey('-3')).toBe('-3');
    expect(formatKey('-257')).toBe('-257');
    expect(formatKey('-1 (kty)')).toBe('-1 (kty)');
  });

  it('shows a positive label and its negative counterpart differently', () => {
    expect(formatKey('1')).toBe('1');
    expect(formatKey('-1')).not.toBe(formatKey('1'));
  });

  it('still splits snake, kebab and camel case names', () => {
    expect(formatKey('user-handle')).toBe('User Handle');
    expect(formatKey('sign-count')).toBe('Sign Count');
    expect(formatKey('authData')).toBe('Auth Data');
  });

  it('shows a typed key spelling or a key in EDN exactly as the decoder wrote it', () => {
    // These were rewritten: H'01' (bytes), " 1" (text), True (boolean) #2, "a B" (text).
    for (const key of [
      "h'01' (bytes)",
      '"-1" (text)',
      'true (boolean) #2',
      '"a_b" (text)',
      '1.5 (float)',
      '[1, 2] (array)',
      "float'7e01'",
      '["a", "b"]',
      'null (null)',
    ]) {
      expect(formatKey(key)).toBe(key);
    }
  });

  it('shows a key the decoder spelled as a number or an EDN word exactly as written', () => {
    // These were rewritten: Infinity, Na N 2, 1(1.5 3), 5e 324, Na N, True, Invalid(h'ff').
    for (const key of [
      '-Infinity',
      'Infinity',
      'NaN',
      'NaN_2',
      '1(1.5_3)',
      '24_0(0)',
      '5e-324',
      '1.5_3',
      '-0.0',
      'true',
      'null',
      "invalid(h'ff')",
      'invalid(array[2] at offset 1)',
    ]) {
      expect(formatKey(key)).toBe(key);
    }
    expect(formatKey('-Infinity')).not.toBe(formatKey('Infinity'));
  });

  it('still formats a field name that only mentions a type', () => {
    expect(formatKey('credentialId')).toBe('Credential ID');
    expect(formatKey('1 (fmt)')).toBe('1 (fmt)');
  });

  it('says "Value" for a key with nothing to show, and keeps a short all-capitals key', () => {
    expect(formatKey('')).toBe('Value');
    expect(formatKey(7)).toBe('Value');
    expect(formatKey('__')).toBe('Value');
    expect(formatKey('UV')).toBe('UV');
    expect(formatKey('RK2')).toBe('RK2');
  });
});
