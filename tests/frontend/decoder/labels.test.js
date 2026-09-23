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
});
