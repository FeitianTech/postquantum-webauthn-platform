import { describe, expect, it } from 'vitest';

import { attempt, describeError, describeValue } from '../../../../frontend/static/scripts/shared/browser/probe.js';

// Reading a browser API that may be missing or throw (shared/browser/probe.js).

describe('describeValue', () => {
  it('writes a value as JSON, and undefined as its name', () => {
    expect(describeValue({ uv: true })).toBe('{"uv":true}');
    expect(describeValue(undefined)).toBe('undefined');
  });

  it('writes what JSON cannot as text', () => {
    const cyclic = {};
    cyclic.self = cyclic;
    expect(describeValue(cyclic)).toBe('[object Object]');
    expect(describeValue(Symbol('uv'))).toBe('Symbol(uv)');
  });
});

describe('describeError', () => {
  it('names an error by its name and message', () => {
    expect(describeError(new TypeError('no'))).toBe('TypeError: no');
    expect(describeError({ name: '', message: 'bare' })).toBe('Error: bare');
    expect(describeError(new RangeError(''))).toBe('RangeError');
    expect(describeError('text')).toBe('text');
  });
});

describe('attempt', () => {
  it('gives the value read, or what was thrown', () => {
    expect(attempt(() => 1)).toEqual({ value: 1 });
    expect(
      attempt(() => {
        throw new Error('no');
      }),
    ).toEqual({ error: 'Error: no' });
  });
});
