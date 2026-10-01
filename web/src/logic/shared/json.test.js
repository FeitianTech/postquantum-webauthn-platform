import { describe, expect, it } from 'vitest';

import { cloneJson } from './json.js';

// A copy of a JSON value (shared/json.js).

describe('cloneJson', () => {
  it('copies a map or a list', () => {
    const value = { fmt: 'packed', attStmt: { x5c: ['MIIB'] }, skipped: undefined };
    const copy = cloneJson(value);
    expect(copy).toEqual({ fmt: 'packed', attStmt: { x5c: ['MIIB'] } });
    expect(copy.attStmt).not.toBe(value.attStmt);
    expect(cloneJson([1, 'two'])).toEqual([1, 'two']);
  });

  it('has no copy of a value that is not a map or a list', () => {
    expect([null, undefined, 'o2Nm', 5, true].map(cloneJson)).toEqual([null, null, null, null, null]);
  });

  it('copies every level, so the copy shares nothing with the value', () => {
    const value = { fmt: 'packed', attStmt: { x5c: ['MIIB'] }, properties: { residentKey: true } };
    const copy = cloneJson(value);
    copy.attStmt.x5c.push('MIIC');
    expect(value.attStmt.x5c).toEqual(['MIIB']);
    expect(copy.properties).not.toBe(value.properties);
  });
});
