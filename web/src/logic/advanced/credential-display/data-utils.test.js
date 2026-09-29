import { Buffer } from 'node:buffer';
import { describe, expect, it } from 'vitest';

import {
  cloneJson,
  collectTruthyEntries,
  normalizeClientDataString,
} from './data-utils.js';
import { registration } from '@/test/logic/advanced/credentials/registration-detail-answers.js';

// The registration view's small helpers (advanced/credential-display/data-utils.js).

/** The client data a registration kept, as the browser sent it: base64url. */
const clientData = () => registration('es256').storedCredential.clientDataJSON;

describe('normalizeClientDataString', () => {
  it('keeps base64url client data as it is, trimmed', () => {
    expect(normalizeClientDataString(` ${clientData()}\n`)).toBe(clientData());
  });

  it('writes client data kept in standard base64 as base64url', () => {
    const base64 = Buffer.from(clientData(), 'base64url').toString('base64');
    expect(normalizeClientDataString(base64)).toBe(clientData());
  });

  it('keeps text with a base64url character as it is', () => {
    expect(normalizeClientDataString('ab-c_d')).toBe('ab-c_d');
  });

  it('keeps text that is not base64 as it is', () => {
    expect(normalizeClientDataString(' {"type":"webauthn.create"} ')).toBe('{"type":"webauthn.create"}');
  });

  it('has nothing for blank text or a value that is not text', () => {
    expect(normalizeClientDataString('  ')).toBe('');
    expect(normalizeClientDataString({ type: 'webauthn.create' })).toBe('');
  });
});

describe('cloneJson', () => {
  it('copies a map or a list through JSON', () => {
    const value = { fmt: 'packed', attStmt: { x5c: ['MIIB'] }, skipped: undefined };
    const copy = cloneJson(value);
    expect(copy).toEqual({ fmt: 'packed', attStmt: { x5c: ['MIIB'] } });
    expect(copy.attStmt).not.toBe(value.attStmt);
    expect(cloneJson([1, 'two'])).toEqual([1, 'two']);
  });

  it('has no copy of a value that is not a map or a list', () => {
    expect([null, undefined, 'o2Nm', 5, true].map(cloneJson)).toEqual([null, null, null, null, null]);
  });

  it('has no copy of a value JSON cannot hold', () => {
    const cyclic = { fmt: 'packed' };
    cyclic.self = cyclic;
    expect(cloneJson(cyclic)).toBeNull();
    expect(cloneJson({ counter: 1n })).toBeNull();
  });
});

describe('collectTruthyEntries', () => {
  it('gathers the entries of each source in order, a list item by item', () => {
    expect(collectTruthyEntries('a', ['b', null, '', 'c'], null, undefined, { d: 1 })).toEqual(['a', 'b', 'c', { d: 1 }]);
  });

  it('has no entries without sources', () => {
    expect(collectTruthyEntries()).toEqual([]);
  });
});
