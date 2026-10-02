import { describe, expect, it } from 'vitest';

import {
  attestationObjectDecodedCandidates,
  attestationObjectStringCandidates,
  authenticatorDataHexCandidates,
  authenticatorDataStringCandidates,
  pickFirstObject,
  pickFirstString,
  resolveStoredRegistrationResponse,
} from './registration-fields.js';

// Where a saved record may keep its registration's parts, and the first value of
// a kind among candidates (credentials/detail/registration-fields.js).

describe('the candidates a registration is read from', () => {
  it('names the attestation object a record keeps, as text or decoded', () => {
    const decoded = {};
    expect(attestationObjectStringCandidates({ attestationObject: 'o2Nm', attestationObjectRaw: 'x' })).toEqual(['o2Nm']);
    expect(attestationObjectDecodedCandidates({ attestationObject: decoded, attestationObjectDecoded: {} })).toEqual([decoded]);
    expect(attestationObjectDecodedCandidates({ attestationObject: 'text' })).toEqual([null]);
  });

  it('names the authenticator data a record keeps, and its hex', () => {
    const source = { authenticatorData: 'SZYN', authenticatorDataHex: '4996', authenticatorDataBase64: 'x' };
    expect(authenticatorDataStringCandidates(source)).toEqual(['SZYN']);
    expect(authenticatorDataHexCandidates(source)).toEqual(['4996']);
  });

  it('names nothing for a source that is not an object', () => {
    [null, undefined, 'text'].forEach((source) => {
      expect(attestationObjectStringCandidates(source)).toEqual([]);
      expect(attestationObjectDecodedCandidates(source)).toEqual([]);
      expect(authenticatorDataStringCandidates(source)).toEqual([]);
      expect(authenticatorDataHexCandidates(source)).toEqual([]);
    });
  });

  it('reads a kept response\'s nested response, else the response itself', () => {
    const nested = { attestationObject: 'x' };
    expect(resolveStoredRegistrationResponse({ response: nested })).toBe(nested);
    const flat = { attestationObject: 'x', response: 'not an object' };
    expect(resolveStoredRegistrationResponse(flat)).toBe(flat);
    expect(resolveStoredRegistrationResponse(null)).toBeNull();
    expect(resolveStoredRegistrationResponse('text')).toBeNull();
  });
});

describe('pickFirstString and pickFirstObject', () => {
  it('pick the first text that is not blank, trimmed', () => {
    expect(pickFirstString(null, 42, '  ', ' packed ', 'none')).toBe('packed');
    expect(pickFirstString(undefined, '')).toBe('');
    expect(pickFirstString()).toBe('');
  });

  it('pick the first object', () => {
    const object = { a: 1 };
    expect(pickFirstObject(null, 'text', 0, object, {})).toBe(object);
    expect(pickFirstObject(undefined, 'text')).toBeNull();
  });
});
