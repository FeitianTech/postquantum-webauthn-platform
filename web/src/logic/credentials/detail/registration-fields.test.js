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
  it('names the attestation object\'s spellings in the order they are read', () => {
    const source = {
      attestationObjectRaw: 1,
      attestationObject: 2,
      attestationObjectBase64: 3,
    };
    expect(attestationObjectStringCandidates(source)).toEqual([1, 2, 3]);
  });

  it('names the decoded attestation object\'s places, the encoded ones only when they hold an object', () => {
    const [a, b] = [{}, {}];
    expect(attestationObjectDecodedCandidates({ attestationObjectDecoded: a, attestationObject: b })).toEqual([a, b]);
    expect(attestationObjectDecodedCandidates({ attestationObject: 'text' })).toEqual([undefined, null]);
  });

  it('names the authenticator data\'s spellings, and its hex\'s', () => {
    const source = {
      authenticatorDataRaw: 1,
      authenticatorData: 2,
      authenticatorDataBase64: 3,
      authenticatorDataBase64Url: 4,
      authenticatorDataHex: 5,
    };
    expect(authenticatorDataStringCandidates(source)).toEqual([1, 2, 3, 4]);
    expect(authenticatorDataHexCandidates(source)).toEqual([5]);
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
