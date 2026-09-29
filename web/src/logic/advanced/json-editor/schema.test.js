// The members the JSON editor knows in each part of a request, and how it checks keys (advanced/json-editor/schema.js).
import { describe, expect, it } from 'vitest';

import {
  KNOWN_ALGORITHMS,
  KNOWN_AUTHENTICATION_EXTENSION_KEYS,
  KNOWN_AUTHENTICATION_PUBLIC_KEY_KEYS,
  KNOWN_AUTH_SELECTION_KEYS,
  KNOWN_HINT_VALUES,
  KNOWN_LARGE_BLOB_AUTH_KEYS,
  KNOWN_LARGE_BLOB_REG_KEYS,
  KNOWN_PRF_EVAL_KEYS,
  KNOWN_PRF_KEYS,
  KNOWN_REGISTRATION_EXTENSION_KEYS,
  KNOWN_REGISTRATION_PUBLIC_KEY_KEYS,
  KNOWN_RP_KEYS,
  KNOWN_USER_KEYS,
  assertAllowedKeys,
  assertPlainObject,
  isPlainObject,
} from './schema.js';

describe('the known members', () => {
  it('of a registration request are the ten the editor handles', () => {
    expect([...KNOWN_REGISTRATION_PUBLIC_KEY_KEYS]).toEqual([
      'rp',
      'user',
      'challenge',
      'pubKeyCredParams',
      'timeout',
      'authenticatorSelection',
      'attestation',
      'extensions',
      'excludeCredentials',
      'hints',
    ]);
  });

  it('of an authentication request are the seven the editor handles', () => {
    expect([...KNOWN_AUTHENTICATION_PUBLIC_KEY_KEYS]).toEqual([
      'challenge',
      'timeout',
      'rpId',
      'allowCredentials',
      'userVerification',
      'extensions',
      'hints',
    ]);
  });

  it('of the relying party, the user and the authenticator selection are those WebAuthn defines', () => {
    expect([...KNOWN_RP_KEYS]).toEqual(['name', 'id']);
    expect([...KNOWN_USER_KEYS]).toEqual(['id', 'name', 'displayName']);
    expect([...KNOWN_AUTH_SELECTION_KEYS]).toEqual([
      'authenticatorAttachment',
      'residentKey',
      'requireResidentKey',
      'userVerification',
    ]);
  });

  it('of the extensions are six in a registration and two in an authentication', () => {
    expect([...KNOWN_REGISTRATION_EXTENSION_KEYS]).toEqual([
      'credProps',
      'minPinLength',
      'credentialProtectionPolicy',
      'enforceCredentialProtectionPolicy',
      'largeBlob',
      'prf',
    ]);
    expect([...KNOWN_AUTHENTICATION_EXTENSION_KEYS]).toEqual(['largeBlob', 'prf']);
  });

  it('of largeBlob are support in a registration and read and write in an authentication', () => {
    expect([...KNOWN_LARGE_BLOB_REG_KEYS]).toEqual(['support']);
    expect([...KNOWN_LARGE_BLOB_AUTH_KEYS]).toEqual(['read', 'write']);
  });

  it('of prf are eval, which holds first and second', () => {
    expect([...KNOWN_PRF_KEYS]).toEqual(['eval']);
    expect([...KNOWN_PRF_EVAL_KEYS]).toEqual(['first', 'second']);
  });

  it('of the hints are the three WebAuthn defines', () => {
    expect([...KNOWN_HINT_VALUES]).toEqual(['client-device', 'hybrid', 'security-key']);
  });
});

describe('the known algorithms', () => {
  it('are the numbers of every COSE algorithm the labels name', () => {
    expect([...KNOWN_ALGORITHMS].sort((a, b) => a - b)).toEqual([
      -65535, -259, -258, -257, -53, -52, -51, -50, -49, -48, -47, -39, -38, -37, -36, -35, -19, -9, -8, -7,
    ]);
  });
});

describe('isPlainObject', () => {
  it('is true for an object', () => {
    expect(isPlainObject({ name: 'alice' })).toBe(true);
    expect(isPlainObject({})).toBe(true);
  });

  it('is false for an array, null and every value that is not an object', () => {
    [[], null, undefined, 'rp', 0, 1, true, false].forEach(value => {
      expect(isPlainObject(value)).toBe(false);
    });
  });
});

describe('assertPlainObject', () => {
  it('accepts an object', () => {
    expect(() => assertPlainObject({ name: 'alice' }, 'publicKey.user')).not.toThrow();
  });

  it('refuses anything else, naming the path', () => {
    expect(() => assertPlainObject(['alice'], 'publicKey.user')).toThrow('publicKey.user must be an object.');
    expect(() => assertPlainObject(null, 'publicKey.rp')).toThrow('publicKey.rp must be an object.');
  });
});

describe('assertAllowedKeys', () => {
  it('accepts an object holding only allowed members', () => {
    expect(() => assertAllowedKeys({ name: 'Example', id: 'localhost' }, KNOWN_RP_KEYS, 'publicKey.rp')).not.toThrow();
  });

  it('refuses an object holding other members, naming each in order', () => {
    expect(() => assertAllowedKeys({ icon: 'x', name: 'Example', origin: 'y' }, KNOWN_RP_KEYS, 'publicKey.rp')).toThrow(
      'publicKey.rp contains unsupported properties: icon, origin',
    );
  });

  it('checks nothing in a value that is not an object', () => {
    expect(() => assertAllowedKeys(['icon'], KNOWN_RP_KEYS, 'publicKey.rp')).not.toThrow();
    expect(() => assertAllowedKeys('icon', KNOWN_RP_KEYS, 'publicKey.rp')).not.toThrow();
  });
});
