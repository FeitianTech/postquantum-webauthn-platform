// The members the JSON editor knows in each part of a request, and how it compares and checks keys (advanced/json-editor/schema.js).
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
  createNormalizedKeySet,
  isPlainObject,
  normalizeKeyName,
  shouldPreserveUnknownKey,
} from '../../../../frontend/static/scripts/advanced/json-editor/schema.js';

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

describe('normalizeKeyName', () => {
  it('trims, lowers the case and keeps only letters and digits', () => {
    expect(normalizeKeyName('  Pub_Key-Cred.Params 2 ')).toBe('pubkeycredparams2');
  });

  it('gives no name for a key that is not text', () => {
    expect(normalizeKeyName(42)).toBe('');
    expect(normalizeKeyName(null)).toBe('');
  });
});

describe('createNormalizedKeySet', () => {
  it('normalizes each key of a set', () => {
    expect([...createNormalizedKeySet(new Set(['pubKeyCredParams', 'rpId']))]).toEqual(['pubkeycredparams', 'rpid']);
  });

  it('normalizes each key of an array', () => {
    expect([...createNormalizedKeySet(['Display Name', 'id'])]).toEqual(['displayname', 'id']);
  });

  it('leaves out a key that normalizes to nothing', () => {
    expect([...createNormalizedKeySet(['---', 7, 'rp'])]).toEqual(['rp']);
  });

  it('is empty when no keys are given', () => {
    expect(createNormalizedKeySet(undefined).size).toBe(0);
    expect(createNormalizedKeySet(null).size).toBe(0);
  });
});

describe('shouldPreserveUnknownKey', () => {
  const known = createNormalizedKeySet(['challenge', 'timeout']);

  it('keeps a key unlike every known one', () => {
    expect(shouldPreserveUnknownKey('customFlag', known)).toBe(true);
  });

  it('keeps any key when no key is known', () => {
    expect(shouldPreserveUnknownKey('timeout', new Set())).toBe(true);
  });

  it('drops a key that normalizes to nothing', () => {
    expect(shouldPreserveUnknownKey('--', known)).toBe(false);
    expect(shouldPreserveUnknownKey(3, known)).toBe(false);
  });

  it('drops a known key however it is spelled', () => {
    expect(shouldPreserveUnknownKey('Time_Out', known)).toBe(false);
  });

  it('drops a known key followed by up to eight more characters, as a variant of it', () => {
    expect(shouldPreserveUnknownKey('challengeValue', known)).toBe(false);
    expect(shouldPreserveUnknownKey('challenge12345678', known)).toBe(false);
  });

  it('keeps a key that starts with a known one but runs more than eight characters longer', () => {
    expect(shouldPreserveUnknownKey('challengeDescription', known)).toBe(true);
  });

  it('drops a known key preceded by up to eight more characters, as a variant of it', () => {
    expect(shouldPreserveUnknownKey('myTimeout', known)).toBe(false);
  });

  it('keeps a key that ends with a known one but runs more than eight characters longer', () => {
    expect(shouldPreserveUnknownKey('requestedByServerTimeout', known)).toBe(true);
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
