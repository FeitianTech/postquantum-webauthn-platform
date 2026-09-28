// The checks both requests' validation shares: byte values, whole numbers, hints, and the prf and largeBlob extensions (advanced/json-editor/validation-common.js).
import { describe, expect, it } from 'vitest';

import {
  normalizeInteger,
  validateBinaryField,
  validateHints,
  validateLargeBlobExtension,
  validatePrfExtension,
} from '../../../../frontend/static/scripts/advanced/json-editor/validation-common.js';

const NOT_BYTES = 'publicKey.challenge must be a base64url, base64, or hexadecimal value.';

describe('validateBinaryField', () => {
  it('gives the hexadecimal of a $hex value', () => {
    expect(validateBinaryField({ $hex: 'abcd' }, 'publicKey.challenge')).toBe('abcd');
  });

  it('gives the hexadecimal of a $base64url value', () => {
    expect(validateBinaryField({ $base64url: 'q80' }, 'publicKey.challenge')).toBe('abcd');
  });

  it('gives the hexadecimal of a $base64 value', () => {
    expect(validateBinaryField({ $base64: 'q80=' }, 'publicKey.challenge')).toBe('abcd');
  });

  it('reads bare text as base64url', () => {
    expect(validateBinaryField('q80', 'publicKey.challenge')).toBe('abcd');
  });

  it('gives the hexadecimal of a typed array', () => {
    expect(validateBinaryField(new Uint8Array([0xab, 0xcd]), 'publicKey.challenge')).toBe('abcd');
  });

  it('requires a value', () => {
    expect(() => validateBinaryField(undefined, 'publicKey.challenge')).toThrow('publicKey.challenge is required.');
    expect(() => validateBinaryField(null, 'publicKey.user.id')).toThrow('publicKey.user.id is required.');
  });

  it('gives no bytes for a missing value when empty is allowed', () => {
    expect(validateBinaryField(undefined, 'publicKey.challenge', { allowEmpty: true })).toBe('');
    expect(validateBinaryField(null, 'publicKey.challenge', { allowEmpty: true })).toBe('');
  });

  it('refuses a value that holds no bytes', () => {
    [{}, { $hex: '' }, '', '   ', 42, true].forEach(value => {
      expect(() => validateBinaryField(value, 'publicKey.challenge')).toThrow(NOT_BYTES);
    });
  });

  it('refuses a value whose base64 does not decode', () => {
    expect(() => validateBinaryField({ $base64: 'q8-0' }, 'publicKey.challenge')).toThrow(NOT_BYTES);
    expect(() => validateBinaryField({ $base64url: '%%' }, 'publicKey.challenge')).toThrow(NOT_BYTES);
    expect(() => validateBinaryField('%%%', 'publicKey.challenge')).toThrow(NOT_BYTES);
  });

  it('gives no bytes for empty or blank text when empty is allowed', () => {
    expect(validateBinaryField('', 'publicKey.challenge', { allowEmpty: true })).toBe('');
    expect(validateBinaryField('   ', 'publicKey.challenge', { allowEmpty: true })).toBe('');
  });

  it('refuses a value that holds no bytes when empty is allowed, unless it is blank text', () => {
    expect(() => validateBinaryField({}, 'publicKey.challenge', { allowEmpty: true })).toThrow(NOT_BYTES);
    expect(() => validateBinaryField('%%%', 'publicKey.challenge', { allowEmpty: true })).toThrow(NOT_BYTES);
  });

  it('requires a value when the options say nothing of empty values', () => {
    expect(() => validateBinaryField(undefined, 'publicKey.challenge', {})).toThrow('publicKey.challenge is required.');
  });
});

describe('normalizeInteger', () => {
  it('gives no number for a missing value', () => {
    expect(normalizeInteger(undefined, 'publicKey.timeout')).toBeNull();
    expect(normalizeInteger(null, 'publicKey.timeout')).toBeNull();
  });

  it('rounds a number down to a whole number', () => {
    expect(normalizeInteger(90000, 'publicKey.timeout')).toBe(90000);
    expect(normalizeInteger(1500.7, 'publicKey.timeout')).toBe(1500);
    expect(normalizeInteger(-3.2, 'publicKey.timeout')).toBe(-4);
  });

  it('reads a whole number from text, trimmed', () => {
    expect(normalizeInteger(' 120000 ', 'publicKey.timeout')).toBe(120000);
    expect(normalizeInteger('-5', 'publicKey.timeout')).toBe(-5);
  });

  it('gives no number for blank text', () => {
    expect(normalizeInteger('   ', 'publicKey.timeout')).toBeNull();
  });

  it('refuses text that is not a number', () => {
    expect(() => normalizeInteger('soon', 'publicKey.timeout')).toThrow('publicKey.timeout must be a whole number.');
  });

  it('refuses digits too many for a finite number', () => {
    expect(() => normalizeInteger('9'.repeat(400), 'publicKey.timeout')).toThrow('publicKey.timeout must be a whole number.');
  });

  it('refuses a number that is not finite', () => {
    expect(() => normalizeInteger(Number.NaN, 'publicKey.timeout')).toThrow('publicKey.timeout must be a whole number.');
    expect(() => normalizeInteger(Number.POSITIVE_INFINITY, 'publicKey.timeout')).toThrow(
      'publicKey.timeout must be a whole number.',
    );
  });

  it('refuses a value that is neither a number nor text', () => {
    expect(() => normalizeInteger(true, 'publicKey.timeout')).toThrow('publicKey.timeout must be a whole number.');
    expect(() => normalizeInteger({ ms: 1 }, 'publicKey.timeout')).toThrow('publicKey.timeout must be a whole number.');
  });
});

describe('validateHints', () => {
  it('accepts no hints', () => {
    expect(() => validateHints(undefined, 'publicKey.hints')).not.toThrow();
  });

  it('accepts the known hints, trimmed and in any case', () => {
    expect(() => validateHints(['security-key', ' Hybrid ', 'CLIENT-DEVICE'], 'publicKey.hints')).not.toThrow();
    expect(() => validateHints([], 'publicKey.hints')).not.toThrow();
  });

  it('refuses hints that are not an array', () => {
    expect(() => validateHints('hybrid', 'publicKey.hints')).toThrow('publicKey.hints must be an array of strings.');
    expect(() => validateHints(null, 'publicKey.hints')).toThrow('publicKey.hints must be an array of strings.');
  });

  it('refuses a hint that is not text, naming its index', () => {
    expect(() => validateHints(['hybrid', 3], 'publicKey.hints')).toThrow('publicKey.hints[1] must be a string.');
  });

  it('refuses a hint WebAuthn does not define, naming its index', () => {
    expect(() => validateHints(['usb'], 'publicKey.hints')).toThrow('publicKey.hints[0] is not a supported hint value.');
  });
});

describe('validatePrfExtension', () => {
  const PRF = 'publicKey.extensions.prf';

  it('accepts eval with first and second', () => {
    expect(() => validatePrfExtension({ eval: { first: { $hex: '01' }, second: { $base64url: 'Ag' } } }, PRF)).not.toThrow();
  });

  it('accepts prf with no eval, and eval with either value alone or none', () => {
    expect(() => validatePrfExtension({}, PRF)).not.toThrow();
    expect(() => validatePrfExtension({ eval: {} }, PRF)).not.toThrow();
    expect(() => validatePrfExtension({ eval: { first: { $hex: '01' } } }, PRF)).not.toThrow();
    expect(() => validatePrfExtension({ eval: { second: { $hex: '02' } } }, PRF)).not.toThrow();
  });

  it('refuses prf that is not an object', () => {
    expect(() => validatePrfExtension(true, PRF)).toThrow('publicKey.extensions.prf must be an object.');
  });

  it('refuses a member of prf other than eval', () => {
    expect(() => validatePrfExtension({ evalByCredential: {} }, PRF)).toThrow(
      'publicKey.extensions.prf contains unsupported properties: evalByCredential',
    );
  });

  it('refuses eval that is not an object', () => {
    expect(() => validatePrfExtension({ eval: 'first' }, PRF)).toThrow('publicKey.extensions.prf.eval must be an object.');
  });

  it('refuses a member of eval other than first and second', () => {
    expect(() => validatePrfExtension({ eval: { first: { $hex: '01' }, third: { $hex: '03' } } }, PRF)).toThrow(
      'publicKey.extensions.prf.eval contains unsupported properties: third',
    );
  });

  it('refuses a first value that holds no bytes', () => {
    expect(() => validatePrfExtension({ eval: { first: null } }, PRF)).toThrow('publicKey.extensions.prf.eval.first is required.');
  });

  it('refuses a second value that holds no bytes', () => {
    expect(() => validatePrfExtension({ eval: { first: { $hex: '01' }, second: {} } }, PRF)).toThrow(
      'publicKey.extensions.prf.eval.second must be a base64url, base64, or hexadecimal value.',
    );
  });
});

describe('validateLargeBlobExtension', () => {
  const LARGE_BLOB = 'publicKey.extensions.largeBlob';

  describe('in an authentication', () => {
    it('accepts read, write, both or neither', () => {
      expect(() => validateLargeBlobExtension({}, LARGE_BLOB, 'authentication')).not.toThrow();
      expect(() => validateLargeBlobExtension({ read: true }, LARGE_BLOB, 'authentication')).not.toThrow();
      expect(() => validateLargeBlobExtension({ write: { $hex: '0102' } }, LARGE_BLOB, 'authentication')).not.toThrow();
      expect(() => validateLargeBlobExtension({ read: false, write: 'AQI' }, LARGE_BLOB, 'authentication')).not.toThrow();
    });

    it('refuses largeBlob that is not an object', () => {
      expect(() => validateLargeBlobExtension('read', LARGE_BLOB, 'authentication')).toThrow(
        'publicKey.extensions.largeBlob must be an object.',
      );
    });

    it('refuses support, which belongs to a registration', () => {
      expect(() => validateLargeBlobExtension({ support: 'required' }, LARGE_BLOB, 'authentication')).toThrow(
        'publicKey.extensions.largeBlob contains unsupported properties: support',
      );
    });

    it('refuses read that is not a boolean', () => {
      expect(() => validateLargeBlobExtension({ read: 'yes' }, LARGE_BLOB, 'authentication')).toThrow(
        'publicKey.extensions.largeBlob.read must be a boolean.',
      );
    });

    it('refuses write that holds no bytes', () => {
      expect(() => validateLargeBlobExtension({ write: {} }, LARGE_BLOB, 'authentication')).toThrow(
        'publicKey.extensions.largeBlob.write must be a base64url, base64, or hexadecimal value.',
      );
    });
  });

  describe('in a registration', () => {
    it('accepts support preferred or required, or none', () => {
      expect(() => validateLargeBlobExtension({}, LARGE_BLOB, 'registration')).not.toThrow();
      expect(() => validateLargeBlobExtension({ support: 'preferred' }, LARGE_BLOB, 'registration')).not.toThrow();
      expect(() => validateLargeBlobExtension({ support: 'required' }, LARGE_BLOB, 'registration')).not.toThrow();
    });

    it('refuses largeBlob that is not an object', () => {
      expect(() => validateLargeBlobExtension(null, LARGE_BLOB, 'registration')).toThrow(
        'publicKey.extensions.largeBlob must be an object.',
      );
    });

    it('refuses read and write, which belong to an authentication', () => {
      expect(() => validateLargeBlobExtension({ read: true, write: 'AQI' }, LARGE_BLOB, 'registration')).toThrow(
        'publicKey.extensions.largeBlob contains unsupported properties: read, write',
      );
    });

    it('refuses support other than preferred or required', () => {
      expect(() => validateLargeBlobExtension({ support: 'optional' }, LARGE_BLOB, 'registration')).toThrow(
        'publicKey.extensions.largeBlob.support must be preferred or required.',
      );
      expect(() => validateLargeBlobExtension({ support: true }, LARGE_BLOB, 'registration')).toThrow(
        'publicKey.extensions.largeBlob.support must be preferred or required.',
      );
    });

    it('applies to any scope other than authentication', () => {
      expect(() => validateLargeBlobExtension({ read: true }, LARGE_BLOB)).toThrow(
        'publicKey.extensions.largeBlob contains unsupported properties: read',
      );
    });
  });
});
