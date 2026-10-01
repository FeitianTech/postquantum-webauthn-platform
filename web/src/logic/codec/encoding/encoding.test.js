import { describe, expect, it } from 'vitest';

// The Codec's encoding leaves: whether a value can be encoded to a format, and the
// summary of what was encoded.
import { canEncodeToFormat } from './can-encode.js';
import { findEncodedSummary } from './summary.js';

describe('codec encoding helpers', () => {
  it('validates canonical and aliased encoder formats', () => {
    expect(canEncodeToFormat({ ok: true }, 'JSON (binary)')).toBe(true);
    expect(canEncodeToFormat({ ok: true }, 'CBOR (canonical)')).toBe(true);
    expect(canEncodeToFormat({ ok: true }, 'COSE')).toBe(true);
    expect(canEncodeToFormat(undefined, 'json')).toBe(false);

    expect(canEncodeToFormat({ bytes: [1, 2, 3] }, 'PEM')).toBe(true);
    expect(canEncodeToFormat({ raw: 'aabbccdd' }, 'DER')).toBe(true);
    expect(canEncodeToFormat({ payload: 'not@@binary' }, 'PEM')).toBe(false);

    expect(canEncodeToFormat({ value: true }, '')).toBe(true);
    expect(canEncodeToFormat({ value: true }, 'custom-format')).toBe(true);
  });

  it('detects nested binary-convertible payloads for DER/PEM', () => {
    expect(
      canEncodeToFormat({
        data: {
          binary: {
            base64url: 'qrvM3Q',
          },
        },
      }, 'pem'),
    ).toBe(true);

    expect(canEncodeToFormat({
      values: [{ value: '-----BEGIN CERTIFICATE-----abc-----END CERTIFICATE-----' }],
    }, 'der')).toBe(true);

    expect(canEncodeToFormat({ bytes: [0, 256, -1] }, 'pem')).toBe(false);
    expect(canEncodeToFormat({ bytes: true }, 'pem')).toBe(false);
  });

  it('finds encoded summary objects and normalizes section labels', () => {
    const nestedSummary = findEncodedSummary({
      encodedValue: {
        binary: {
          hex: 'aabbccdd',
          base64: 'qrvM3Q==',
        },
      },
    }, 'binary');

    expect(nestedSummary).not.toBeNull();
    expect(nestedSummary?.label).toBe('Encoded value');
    expect(nestedSummary?.summary).toMatchObject({ hex: 'aabbccdd' });

    const arraySummary = findEncodedSummary([
      null,
      { base64url: 'qrvM3Q' },
    ], 'responseDetails');

    expect(arraySummary).not.toBeNull();
    expect(arraySummary?.label).toBe('Response details');
  });
});
