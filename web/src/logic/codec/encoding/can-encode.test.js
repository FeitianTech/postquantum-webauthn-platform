import { describe, expect, it } from 'vitest';

import { canEncodeToFormat } from './can-encode.js';

// Whether the encoder can write a value in a format (codec/encoding/can-encode.js).

describe('what the encoder can take', () => {
  it('encodes any value as JSON, CBOR or COSE, and only bytes as DER or PEM', () => {
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

  it('finds bytes for DER or PEM nested in the value, and refuses what is not bytes', () => {
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
});
