import { describe, expect, it } from 'vitest';

import {
  canEncodeToFormat,
  createEncodedFormatElements,
  findEncodedSummary,
} from '../../../frontend/static/scripts/decoder/codec/encoding.js';

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

  it('creates ordered encoded format blocks while skipping unsupported keys', () => {
    const blocks = createEncodedFormatElements({
      base64url: 'qrvM3Q',
      encoding: 'cbor',
      base64: 'qrvM3Q==',
      custom: 'custom-value',
      hex: 'aabbccdd',
      ignoredEmpty: '   ',
    });

    expect(blocks).toHaveLength(4);
    const labels = blocks.map((block) => block.querySelector('.codec-encoded-label')?.textContent);
    expect(labels).toEqual(['Hex', 'Base64', 'Base64url', 'Custom']);

    const firstValue = blocks[0].querySelector('.codec-encoded-value')?.textContent;
    expect(firstValue).toBe('aabbccdd');

    expect(createEncodedFormatElements(null)).toEqual([]);
    expect(createEncodedFormatElements('string')).toEqual([]);
  });
});
