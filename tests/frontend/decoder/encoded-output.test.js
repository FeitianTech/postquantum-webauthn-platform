import { describe, expect, it } from 'vitest';

import { hasBinaryConvertibleValue } from '../../../frontend/static/scripts/decoder/codec/encoding/binary.js';
import { getCanonicalEncoderFormat } from '../../../frontend/static/scripts/decoder/codec/encoding/format.js';
import {
  describeEncodedOutput,
  findEncodedSummary,
  listEncodedFormats,
} from '../../../frontend/static/scripts/decoder/codec/encoding/summary.js';

describe('the encoded bytes', () => {
  it('lists Hex, Base64, Base64url and Colon Hex first, then other strings, never encoding or a blank', () => {
    expect(listEncodedFormats({
      pem: '-----BEGIN DATA-----', colonHex: 'a0:ff', encoding: 'hex', base64url: 'oP8', base64: ' ', hex: 'a0ff', length: 2,
    })).toEqual([
      { key: 'hex', label: 'Hex', value: 'a0ff' },
      { key: 'base64url', label: 'Base64url', value: 'oP8' },
      { key: 'colonHex', label: 'Colon Hex', value: 'a0:ff' },
      { key: 'pem', label: 'PEM', value: '-----BEGIN DATA-----' },
    ]);
    expect(listEncodedFormats(null)).toEqual([]);
    expect(listEncodedFormats('a0ff')).toEqual([]);
  });

  it('labels the section by the key holding the summary, and gives the byte length when the summary has one', () => {
    expect(describeEncodedOutput({ encodedValue: { hex: '01', byteLength: 1, length: 9 } })).toEqual({
      label: 'Encoded value', formats: [{ key: 'hex', label: 'Hex', value: '01' }], byteLength: 1,
    });
    expect(describeEncodedOutput({ hex: '01', length: null })).toEqual({
      label: 'Encoded output', formats: [{ key: 'hex', label: 'Hex', value: '01' }], byteLength: null,
    });
    expect(describeEncodedOutput({ binary: { hex: '01', length: Infinity } }).byteLength).toBeNull();
  });

  it('has nothing to show without a summary', () => {
    expect(describeEncodedOutput({ json: { a: 1 } })).toBeNull();
    expect(describeEncodedOutput(undefined)).toBeNull();
  });
});

describe('finding the encoded bytes', () => {
  it('finds a summary by its base64 or base64url, inside a list too', () => {
    expect(findEncodedSummary({ base64: 'AQ==' })).toEqual({ summary: { base64: 'AQ==' }, label: 'Encoded output' });
    expect(findEncodedSummary([1, { data: { base64url: 'AQ' } }])).toEqual({ summary: { base64url: 'AQ' }, label: 'Data' });
    expect(findEncodedSummary(['a', null])).toBeNull();
    expect(findEncodedSummary(5)).toBeNull();
    expect(findEncodedSummary({ binary: 'a0ff' })).toBeNull();
    // A key that reads "Binary" names the section "Encoded output"; `binary` itself reads "Binary summary".
    expect(findEncodedSummary({ bin: { hex: '01' } }).label).toBe('Encoded output');
    expect(findEncodedSummary({ binary: [{ hex: '01' }] }).label).toBe('Binary summary');
  });
});

describe('what the encoder can take', () => {
  it('reads no format from something that is not text', () => {
    expect(getCanonicalEncoderFormat(null)).toBe('');
    expect(getCanonicalEncoderFormat(' EDN (exact bytes) ')).toBe('edn');
  });

  it('finds no bytes in a blank string, null or an empty list', () => {
    expect(hasBinaryConvertibleValue('   ')).toBe(false);
    expect(hasBinaryConvertibleValue(null)).toBe(false);
    expect(hasBinaryConvertibleValue([])).toBe(false);
    expect(hasBinaryConvertibleValue(12)).toBe(false);
  });
});
