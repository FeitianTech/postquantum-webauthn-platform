import { describe, expect, it } from 'vitest';

// The MDS explorer's leaf helpers: what they extract, format and resolve.
import {
  extractByteArray,
  extractList,
} from './extractors.js';
import {
  formatCertificateDateDisplay,
  formatDate,
  formatDetailValue,
  formatEnum,
  formatUpv,
  normaliseEnumKey,
} from './formatters.js';
import {
  formatGuidCandidate,
  normaliseAaguid,
} from './resolvers.js';

describe('mds-utils', () => {
  it('formats enums, keys and detail values consistently', () => {
    expect(formatEnum('FIDO_CERTIFIED_L1')).toBe('FIDO Certified L1');
    expect(formatEnum('uvm-passcode_internal')).toBe('Uvm Passcode Internal');
    expect(formatEnum('ed25519_eddsa_sha512_raw')).toBe('ED25519 Eddsa SHA512 Raw');

    expect(normaliseEnumKey('  fido certified-l1 ')).toBe('FIDO_CERTIFIED_L1');
    expect(normaliseEnumKey(null)).toBe('');

    expect(formatDetailValue(true)).toBe('true');
    expect(formatDetailValue(['a', false, null])).toBe('a, false, —');
    expect(formatDetailValue(undefined)).toBe('—');
  });

  it('normalizes an AAGUID', () => {
    expect(normaliseAaguid('00112233-4455-6677-8899-AABBCCDDEEFF')).toBe('00112233-4455-6677-8899-aabbccddeeff');
  });

  it('parses guid candidates and byte-array like inputs', () => {
    expect(formatGuidCandidate('00112233445566778899aabbccddeeff')).toBe('00112233-4455-6677-8899-aabbccddeeff');
    expect(formatGuidCandidate('00112233-4455-6677-8899-aabbccddeeff')).toBe('00112233-4455-6677-8899-aabbccddeeff');

    const bytes = new Uint8Array([
      0x00, 0x11, 0x22, 0x33,
      0x44, 0x55,
      0x66, 0x77,
      0x88, 0x99,
      0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    ]);
    expect(formatGuidCandidate(bytes)).toBe('00112233-4455-6677-8899-aabbccddeeff');
    expect(formatGuidCandidate({ toString: () => '00112233445566778899aabbccddeeff' })).toBe(
      '00112233-4455-6677-8899-aabbccddeeff',
    );
    expect(formatGuidCandidate('not-guid')).toBe('');

    expect(extractByteArray([1, 2, 3])).toEqual([1, 2, 3]);
    expect(extractByteArray(bytes)).toEqual(Array.from(bytes));
    expect(extractByteArray(new DataView(bytes.buffer))).toEqual(Array.from(bytes));
    expect(extractByteArray(bytes.buffer)).toEqual(Array.from(bytes));
    expect(extractByteArray(['1', 2])).toBeNull();
    expect(extractByteArray(null)).toBeNull();
  });

  it('extracts lists and formats UPV', () => {
    expect(extractList('single')).toEqual(['single']);
    expect(extractList(['a', '', null, 'b'])).toEqual(['a', 'b']);
    expect(extractList(null)).toEqual([]);

    expect(formatUpv([{ major: 1, minor: 0 }, { Major: 1, Minor: 1 }])).toEqual(['1.0', '1.1']);
    expect(formatUpv(null)).toEqual([]);
  });

  it('formats date values for metadata timelines', () => {
    expect(formatDate('2025-03-14T12:00:00Z')).toMatch(/2025/);
    expect(formatDate('not-a-date')).toBe('not-a-date');
    expect(formatDate('')).toBe('');

    expect(formatCertificateDateDisplay('2025-03-14T12:00:00Z')).toContain('GMT');
    expect(formatCertificateDateDisplay('bad-date')).toBe('bad-date');
    expect(formatCertificateDateDisplay(null)).toBe('');
  });
});
