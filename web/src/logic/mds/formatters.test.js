import { describe, expect, it } from 'vitest';

import {
  formatCertificateDateDisplay,
  formatDetailValue,
  formatEnum,
  formatSignatureHashName,
  formatUpv,
  normaliseEnumKey,
} from './formatters.js';

// How the explorer words MDS's values (mds/formatters.js).

describe('an MDS enum', () => {
  it('is written as words, with the acronyms MDS uses in capitals', () => {
    expect(formatEnum('FIDO_CERTIFIED_L1')).toBe('FIDO Certified L1');
    expect(formatEnum('uvm-passcode_internal')).toBe('Uvm Passcode Internal');
    expect(formatEnum('ed25519_eddsa_sha512_raw')).toBe('ED25519 Eddsa SHA512 Raw');
  });

  it('is compared as its key, in capitals with underscores', () => {
    expect(normaliseEnumKey('  fido certified-l1 ')).toBe('FIDO_CERTIFIED_L1');
    expect(normaliseEnumKey(null)).toBe('');
  });
});

describe('a detail\'s value', () => {
  it('is written as text, a list joined, and a dash for none', () => {
    expect(formatDetailValue(true)).toBe('true');
    expect(formatDetailValue(['a', false, null])).toBe('a, false, —');
    expect(formatDetailValue(undefined)).toBe('—');
  });
});

describe('the versions', () => {
  it('are written as major.minor, either spelling, skipping what is not one', () => {
    expect(formatUpv([{ major: 1, minor: 0 }, { Major: 1, Minor: 1 }])).toEqual(['1.0', '1.1']);
    expect(formatUpv([{ major: 1, minor: 2 }, null, { major: 1 }])).toEqual(['1.2']);
    expect(formatUpv({ Major: 1, Minor: 0 })).toEqual(['1.0']);
    expect(formatUpv(null)).toEqual([]);
  });
});

describe('a certificate date', () => {
  it('is written as a date, or as given when it is not one, or as nothing', () => {
    expect(formatCertificateDateDisplay('2025-03-14T12:00:00Z')).toContain('GMT');
    expect(formatCertificateDateDisplay('bad-date')).toBe('bad-date');
    expect(formatCertificateDateDisplay('someday')).toBe('someday');
    expect(formatCertificateDateDisplay(null)).toBe('');
    expect(formatCertificateDateDisplay({})).toBe('');
  });
});

describe('a signature hash name', () => {
  it('is none when blank or not text', () => {
    expect(formatSignatureHashName('  ')).toBe('');
    expect(formatSignatureHashName(42)).toBe('');
  });
});
