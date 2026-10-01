import { describe, expect, it } from 'vitest';

import {
  FAKE_CREDENTIAL_MAX_BYTES,
  FAKE_CREDENTIAL_TEXT,
  fakeCredentialLength,
  fakeCredentialSize,
  normaliseFakeCredentialHex,
  normaliseFakeCredentialList,
  withoutFakeCredential,
} from './fake-credentials.js';

// The fake credential IDs a request carries after the saved ones
// (advanced/fake-credentials.js).

describe('a fake credential ID as the list keeps it', () => {
  it('is its hex digits in lower case', () => {
    expect(normaliseFakeCredentialHex(' AB:cd-0F ')).toBe('abcd0f');
  });

  it('is nothing for blank text, text with no hex digit, or a value that is not text', () => {
    expect([normaliseFakeCredentialHex('   '), normaliseFakeCredentialHex('xyz'), normaliseFakeCredentialHex(12)]).toEqual(['', '', '']);
  });

  it('is kept in a list only when it has hex digits', () => {
    expect(normaliseFakeCredentialList(['AA', 'zz', null, 'b0'])).toEqual(['aa', 'b0']);
    expect(normaliseFakeCredentialList('aa')).toEqual([]);
  });

  it('is said to be as many bytes as its hex holds', () => {
    expect(fakeCredentialSize('a1b2c3')).toBe('3 bytes');
    expect(fakeCredentialSize('abc')).toBe('1 bytes');
  });
});

describe('the length of a new fake credential ID', () => {
  it('is the whole number typed', () => {
    expect(fakeCredentialLength('128')).toEqual({ bytes: 128, error: null, notice: null });
    expect(fakeCredentialLength(16)).toEqual({ bytes: 16, error: null, notice: null });
  });

  it('is at most 4096 bytes, and says so when more was asked for', () => {
    expect(FAKE_CREDENTIAL_MAX_BYTES).toBe(4096);
    expect(fakeCredentialLength('5000')).toEqual({ bytes: 4096, error: null, notice: FAKE_CREDENTIAL_TEXT.truncated });
    expect(FAKE_CREDENTIAL_TEXT.truncated).toBe('Credential IDs are limited to 4096 bytes. Generated value truncated to maximum length.');
  });

  it('is none for a length that is not a whole number above 0, with the reason', () => {
    for (const length of ['0', '-3', 'many', '', undefined]) {
      expect(fakeCredentialLength(length)).toEqual({ bytes: 0, error: FAKE_CREDENTIAL_TEXT.invalidLength, notice: null });
    }
    expect(FAKE_CREDENTIAL_TEXT.invalidLength).toBe('Please enter a valid fake credential ID length (at least 1 byte).');
  });
});

describe('removing a fake credential ID', () => {
  it('gives the list without the one at the index, given as a number or text', () => {
    expect(withoutFakeCredential(['aa', 'bb', 'cc'], 1)).toEqual(['aa', 'cc']);
    expect(withoutFakeCredential(['aa', 'bb', 'cc'], '0')).toEqual(['bb', 'cc']);
  });

  it('gives nothing for an index the list does not have', () => {
    for (const index of [-1, 3, 'x', undefined]) {
      expect(withoutFakeCredential(['aa', 'bb', 'cc'], index)).toBeNull();
    }
  });

  it('says so of an empty list, for registration and authentication', () => {
    expect(FAKE_CREDENTIAL_TEXT.noExclude).toBe('No fake credential IDs added.');
    expect(FAKE_CREDENTIAL_TEXT.noAllow).toBe('No fake allow credential IDs added.');
  });
});
