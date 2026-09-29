import { describe, expect, it } from 'vitest';

import {
  CAPABILITY_TEXT,
  authenticationAvailability,
  credentialSupportsLargeBlob,
  credentialSupportsPrf,
  findSavedCredential,
  largeBlobAvailability,
  prfAvailability,
} from './capabilities.js';

// Whether the saved credentials can use largeBlob and prf in an authentication,
// with no page (advanced/auth/capabilities.js).

describe('what a credential supports', () => {
  it('largeBlob: said by the record, its extension outputs or its properties', () => {
    expect(credentialSupportsLargeBlob(null)).toBe(false);
    expect(credentialSupportsLargeBlob('record')).toBe(false);
    expect(credentialSupportsLargeBlob({ largeBlob: true })).toBe(true);
    expect(credentialSupportsLargeBlob({ largeBlobSupported: true })).toBe(true);
    for (const output of [{ supported: true }, { written: true }, { blob: 'x' }, { result: 'x' }, 'present']) {
      expect(credentialSupportsLargeBlob({ clientExtensionOutputs: { largeBlob: output } })).toBe(true);
    }
    expect(credentialSupportsLargeBlob({ clientExtensionOutputs: { largeBlob: { supported: false } } })).toBe(false);
    expect(credentialSupportsLargeBlob({ clientExtensionOutputs: { largeBlob: null } })).toBe(false);
    expect(credentialSupportsLargeBlob({ clientExtensionOutputs: 'none' })).toBe(false);
    expect(credentialSupportsLargeBlob({ properties: { largeBlob: true } })).toBe(true);
    expect(credentialSupportsLargeBlob({ properties: { largeBlobSupported: true } })).toBe(true);
    expect(credentialSupportsLargeBlob({ properties: { largeBlob: 'yes' } })).toBe(false);
    expect(credentialSupportsLargeBlob({ properties: 'none' })).toBe(false);
  });

  it('prf: said by its extension outputs or its properties, unless they say it is not enabled', () => {
    expect(credentialSupportsPrf(undefined)).toBe(false);
    expect(credentialSupportsPrf(7)).toBe(false);
    for (const output of [{ results: {} }, { eval: {} }, { first: 'x' }, { second: 'x' }, { enabled: true }, { enabled: false, results: {} }, 'present']) {
      expect(credentialSupportsPrf({ clientExtensionOutputs: { prf: output } })).toBe(true);
    }
    expect(credentialSupportsPrf({ clientExtensionOutputs: { prf: { enabled: false } } })).toBe(false);
    expect(credentialSupportsPrf({ properties: { prf: { enabled: false } } })).toBe(false);
    expect(credentialSupportsPrf({ properties: { prf: true } })).toBe(true);
    expect(credentialSupportsPrf({ clientExtensionOutputs: { prf: { enabled: false } }, properties: { prf: { enabled: true } } })).toBe(true);
    expect(credentialSupportsPrf({ clientExtensionOutputs: { prf: {} } })).toBe(false);
    expect(credentialSupportsPrf({ clientExtensionOutputs: { prf: 0 } })).toBe(false);
    expect(credentialSupportsPrf({ clientExtensionOutputs: 'none' })).toBe(false);
    expect(credentialSupportsPrf({ properties: { prf: { enabled: true } } })).toBe(true);
    expect(credentialSupportsPrf({ properties: { prf: false } })).toBe(false);
    expect(credentialSupportsPrf({ properties: 'none' })).toBe(false);
  });
});

const CAPABLE = { credentialIdHex: 'AA01', largeBlob: true, clientExtensionOutputs: { prf: { enabled: true } } };
const PLAIN = { credentialId: 'uwI' };

describe('what the form may ask for', () => {
  it('finds a saved credential by its ID in any case', () => {
    expect(findSavedCredential([PLAIN, CAPABLE], 'aa01')).toBe(CAPABLE);
    expect(findSavedCredential([PLAIN, CAPABLE], 'BB02')).toBe(PLAIN);
    expect(findSavedCredential([PLAIN], 'cc03')).toBeNull();
    expect(findSavedCredential(undefined, 'cc03')).toBeNull();
    expect(findSavedCredential([PLAIN], '')).toBeNull();
    expect(findSavedCredential([PLAIN], null)).toBeNull();
    expect(findSavedCredential([{}], 'cc03')).toBeNull();
  });

  it('judges a chosen credential alone, else any saved one, with the note when it may not', () => {
    expect(largeBlobAvailability([PLAIN, CAPABLE])).toEqual({ available: true, message: '' });
    expect(largeBlobAvailability([PLAIN])).toEqual({ available: false, message: CAPABILITY_TEXT.noLargeBlob });
    expect(largeBlobAvailability([])).toEqual({ available: false, message: 'No largeBlob capable credentials available' });
    expect(largeBlobAvailability(undefined)).toEqual({ available: false, message: CAPABILITY_TEXT.noLargeBlob });
    expect(largeBlobAvailability([CAPABLE], PLAIN)).toEqual({ available: false, message: 'Selected credential does not support largeBlob.' });
    expect(largeBlobAvailability([], CAPABLE)).toEqual({ available: true, message: '' });
    expect(prfAvailability([PLAIN, CAPABLE])).toEqual({ available: true, message: '' });
    expect(prfAvailability([PLAIN])).toEqual({ available: false, message: 'No credentials with prf support available.' });
    expect(prfAvailability([CAPABLE], PLAIN)).toEqual({
      available: false,
      message: 'Selected credential does not support the prf extension.',
    });
  });

  it('judges an Allow Credentials choice: a saved credential\'s ID alone, All and Empty every saved one', () => {
    const stored = [PLAIN, CAPABLE];
    const none = { available: false, message: CAPABILITY_TEXT.selectedNoLargeBlob };
    expect(authenticationAvailability(stored, 'bb02')).toEqual({
      largeBlob: none,
      prf: { available: false, message: CAPABILITY_TEXT.selectedNoPrf },
    });
    for (const selection of ['all', 'empty', 'gone', '']) {
      expect(authenticationAvailability(stored, selection)).toEqual({
        largeBlob: { available: true, message: '' },
        prf: { available: true, message: '' },
      });
    }
  });
});
