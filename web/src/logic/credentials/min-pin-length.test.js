import { describe, expect, it } from 'vitest';

import { extractMinPinLengthValue, normalizeMinPinLengthValue } from './min-pin-length.js';
import { goldenAnswers } from '@/test/logic/simple/ceremony-answers.js';

// The minimum PIN length a saved credential reports (credentials/min-pin-length.js).

function storedCredential(scenario) {
  return goldenAnswers(scenario).find(({ body }) => body && body.storedCredential).body.storedCredential;
}

describe('normalizeMinPinLengthValue', () => {
  it('reads a whole number, from a number or from text', () => {
    expect(normalizeMinPinLengthValue(4.9)).toBe(4);
    expect(normalizeMinPinLengthValue(' 6 ')).toBe(6);
  });

  it('reads no length from a negative number or blank text', () => {
    expect(normalizeMinPinLengthValue(-1)).toBeNull();
    expect(normalizeMinPinLengthValue('   ')).toBeNull();
  });
});

describe('extractMinPinLengthValue', () => {
  it('reads the record the server saved', () => {
    expect(extractMinPinLengthValue(storedCredential('simple-register-packed-x5c-extensions'))).toBe(8);
  });

  it('reads the properties first', () => {
    expect(extractMinPinLengthValue({ properties: { minPinLength: '8' } })).toBe(8);
    expect(extractMinPinLengthValue({ properties: { minPinLength: ' 12 ' } })).toBe(12);
  });

  it('reads the extension output, as a number, as text or inside an object', () => {
    expect(extractMinPinLengthValue({ clientExtensionOutputs: { minPinLength: '10' } })).toBe(10);
    expect(extractMinPinLengthValue({ clientExtensionOutputs: { minPinLength: { value: 7 } } })).toBe(7);
    expect(extractMinPinLengthValue({ clientExtensionOutputs: { minPinLength: { minimumPinLength: '9' } } })).toBe(9);
  });

  it('reads the authenticator\'s extensions in the registration data', () => {
    expect(extractMinPinLengthValue({ registrationData: { authenticatorExtensions: { minPinLength: 5 } } })).toBe(5);
  });

  it('finds no length without a record, or where every source holds none', () => {
    expect(extractMinPinLengthValue(null)).toBeNull();
    expect(extractMinPinLengthValue({})).toBeNull();
    expect(extractMinPinLengthValue({ clientExtensionOutputs: { minPinLength: { value: 'not-a-number' } } })).toBeNull();
    expect(extractMinPinLengthValue({ clientExtensionOutputs: { minPinLength: true } })).toBeNull();
    expect(extractMinPinLengthValue({ registrationData: { authenticatorExtensions: { minPinLength: -3 } } })).toBeNull();
  });

  it('finds no length in registration data without authenticator extensions, or without minPinLength', () => {
    const es256 = storedCredential('simple-register-es256');
    expect(extractMinPinLengthValue({ registrationData: es256.relyingParty.registrationData })).toBeNull();
    expect(extractMinPinLengthValue({ registrationData: { authenticatorExtensions: { credProtect: 2 } } })).toBeNull();
  });
});
