import { describe, expect, it } from 'vitest';

import {
  deriveAaguidDisplayValues,
  deriveAaguidFromCredentialData,
  extractAuthenticatorDataHex,
  extractHexFromJsonFormat,
  extractMinPinLengthValue,
  getStoredCredentialAttachment,
  normaliseAaguidValue,
} from '../../../../frontend/static/scripts/advanced/credentials/utils.js';
import { goldenAnswers } from '../../simple/ceremony-answers.js';

// The saved record register-complete answers, as the characterization goldens hold it.
function storedCredential(scenario) {
  return goldenAnswers(scenario).find(({ body }) => body && body.storedCredential).body.storedCredential;
}

const ES256 = storedCredential('simple-register-es256');
const AAGUID = '00112233445566778899aabbccddeeff';

describe('normaliseAaguidValue', () => {
  it('reads the GUID spelling when the raw bytes of the relying party AAGUID are empty', () => {
    expect(normaliseAaguidValue({ ...ES256.relyingParty.aaguid, raw: '' })).toBe(AAGUID);
  });

  it('reads the GUID spelling when the hex spelling is empty', () => {
    expect(normaliseAaguidValue({ hex: '', guid: ES256.properties.aaguidGuid })).toBe(AAGUID);
  });

  it('finds no AAGUID in a record whose every spelling is empty', () => {
    expect(normaliseAaguidValue({ hex: '', raw: '', guid: '' })).toBe('');
  });

  it('skips a base64 spelling that holds no hex and reads the next one', () => {
    expect(normaliseAaguidValue({ base64: '—', base64url: ES256.aaguid })).toBe(AAGUID);
  });

  it('finds no AAGUID in a placeholder with no hex digits', () => {
    expect(normaliseAaguidValue('—')).toBe('');
  });

  it('finds no AAGUID in a number', () => {
    expect(normaliseAaguidValue(0)).toBe('');
  });

  it('reads 22 characters the strict base64url decoder takes as the sixteen bytes they spell, though every one is a hex digit', () => {
    // The all-zero AAGUID, which a browser sends when no attestation is asked for.
    expect(normaliseAaguidValue('AAAAAAAAAAAAAAAAAAAAAA')).toBe('0'.repeat(32));
    expect(normaliseAaguidValue('0123456789abcdefABCDEA')).toBe('d35db7e39ebbf3d69b71d79f00108310');
  });

  it('reads 22 hex digits that spell no sixteen bytes in base64url as hex, as before', () => {
    expect(normaliseAaguidValue('0123456789abcdef012345')).toBe('0123456789abcdef012345');
  });
});

describe('extractMinPinLengthValue', () => {
  it('reads the record the server saved', () => {
    expect(extractMinPinLengthValue(storedCredential('simple-register-packed-x5c-extensions'))).toBe(8);
  });

  it('finds no length in an extension output that is neither a number nor an object', () => {
    expect(extractMinPinLengthValue({ clientExtensionOutputs: { minPinLength: true } })).toBeNull();
  });

  it('finds no length in registration data without authenticator extensions', () => {
    expect(extractMinPinLengthValue({ registrationData: ES256.relyingParty.registrationData })).toBeNull();
  });

  it('finds no length in authenticator extensions without minPinLength', () => {
    expect(extractMinPinLengthValue({
      registrationData: { authenticatorExtensions: { credProtect: 2 } },
    })).toBeNull();
  });
});

describe('extractAuthenticatorDataHex', () => {
  it('finds no bytes in a number', () => {
    expect(extractAuthenticatorDataHex(37)).toBe('');
  });
});

describe('deriveAaguidFromCredentialData', () => {
  it('reads the authenticator data under properties.registrationData', () => {
    const record = { properties: { registrationData: { authenticatorData: ES256.authenticatorDataHex } } };
    expect(deriveAaguidFromCredentialData(record)).toBe(AAGUID);
  });

  it('finds no AAGUID without a record', () => {
    expect(deriveAaguidFromCredentialData(null)).toBe('');
  });
});

describe('getStoredCredentialAttachment', () => {
  it('finds no attachment in a record without one and without properties', () => {
    expect(getStoredCredentialAttachment({ ...ES256, properties: undefined })).toBe('');
  });
});

describe('extractHexFromJsonFormat', () => {
  it('finds no hex in an absent value', () => {
    expect(extractHexFromJsonFormat(undefined)).toBe('');
  });
});

describe('deriveAaguidDisplayValues', () => {
  it('gives every spelling empty without an AAGUID', () => {
    expect(deriveAaguidDisplayValues(null)).toEqual({ aaguidHex: '', aaguidB64: '', aaguidB64u: '' });
  });
});
