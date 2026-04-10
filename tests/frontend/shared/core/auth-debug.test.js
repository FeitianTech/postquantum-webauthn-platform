import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../../../frontend/static/scripts/shared/utils/binary.js', () => ({
  base64UrlToHex: vi.fn((value) => `hex:${value}`),
}));

vi.mock('../../../../frontend/static/scripts/advanced/credentials/utils.js', () => ({
  extractHexFromJsonFormat: vi.fn((value) => `fmt:${JSON.stringify(value)}`),
}));

import {
  printAuthenticationDebug,
  printRegistrationDebug,
} from '../../../../frontend/static/scripts/shared/debug/auth.js';
import { base64UrlToHex } from '../../../../frontend/static/scripts/shared/utils/binary.js';
import { extractHexFromJsonFormat } from '../../../../frontend/static/scripts/advanced/credentials/utils.js';

function collectLogs(logSpy) {
  return logSpy.mock.calls.map((call) => call.join(' '));
}

describe('auth-debug', () => {
  beforeEach(() => {
    window.lastFakeCredLength = 0;
  });

  it('prints registration debug details from extensions and server payloads', () => {
    const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});

    window.lastFakeCredLength = 128;
    const credential = {
      getClientExtensionResults: () => ({
        credProps: { rk: true },
        minPinLength: true,
        largeBlob: { supported: true },
        prf: {
          results: {
            first: { a: 1 },
            second: { b: 2 },
          },
        },
      }),
      response: {
        clientDataJSON: btoa(JSON.stringify({ challenge: 'challenge-value' })),
      },
    };

    const serverResponse = {
      attestationFormat: 'packed',
      excludeCredentialsUsed: true,
      algorithmsUsed: [-8, -7],
      hintsUsed: ['hybrid'],
      credProtectUsed: 2,
      enforceCredProtectUsed: true,
    };

    printRegistrationDebug(credential, {}, serverResponse);

    const lines = collectLogs(logSpy);

    expect(lines).toContain('Resident key: true');
    expect(lines).toContain('Attestation (retrieve or not, plus the format): true, packed');
    expect(lines).toContain('exclude credentials: true');
    expect(lines).toContain('fake credential id length: 128');
    expect(lines).toContain('challenge hex code: hex:challenge-value');
    expect(lines).toContain('credprops (requested or not): true');
    expect(lines).toContain('minpinlength (requested or not): true');
    expect(lines).toContain('credprotect setting: userVerificationOptionalWithCredentialIDList');
    expect(lines).toContain('enforce credprotect: true');
    expect(lines).toContain('largeblob: true');
    expect(lines).toContain('prf: true');

    expect(base64UrlToHex).toHaveBeenCalledWith('challenge-value');
    expect(extractHexFromJsonFormat).toHaveBeenCalledWith({ a: 1 });
    expect(extractHexFromJsonFormat).toHaveBeenCalledWith({ b: 2 });

    logSpy.mockRestore();
  });

  it('handles malformed client data and fallback extension containers', () => {
    const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});

    const credential = {
      clientExtensionResults: {
        credProps: {},
      },
      response: {
        clientDataJSON: '**invalid-base64**',
      },
    };

    printRegistrationDebug(credential, {}, { credProtectUsed: 'none' });

    const lines = collectLogs(logSpy);
    expect(lines).toContain('challenge hex code: ');
    expect(lines).toContain('credprotect setting: none');

    logSpy.mockRestore();
  });

  it('prints authentication debug values and derives largeBlob mode', () => {
    const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});

    window.lastFakeCredLength = 256;
    const assertion = {
      getClientExtensionResults: () => ({
        largeBlob: { written: true, blob: { c: 3 } },
        prf: { results: { first: { d: 4 }, second: { e: 5 } } },
      }),
      response: {
        clientDataJSON: btoa(JSON.stringify({ challenge: 'auth-challenge' })),
      },
    };

    printAuthenticationDebug(assertion, {}, { hintsUsed: ['client-device'] });

    const lines = collectLogs(logSpy);
    expect(lines).toContain('Fake credential ID length: 256');
    expect(lines).toContain('challenge hex code: hex:auth-challenge');
    expect(lines).toContain('hints: client-device');
    expect(lines).toContain('largeblob: write');
    expect(lines).toContain('largeblob write hex code: fmt:{"c":3}');
    expect(lines).toContain('prf eval first hex code: fmt:{"d":4}');
    expect(lines).toContain('prf eval second hex code: fmt:{"e":5}');

    expect(base64UrlToHex).toHaveBeenCalledWith('auth-challenge');
    expect(extractHexFromJsonFormat).toHaveBeenCalledWith({ c: 3 });
    expect(extractHexFromJsonFormat).toHaveBeenCalledWith({ d: 4 });
    expect(extractHexFromJsonFormat).toHaveBeenCalledWith({ e: 5 });

    logSpy.mockRestore();
  });
});
