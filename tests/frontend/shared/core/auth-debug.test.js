import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../../../frontend/static/scripts/advanced/credentials/utils.js', () => ({
  extractHexFromJsonFormat: vi.fn((value) => `fmt:${JSON.stringify(value)}`),
}));

import {
  printAuthenticationDebug,
  printRegistrationDebug,
} from '../../../../frontend/static/scripts/shared/debug/auth.js';
import { extractHexFromJsonFormat } from '../../../../frontend/static/scripts/advanced/credentials/utils.js';
import { state } from '../../../../frontend/static/scripts/shared/state.js';

function toBase64Url(text) {
  return btoa(text).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function collectLogs(logSpy) {
  return logSpy.mock.calls.map((call) => call.join(' '));
}

describe('auth-debug', () => {
  beforeEach(() => {
    state.lastFakeCredLength = 0;
  });

  it('prints registration debug details from extensions and server payloads', () => {
    const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});

    state.lastFakeCredLength = 128;
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
        clientDataJSON: toBase64Url(JSON.stringify({ challenge: 'Y2hhbGxlbmdl' })),
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
    expect(lines).toContain('challenge hex code: 6368616c6c656e6765');
    expect(lines).toContain('credprops (requested or not): true');
    expect(lines).toContain('minpinlength (requested or not): true');
    expect(lines).toContain('credprotect setting: userVerificationOptionalWithCredentialIDList');
    expect(lines).toContain('enforce credprotect: true');
    expect(lines).toContain('largeblob: true');
    expect(lines).toContain('prf: true');

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

    state.lastFakeCredLength = 256;
    const assertion = {
      getClientExtensionResults: () => ({
        largeBlob: { written: true, blob: { c: 3 } },
        prf: { results: { first: { d: 4 }, second: { e: 5 } } },
      }),
      response: {
        clientDataJSON: toBase64Url(JSON.stringify({ challenge: '-_8BAg' })),
      },
    };

    printAuthenticationDebug(assertion, {}, { hintsUsed: ['client-device'] });

    const lines = collectLogs(logSpy);
    expect(lines).toContain('Fake credential ID length: 256');
    expect(lines).toContain('challenge hex code: fbff0102');
    expect(lines).toContain('hints: client-device');
    expect(lines).toContain('largeblob: write');
    expect(lines).toContain('largeblob write hex code: fmt:{"c":3}');
    expect(lines).toContain('prf eval first hex code: fmt:{"d":4}');
    expect(lines).toContain('prf eval second hex code: fmt:{"e":5}');

    expect(extractHexFromJsonFormat).toHaveBeenCalledWith({ c: 3 });
    expect(extractHexFromJsonFormat).toHaveBeenCalledWith({ d: 4 });
    expect(extractHexFromJsonFormat).toHaveBeenCalledWith({ e: 5 });

    logSpy.mockRestore();
  });
});
