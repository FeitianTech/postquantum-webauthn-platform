import { afterEach, describe, expect, it, vi } from 'vitest';

import {
  printAuthenticationDebug,
  printRegistrationDebug,
} from '../../../../frontend/static/scripts/shared/debug/auth.js';

// The ponyfill's create()/get() resolve to the browser's own credential, whose
// response.clientDataJSON is an ArrayBuffer, not text.
function clientDataBuffer(challenge) {
  const json = JSON.stringify({ type: 'webauthn.get', challenge, origin: 'https://example.com' });
  return Uint8Array.from(json, (character) => character.charCodeAt(0)).buffer;
}

function loggedChallenge(print, credential) {
  const log = vi.spyOn(console, 'log').mockImplementation(() => {});
  log.mockClear();
  print(credential, {}, {});
  const line = log.mock.calls.find((call) => call[0] === 'challenge hex code:');
  return line ? line[1] : undefined;
}

describe('the challenge printed after a ceremony', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('is read from the credential the browser returned', () => {
    const credential = {
      response: { clientDataJSON: clientDataBuffer('-_8BAg') },
      getClientExtensionResults: () => ({}),
    };

    expect(loggedChallenge(printAuthenticationDebug, credential)).toBe('fbff0102');
    expect(loggedChallenge(printRegistrationDebug, credential)).toBe('fbff0102');
  });

  it('is read from a typed array too, and is empty when there is nothing to read', () => {
    const view = { response: { clientDataJSON: new Uint8Array(clientDataBuffer('AQID')) }, getClientExtensionResults: () => ({}) };
    const unreadable = { response: { clientDataJSON: 'not base64url!' }, getClientExtensionResults: () => ({}) };
    const missing = { getClientExtensionResults: () => ({}) };

    expect(loggedChallenge(printAuthenticationDebug, view)).toBe('010203');
    expect(loggedChallenge(printAuthenticationDebug, unreadable)).toBe('');
    expect(loggedChallenge(printRegistrationDebug, missing)).toBe('');
  });
});
