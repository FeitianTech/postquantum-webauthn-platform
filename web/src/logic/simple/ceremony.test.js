import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { FailedResponseError } from '../shared/failed-response.js';
import { UPDATE_BROWSER_TEXT, UnsupportedBrowserError } from '../shared/native-json.js';
import { getAllSimpleCredentials } from '../credentials/storage/local/simple-credentials.js';
import { seedUnifiedCredentialRecords } from '../credentials/storage/local/storage-core.js';
import {
  SIMPLE_CEREMONY_TEXT,
  authenticateSimplePasskey,
  ceremonyErrorText,
  keepSimpleCredential,
  registerSimplePasskey,
  registeredText,
} from './ceremony.js';
import { answerResponse, goldenAnswers, installAuthenticator } from '@/test/logic/simple/ceremony-answers.js';

// The Simple tab's ceremonies (simple/ceremony.js) over a stand-in for the
// browser's WebAuthn JSON methods and authenticator, and the server's recorded answers.

const REGISTER = goldenAnswers('simple-register-es256');
const AUTHENTICATE = goldenAnswers('simple-authenticate');
const STORED = [{ credentialId: 'AQIDBA', publicKey: 'pQE', email: 'alice' }];

let authenticator;
let fetch;

function answering(...answers) {
  fetch = vi.fn();
  answers.forEach((answer) => fetch.mockResolvedValueOnce(answerResponse(answer)));
  vi.stubGlobal('fetch', fetch);
}

function sent(call) {
  const [url, init] = fetch.mock.calls[call];
  return { url, init, body: JSON.parse(init.body) };
}

beforeEach(() => {
  authenticator = installAuthenticator(vi);
  // The passkeys this browser keeps.
  seedUnifiedCredentialRecords(STORED);
});

afterEach(() => {
  authenticator.remove();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
  seedUnifiedCredentialRecords(null);
});

describe('registering a passkey', () => {
  it('asks the server, the authenticator, then the server again, and gives the server\'s answer', async () => {
    answering(REGISTER[0], REGISTER[1]);
    const answer = await registerSimplePasskey('alice@example.com');

    expect(answer).toEqual(REGISTER[1].body);
    expect(sent(0).url).toBe('/api/register/begin?email=alice%40example.com');
    expect(sent(0).init).toMatchObject({ method: 'POST', headers: { 'Content-Type': 'application/json' } });
    expect(sent(0).body).toEqual({});
    expect(sent(1).url).toBe('/api/register/complete?email=alice%40example.com');
    expect(sent(1).body).toMatchObject({
      type: 'public-key',
      id: 'AQIDBA',
      rawId: 'AQIDBA',
      response: { attestationObject: 'oA', transports: ['usb'] },
    });
  });

  it('hands the authenticator the server\'s options as bytes', async () => {
    answering(REGISTER[0], REGISTER[1]);
    await registerSimplePasskey('alice');

    const { publicKey } = authenticator.create.mock.calls[0][0];
    expect(publicKey.challenge).toBeInstanceOf(ArrayBuffer);
    expect(publicKey.rp).toEqual(REGISTER[0].body.publicKey.rp);
  });

  it('says each step as it starts', async () => {
    answering(REGISTER[0], REGISTER[1]);
    const onProgress = vi.fn();
    await registerSimplePasskey('alice', { onProgress });

    expect(onProgress.mock.calls.map(([text]) => text)).toEqual([
      'Starting registration...',
      'Connecting your authenticator device...',
      'Completing registration...',
    ]);
  });

  it('passes the extensions the server asked for', async () => {
    const begin = { status: 200, body: { publicKey: { ...REGISTER[0].body.publicKey, extensions: { credProps: true } } } };
    answering(begin, REGISTER[1]);
    await registerSimplePasskey('alice');

    expect(authenticator.create.mock.calls[0][0].publicKey.extensions).toEqual({ credProps: true });
  });

  it('fails as the options do when the server answers something that is not options', async () => {
    answering({ status: 200, body: null });
    await expect(registerSimplePasskey('alice')).rejects.toThrow();
    expect(authenticator.create).not.toHaveBeenCalled();
  });

  it('says a refused start as the server says it', async () => {
    answering({ status: 503, body: { error: 'The stored credentials could not be read. Please try again.' } });
    const failure = registerSimplePasskey('alice');
    await expect(failure).rejects.toBeInstanceOf(FailedResponseError);
    await expect(failure).rejects.toThrow('Registration could not start: The stored credentials could not be read. Please try again.');
  });

  it('says a refused registration as the server says it', async () => {
    answering(REGISTER[0], { status: 400, body: { error: 'Registration verification failed.', verified: false } });
    await expect(registerSimplePasskey('alice')).rejects.toThrow('Registration failed: Registration verification failed.');
  });

  it('sends the credential as the browser writes it: its JSON, with its attachment', async () => {
    answering(REGISTER[0], REGISTER[1]);
    await registerSimplePasskey('alice');

    expect(sent(1).body).toEqual({
      type: 'public-key',
      id: 'AQIDBA',
      rawId: 'AQIDBA',
      authenticatorAttachment: 'cross-platform',
      response: { clientDataJSON: 'eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0', attestationObject: 'oA', transports: ['usb'] },
      clientExtensionResults: {},
    });
  });

  it('names the algorithm the server chose, or says it is unknown', () => {
    expect(registeredText(REGISTER[1].body)).toBe('Registration successful! Algorithm: ES256 (ECDSA)');
    expect(registeredText({})).toBe('Registration successful! Algorithm: Unknown');
  });
});

describe('authenticating with a passkey', () => {
  it('sends the saved credentials, asks the authenticator, and gives the answer and the result', async () => {
    answering(AUTHENTICATE[2], AUTHENTICATE[3]);
    const onProgress = vi.fn();
    const outcome = await authenticateSimplePasskey('alice', { onProgress });

    expect(sent(0).url).toBe('/api/authenticate/begin?email=alice');
    const credentials = [{ credentialId: 'AQIDBA', aaguid: null, publicKey: 'pQE', signCount: 0 }];
    expect(sent(0).body).toEqual({ credentials });
    // The assertion as the browser's JSON, beside the very list begin was sent.
    expect(sent(1).body).toMatchObject({ credential: { id: 'AQIDBA', response: { signature: 'MEQ', userHandle: 'dQ' } }, credentials });
    expect(Object.keys(sent(1).body).sort()).toEqual(['credential', 'credentials']);
    expect(authenticator.get.mock.calls[0][0].publicKey.challenge).toBeInstanceOf(ArrayBuffer);
    expect(outcome).toEqual({
      answer: AUTHENTICATE[3].body,
      result: { title: 'Last authentication', signCount: 6, signCountStatus: 'ok' },
    });
    expect(onProgress.mock.calls.map(([text]) => text)).toEqual([
      'Starting authentication...',
      'Connecting your authenticator device...',
      'Completing authentication...',
    ]);
  });

  it('asks nothing when this browser keeps no passkey for the name', async () => {
    answering();
    await expect(authenticateSimplePasskey('bob')).rejects.toThrow(SIMPLE_CEREMONY_TEXT.noStoredCredentials);
    expect(fetch).not.toHaveBeenCalled();
  });

  it('says the server has no usable credential when it answers 404', async () => {
    answering(AUTHENTICATE[8]);
    await expect(authenticateSimplePasskey('alice')).rejects.toThrow(
      'No credentials found for this username. Please register first.',
    );
  });

  it('says a refused start as the server says it', async () => {
    answering({ status: 503, body: { error: 'The stored credentials could not be read. Please try again.' } });
    await expect(authenticateSimplePasskey('alice')).rejects.toThrow(
      'Authentication could not start: The stored credentials could not be read. Please try again.',
    );
  });

  it('gives a refused assertion as the server read it, with the rejection for the result panel', async () => {
    answering(AUTHENTICATE[4], AUTHENTICATE[5]);
    const outcome = await authenticateSimplePasskey('alice');

    expect(outcome.failure).toMatchObject({
      status: 400,
      signCountStatus: 'regressed',
      failedCredentialId: AUTHENTICATE[5].body.failedCredentialId,
    });
    expect(outcome.failure.text).toContain('Signature counter did not increase');
    expect(outcome.result).toEqual({
      title: 'Last authentication',
      signCountStatus: 'regressed',
      consequence: 'Authentication was rejected.',
    });
  });

});

describe('keeping a registration', () => {
  it('saves the server\'s record in this browser, for the name it was registered under', () => {
    seedUnifiedCredentialRecords([]);
    keepSimpleCredential(REGISTER[1].body.storedCredential, 'alice@example.com');
    const [kept] = getAllSimpleCredentials();
    expect(kept).toMatchObject({ type: 'simple', email: 'alice@example.com', credentialId: REGISTER[1].body.storedCredential.credentialId });
  });
});

describe('what a failed ceremony says', () => {
  it('names the browser\'s refusals', () => {
    expect(ceremonyErrorText({ name: 'NotAllowedError' }, 'registration')).toBe('User cancelled or authenticator not available');
    expect(ceremonyErrorText({ name: 'SecurityError' }, 'authentication')).toBe('Security error - check your connection and try again');
    expect(ceremonyErrorText({ name: 'NotSupportedError' }, 'registration')).toBe('WebAuthn is not supported in this browser');
  });

  it('says an InvalidStateError one way for each ceremony', () => {
    expect(ceremonyErrorText({ name: 'InvalidStateError' }, 'registration')).toBe('Authenticator is already registered for this account');
    expect(ceremonyErrorText({ name: 'InvalidStateError' }, 'authentication')).toBe('Authenticator error or invalid credential');
  });

  it('gives anything else its own message, a name that is also an object property included', () => {
    expect(ceremonyErrorText(new Error('Registration failed: Invalid signature.'), 'registration')).toBe('Registration failed: Invalid signature.');
    expect(ceremonyErrorText({ name: 'toString', message: 'odd' }, 'registration')).toBe('odd');
  });
});

describe('a browser without WebAuthn\'s JSON methods', () => {
  it('asks nothing of the server or the authenticator, and says to update the browser', async () => {
    delete globalThis.PublicKeyCredential;
    answering();

    await expect(registerSimplePasskey('alice')).rejects.toThrow(UPDATE_BROWSER_TEXT);
    await expect(authenticateSimplePasskey('alice')).rejects.toBeInstanceOf(
      UnsupportedBrowserError,
    );
    expect(fetch).not.toHaveBeenCalled();
    expect(authenticator.create).not.toHaveBeenCalled();
    expect(authenticator.get).not.toHaveBeenCalled();
  });
});
