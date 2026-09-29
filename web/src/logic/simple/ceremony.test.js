import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { FailedResponseError } from '../shared/api/failed-response.js';
import { state } from '../shared/state.js';
import {
  SIMPLE_CEREMONY_TEXT,
  authenticateSimplePasskey,
  ceremonyErrorText,
  registerSimplePasskey,
  registeredText,
} from './ceremony.js';
import { answerResponse, goldenAnswers, installAuthenticator } from '@/test/logic/simple/ceremony-answers.js';

// The Simple tab's ceremonies (simple/ceremony.js) over the real WebAuthn
// ponyfill, a stand-in authenticator and the server's recorded answers.

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

const credentialsFor = vi.fn(() => STORED);
const prepareForServer = vi.fn((records) => records.map(({ credentialId }) => ({ credentialId })));

beforeEach(() => {
  authenticator = installAuthenticator(vi);
  vi.spyOn(console, 'log').mockImplementation(() => {});
  state.lastFakeCredLength = 7;
});

afterEach(() => {
  authenticator.remove();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
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
    expect(state.lastFakeCredLength).toBe(0);
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

  it('prints the registration to the console', async () => {
    answering(REGISTER[0], REGISTER[1]);
    await registerSimplePasskey('alice');
    expect(console.log).toHaveBeenCalledWith('pubkeycredparam used:', expect.anything());
  });

  it('sends the server\'s session state back, and passes the extensions it asked for', async () => {
    const begin = { status: 200, body: { __session_state: 'state-1', publicKey: { ...REGISTER[0].body.publicKey, extensions: { credProps: true } } } };
    answering(begin, REGISTER[1]);
    await registerSimplePasskey('alice');

    expect(authenticator.create.mock.calls[0][0].publicKey.extensions).toEqual({ credProps: true });
    expect(sent(1).body.__session_state).toBe('state-1');
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

  it('names the algorithm the server chose, or says it is unknown', () => {
    expect(registeredText(REGISTER[1].body)).toBe('Registration successful! Algorithm: ES256 (ECDSA)');
    expect(registeredText({})).toBe('Registration successful! Algorithm: Unknown');
  });
});

describe('authenticating with a passkey', () => {
  it('sends the saved credentials, asks the authenticator, and gives the answer and the result', async () => {
    answering(AUTHENTICATE[2], AUTHENTICATE[3]);
    const onProgress = vi.fn();
    const outcome = await authenticateSimplePasskey('alice', { credentialsFor, prepareForServer, onProgress });

    expect(credentialsFor).toHaveBeenCalledWith('alice');
    expect(sent(0).url).toBe('/api/authenticate/begin?email=alice');
    expect(sent(0).body).toEqual({ credentials: [{ credentialId: 'AQIDBA' }] });
    expect(sent(1).body).toMatchObject({ id: 'AQIDBA', response: { signature: 'MEQ', userHandle: 'dQ' } });
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
    expect(console.log).toHaveBeenCalled();
  });

  it('asks nothing when this browser keeps no passkey for the name', async () => {
    answering();
    await expect(
      authenticateSimplePasskey('bob', { credentialsFor: () => [], prepareForServer }),
    ).rejects.toThrow(SIMPLE_CEREMONY_TEXT.noStoredCredentials);
    expect(fetch).not.toHaveBeenCalled();
  });

  it('says the server has no usable credential when it answers 404', async () => {
    answering(AUTHENTICATE[8]);
    await expect(authenticateSimplePasskey('alice', { credentialsFor, prepareForServer })).rejects.toThrow(
      'No credentials found for this username. Please register first.',
    );
  });

  it('says a refused start as the server says it', async () => {
    answering({ status: 503, body: { error: 'The stored credentials could not be read. Please try again.' } });
    await expect(authenticateSimplePasskey('alice', { credentialsFor, prepareForServer })).rejects.toThrow(
      'Authentication could not start: The stored credentials could not be read. Please try again.',
    );
  });

  it('gives a refused assertion as the server read it, with the rejection for the result panel', async () => {
    answering(AUTHENTICATE[4], AUTHENTICATE[5]);
    const outcome = await authenticateSimplePasskey('alice', { credentialsFor, prepareForServer });

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

  it('sends the server\'s session state back with the assertion', async () => {
    answering({ status: 200, body: { ...AUTHENTICATE[2].body, __session_state: 'state-2' } }, AUTHENTICATE[3]);
    await authenticateSimplePasskey('alice', { credentialsFor, prepareForServer });
    expect(sent(1).body.__session_state).toBe('state-2');
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
