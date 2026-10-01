// The Advanced tab's authentication with no DOM (advanced/authentication/ceremony.js), over the server's recorded answers.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import {
  ADVANCED_ASSERTION_TEXT,
  advancedAuthenticationFailureText,
  authenticateAdvancedCredential,
  readAssertionRequest,
} from './ceremony.js';
import { ADVANCED_CEREMONY_TEXT } from '../registration/ceremony.js';
import { ensureAuthenticationHintsAllowed } from '../hints.js';
import { UPDATE_BROWSER_TEXT } from '../../shared/native-json.js';
import { answerResponse, credentialToJSON, installAuthenticator } from '@/test/logic/simple/ceremony-answers.js';
import { advancedAuthentications, recordedAssertion } from '@/test/logic/advanced/advanced-answers.js';

const BEGIN = '/api/advanced/authenticate/begin';
const COMPLETE = '/api/advanced/authenticate/complete';

const { records, first, regressed, refused, none } = advancedAuthentications();
const [CAPABLE, PLAIN] = records;
const STORED = records.map((record) => ({ credentialId: record.credentialIdBase64Url, publicKey: record.publicKey }));
const CHALLENGE = { $hex: '71'.repeat(32) };

/** The request the tab sends: the editor's text, with `overrides` in publicKey and a key beside it. */
function request(overrides = {}) {
  return JSON.stringify({ publicKey: { challenge: CHALLENGE, userVerification: 'preferred', ...overrides }, note: 'kept' });
}

let fetch;
let authenticator;

/** The server: each path answers its recorded answer. */
function serving({ begin, complete }) {
  fetch = vi.fn(async (url) => answerResponse(url === BEGIN ? begin : complete));
  vi.stubGlobal('fetch', fetch);
}

function sent(call) {
  const [url, init] = fetch.mock.calls[call];
  return { url, body: JSON.parse(init.body) };
}

const asked = () => fetch.mock.calls.map(([url]) => url);

/** What the form's views give the ceremony: the real hints' check over the saved records, the records sent, two form values. */
function formOptions(overrides = {}) {
  return {
    ensureHints: vi.fn((publicKey) => ensureAuthenticationHintsAllowed(publicKey, { storedCredentials: records })),
    prepareForServer: vi.fn(() => STORED),
    hashAlgorithm: vi.fn(() => 'SHA-384'),
    onStart: vi.fn(),
    onProgress: vi.fn(),
    ...overrides,
  };
}

function authenticatorGiving(assertion) {
  authenticator.remove();
  authenticator = installAuthenticator(vi, { get: assertion });
}

beforeEach(() => {
  authenticator = installAuthenticator(vi, { get: recordedAssertion(first) });
});

afterEach(() => {
  authenticator.remove();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe('the request', () => {
  it('is the editor\'s text, holding publicKey with a challenge', () => {
    expect(readAssertionRequest(request())).toEqual(JSON.parse(request()));
    expect(() => readAssertionRequest('{}')).toThrow('Invalid JSON structure: Missing "publicKey" property');
    expect(() => readAssertionRequest('{"publicKey": {}}')).toThrow(
      'Invalid CredentialRequestOptions: Missing required "challenge" property',
    );
    expect(() => readAssertionRequest('{ nope')).toThrow(SyntaxError);
  });

  it('says a failure by the browser\'s name for it, else by its own message', () => {
    const named = (name) => Object.assign(new Error('ignored'), { name });
    expect(advancedAuthenticationFailureText(named('NotAllowedError'))).toBe(
      'Advanced authentication failed: User cancelled or no compatible authenticator detected',
    );
    expect(advancedAuthenticationFailureText(named('InvalidStateError'))).toBe(
      'Advanced authentication failed: Invalid authenticator state - please try again',
    );
    expect(advancedAuthenticationFailureText(named('SecurityError'))).toBe(
      'Advanced authentication failed: Security error - check your connection and try again',
    );
    expect(advancedAuthenticationFailureText(new Error('odd'))).toBe('Advanced authentication failed: odd');
  });
});

describe('an authentication', () => {
  it('detects the credentials, asks the authenticator, completes, and says what the server made of it', async () => {
    serving(first);
    const options = formOptions();
    const outcome = await authenticateAdvancedCredential(request(), options);

    expect(asked()).toEqual([BEGIN, COMPLETE]);
    expect(options.onStart).toHaveBeenCalledTimes(1);
    expect(options.onProgress.mock.calls.map(([text]) => text)).toEqual([
      'Detecting credentials...',
      'Connecting your authenticator device...',
      'Completing authentication...',
    ]);
    // The begin is the edit with the records; the complete adds the assertion and the hash.
    expect(sent(0).body).toEqual({ ...JSON.parse(request()), __storedCredentials: STORED });
    const complete = sent(1).body;
    expect(Object.keys(complete).sort()).toEqual(
      ['__assertion_response', '__hash_algorithm', '__storedCredentials', 'note', 'publicKey'].sort(),
    );
    expect(complete.__hash_algorithm).toBe('SHA-384');
    expect(complete.__assertion_response).toMatchObject({
      id: CAPABLE.credentialIdBase64Url,
      authenticatorAttachment: 'cross-platform',
      clientExtensionResults: {},
    });

    expect(outcome).toEqual({
      authenticated: true,
      answer: first.complete.body,
      result: {
        title: 'Last authentication',
        signCount: 1,
        signCountStatus: 'ok',
        consequence: 'The advanced tab reports this and does not reject the assertion.',
        showChallenge: true,
        challengeSource: 'server-session',
        challengeStatus: 'fresh',
      },
    });
    expect(ADVANCED_ASSERTION_TEXT.authenticated).toBe('Advanced authentication successful!');
  });

  it('gives the browser the begin\'s extensions, and sends every extension result as its JSON writes it', async () => {
    serving({
      begin: { ...regressed.begin, body: { ...regressed.begin.body, publicKey: { ...regressed.begin.body.publicKey, extensions: { largeBlob: { read: true } } } } },
      complete: regressed.complete,
    });
    authenticatorGiving(recordedAssertion(regressed, { largeBlob: { blob: new Uint8Array([1, 2]).buffer } }));
    const outcome = await authenticateAdvancedCredential(request({ extensions: { largeBlob: { read: true } } }), formOptions());

    expect(authenticator.get.mock.calls[0][0].publicKey.extensions).toEqual({ largeBlob: { read: true } });
    expect(sent(1).body.__assertion_response.clientExtensionResults).toEqual({ largeBlob: { blob: 'AQI' } });
    // A counter below the stored one is reported, and the tab does not reject it.
    expect(outcome.result).toMatchObject({ signCount: 2, signCountStatus: 'regressed', challengeStatus: 'replayed' });
  });

  it('gives the browser prf\'s inputs as the bytes the begin names', async () => {
    serving({
      begin: { ...first.begin, body: { ...first.begin.body, publicKey: { ...first.begin.body.publicKey, extensions: { prf: { eval: { first: 'AQ' } } } } } },
      complete: first.complete,
    });
    await authenticateAdvancedCredential(request(), formOptions());
    const { first: evaluation } = authenticator.get.mock.calls[0][0].publicKey.extensions.prf.eval;
    expect(Array.from(new Uint8Array(evaluation))).toEqual([1]);
  });

  it('completes with an assertion that has no attachment', async () => {
    serving(first);
    authenticatorGiving({ ...recordedAssertion(first), authenticatorAttachment: undefined });
    await authenticateAdvancedCredential(request(), formOptions());
    expect(sent(1).body.__assertion_response.authenticatorAttachment).toBeNull();
  });

  it('authenticates without being told where to say its steps', async () => {
    serving(first);
    const { onStart, onProgress, ...silent } = formOptions();
    expect((await authenticateAdvancedCredential(request(), silent)).authenticated).toBe(true);
  });
});

describe('a refused authentication', () => {
  it('names the credential the server refused, with where its challenge came from', async () => {
    serving(refused);
    authenticatorGiving(recordedAssertion(refused));
    const outcome = await authenticateAdvancedCredential(request(), formOptions());

    expect(outcome).toEqual({
      authenticated: false,
      text: 'Advanced authentication failed: Invalid signature. Start the ceremony again.',
      failedCredentialId: CAPABLE.credentialIdBase64Url,
      result: {
        title: 'Last authentication',
        signCountStatus: null,
        showChallenge: true,
        challengeSource: 'server-session',
        challengeStatus: 'replayed',
      },
    });
  });

  it('says there are no credentials when the begin finds none, in the server\'s words or its own', async () => {
    serving({ begin: none });
    const options = formOptions();
    const outcome = await authenticateAdvancedCredential(request(), options);
    expect(outcome).toEqual({ authenticated: false, text: 'Advanced authentication failed: No credentials detected. Please register a credential first.' });
    expect(options.onStart).toHaveBeenCalled();
    expect(authenticator.get).not.toHaveBeenCalled();

    serving({ begin: { status: 404, body: { $text: '<p>Not Found</p>' } } });
    expect((await authenticateAdvancedCredential(request(), formOptions())).text).toBe(
      `Advanced authentication failed: ${ADVANCED_ASSERTION_TEXT.noCredentials}`,
    );
  });

  it('says another refused begin as the server says it', async () => {
    serving({ begin: { status: 503, body: { error: 'Stored credentials could not be read.' } } });
    const outcome = await authenticateAdvancedCredential(request(), formOptions());
    expect(outcome.text).toMatch(/^Advanced authentication failed: Stored credentials could not be read\./);
    expect(asked()).toEqual([BEGIN]);
  });

  it('asks nothing for text that is not a request', async () => {
    serving(first);
    for (const [text, sentence] of [
      ['{}', ADVANCED_CEREMONY_TEXT.missingPublicKey],
      ['{"publicKey": {"userVerification": "required"}}', ADVANCED_ASSERTION_TEXT.missingChallenge],
    ]) {
      const options = formOptions();
      expect(await authenticateAdvancedCredential(text, options)).toEqual({
        authenticated: false,
        text: `Advanced authentication failed: ${sentence}`,
      });
      expect(options.onStart).not.toHaveBeenCalled();
    }
    expect((await authenticateAdvancedCredential('{ nope', formOptions())).text).toMatch(/^Advanced authentication failed: /);
    expect(asked()).toEqual([]);
  });

  it('says the browser\'s refusal by its name', async () => {
    serving(first);
    authenticatorGiving(() => Promise.reject(Object.assign(new Error('cancelled'), { name: 'NotAllowedError' })));
    const outcome = await authenticateAdvancedCredential(request(), formOptions());
    expect(outcome.text).toBe('Advanced authentication failed: User cancelled or no compatible authenticator detected');
    expect(asked()).toEqual([BEGIN]);
  });
});

describe('the hints', () => {
  it('narrow allowCredentials to the credentials whose attachment they allow, before anything is asked', async () => {
    serving(first);
    const list = [{ type: 'public-key', id: { $hex: CAPABLE.credentialIdHex } }];
    await authenticateAdvancedCredential(request({ hints: ['client-device'], allowCredentials: list }), formOptions());
    // Both saved credentials are cross-platform: a client-device hint leaves none.
    expect(sent(0).body.publicKey).not.toHaveProperty('allowCredentials');
    expect(PLAIN.authenticatorAttachment).toBe('cross-platform');
  });

  it('stop the ceremony when they refuse the request, saying their own message', async () => {
    serving(first);
    const options = formOptions();
    const outcome = await authenticateAdvancedCredential(request({ hints: ['hybrid'], allowCredentials: [{ id: '!!' }] }), options);
    expect(outcome).toEqual({ authenticated: false, text: 'base64 has "!" at position 0, outside its alphabet' });
    expect(options.onStart).not.toHaveBeenCalled();
    expect(asked()).toEqual([]);

    const silent = formOptions({ ensureHints: () => { throw new Error(''); } });
    expect((await authenticateAdvancedCredential(request(), silent)).text).toBe('Invalid hint configuration.');
  });
});

describe('the assertion the server is sent', () => {
  it('is its JSON as the browser writes it: its attachment, and no userHandle when it has none', async () => {
    serving(first);
    await authenticateAdvancedCredential(request(), formOptions());

    const sentAssertion = sent(1).body.__assertion_response;
    expect(sentAssertion).toEqual(credentialToJSON(recordedAssertion(first)));
    expect(sentAssertion.authenticatorAttachment).toBe('cross-platform');
    expect(sentAssertion.response).not.toHaveProperty('userHandle');
  });

  it('asks nothing in a browser without WebAuthn\'s JSON methods, and says to update it', async () => {
    serving(first);
    delete globalThis.PublicKeyCredential;
    const options = formOptions();
    const outcome = await authenticateAdvancedCredential(request(), options);

    expect(outcome).toEqual({ authenticated: false, text: `Advanced authentication failed: ${UPDATE_BROWSER_TEXT}` });
    expect(asked()).toEqual([]);
    expect(options.onStart).not.toHaveBeenCalled();
    expect(authenticator.get).not.toHaveBeenCalled();
  });
});
