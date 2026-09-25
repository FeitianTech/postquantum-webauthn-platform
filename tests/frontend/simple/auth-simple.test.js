import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../../frontend/static/scripts/shared/webauthn/json-ponyfill.js', () => ({
  create: vi.fn(),
  get: vi.fn(),
  parseCreationOptionsFromJSON: vi.fn((value) => value),
  parseRequestOptionsFromJSON: vi.fn((value) => value),
}));

vi.mock('../../../frontend/static/scripts/shared/utils/binary.js', () => ({
  convertExtensionsForClient: vi.fn((value) => value),
}));

vi.mock('../../../frontend/static/scripts/shared/ui/status.js', () => ({
  hideProgress: vi.fn(),
  hideStatus: vi.fn(),
  showProgress: vi.fn(),
  showStatus: vi.fn(),
}));

vi.mock('../../../frontend/static/scripts/advanced/credentials/index.js', () => ({
  loadSavedCredentials: vi.fn(),
  queueAuthenticatedCredentialFlash: vi.fn(),
  queueFailedCredentialFlash: vi.fn(),
  updateCredentialsDisplay: vi.fn(),
}));

vi.mock('../../../frontend/static/scripts/shared/debug/auth.js', () => ({
  printAuthenticationDebug: vi.fn(),
  printRegistrationDebug: vi.fn(),
}));

vi.mock('../../../frontend/static/scripts/shared/storage/local.js', () => ({
  getSimpleCredentialsForEmail: vi.fn(),
  prepareCredentialsForServer: vi.fn((value) => value),
  saveSimpleCredential: vi.fn(),
  updateSimpleCredentialSignCount: vi.fn(),
}));

import {
  create,
  get,
  parseCreationOptionsFromJSON,
  parseRequestOptionsFromJSON,
} from '../../../frontend/static/scripts/shared/webauthn/json-ponyfill.js';
import { convertExtensionsForClient } from '../../../frontend/static/scripts/shared/utils/binary.js';
import { loadSavedCredentials, queueAuthenticatedCredentialFlash, queueFailedCredentialFlash, updateCredentialsDisplay } from '../../../frontend/static/scripts/advanced/credentials/index.js';
import { getSimpleCredentialsForEmail, prepareCredentialsForServer, saveSimpleCredential, updateSimpleCredentialSignCount } from '../../../frontend/static/scripts/shared/storage/local.js';
import { hideProgress, showStatus } from '../../../frontend/static/scripts/shared/ui/status.js';
import { state } from '../../../frontend/static/scripts/shared/state.js';
import { simpleAuthenticate, simpleRegister } from '../../../frontend/static/scripts/simple/auth-simple.js';

function jsonResponse(payload, ok = true, status = 200) {
  return {
    ok,
    status,
    json: vi.fn().mockResolvedValue(payload),
    text: vi.fn().mockResolvedValue(typeof payload === 'string' ? payload : JSON.stringify(payload)),
  };
}

describe('auth-simple', () => {
  beforeEach(() => {
    document.body.innerHTML = '<input id="simple-email" />';
    state.lastFakeCredLength = 123;
    window.lastFakeCredLength = 123;
    vi.clearAllMocks();
  });

  it('rejects registration without a username', async () => {
    await simpleRegister();
    expect(showStatus).toHaveBeenCalledWith('simple', 'Please enter a username.', 'error');
  });

  it('rejects authentication without a username', async () => {
    await simpleAuthenticate();
    expect(showStatus).toHaveBeenCalledWith('simple', 'Please enter a username.', 'error');
  });

  it('registers a credential successfully', async () => {
    document.getElementById('simple-email').value = 'user@example.com';
    parseCreationOptionsFromJSON.mockReturnValue({ publicKey: {} });
    convertExtensionsForClient.mockReturnValue({ credProps: true });
    create.mockResolvedValue({
      toJSON: () => ({ id: 'cred-1' }),
    });
    fetch.mockResolvedValueOnce(jsonResponse({
      __session_state: 'session-1',
      publicKey: { extensions: { credProps: true } },
    }));
    fetch.mockResolvedValueOnce(jsonResponse({
      algo: 'ES256',
      storedCredential: { credentialId: 'cred-1', publicKey: 'cHVibGlj' },
    }));

    await simpleRegister();

    expect(create).toHaveBeenCalledWith({ publicKey: { extensions: { credProps: true } } });
    expect(saveSimpleCredential).toHaveBeenCalledWith({
      credentialId: 'cred-1',
      publicKey: 'cHVibGlj',
      email: 'user@example.com',
    });
    expect(loadSavedCredentials).toHaveBeenCalled();
    expect(state.lastFakeCredLength).toBe(0);
    expect(window.lastFakeCredLength).toBe(0);
    expect(hideProgress).toHaveBeenCalledWith('simple');
  });

  it('authenticates a credential successfully', async () => {
    document.getElementById('simple-email').value = 'user@example.com';
    getSimpleCredentialsForEmail.mockReturnValue([{ credentialId: 'cred-1', publicKey: 'cHVibGlj' }]);
    prepareCredentialsForServer.mockReturnValue([{ credentialId: 'cred-1', publicKey: 'cHVibGlj' }]);
    parseRequestOptionsFromJSON.mockReturnValue({ publicKey: {} });
    get.mockResolvedValue({
      toJSON: () => ({ id: 'cred-1' }),
    });
    fetch.mockResolvedValueOnce(jsonResponse({
      __session_state: 'session-2',
      publicKey: {},
    }));
    fetch.mockResolvedValueOnce(jsonResponse({
      authenticatedCredentialId: 'cred-1',
      signCount: 10,
    }));

    await simpleAuthenticate();

    expect(prepareCredentialsForServer).toHaveBeenCalled();
    expect(updateSimpleCredentialSignCount).toHaveBeenCalledWith('user@example.com', 'cred-1', 10);
    expect(queueAuthenticatedCredentialFlash).toHaveBeenCalledWith('cred-1');
    expect(loadSavedCredentials).toHaveBeenCalled();
  });

  it('handles authentication failures with credential feedback', async () => {
    document.getElementById('simple-email').value = 'user@example.com';
    getSimpleCredentialsForEmail.mockReturnValue([{ credentialId: 'cred-1', publicKey: 'cHVibGlj' }]);
    prepareCredentialsForServer.mockReturnValue([{ credentialId: 'cred-1', publicKey: 'cHVibGlj' }]);
    parseRequestOptionsFromJSON.mockReturnValue({ publicKey: {} });
    get.mockResolvedValue({
      toJSON: () => ({ id: 'cred-1' }),
    });
    fetch.mockResolvedValueOnce(jsonResponse({
      __session_state: 'session-2',
      publicKey: {},
    }));
    fetch.mockResolvedValueOnce({
      ok: false,
      status: 400,
      json: vi.fn().mockRejectedValue(new Error('no json')),
      text: vi.fn().mockResolvedValue(JSON.stringify({
        error: 'Bad assertion',
        failedCredentialId: 'cred-1',
      })),
    });

    await simpleAuthenticate();

    expect(queueFailedCredentialFlash).toHaveBeenCalledWith('cred-1');
    expect(updateCredentialsDisplay).toHaveBeenCalled();
    expect(showStatus).toHaveBeenCalledWith('simple', 'Bad assertion', 'error');
  });

  it('maps registration and authentication WebAuthn error names to friendly messages', async () => {
    document.getElementById('simple-email').value = 'user@example.com';

    parseCreationOptionsFromJSON.mockReturnValue({ publicKey: {} });
    create.mockRejectedValueOnce({ name: 'NotSupportedError', message: 'not supported' });
    fetch.mockResolvedValueOnce(jsonResponse({ publicKey: {} }));

    await simpleRegister();
    expect(showStatus).toHaveBeenCalledWith('simple', 'WebAuthn is not supported in this browser', 'error');

    getSimpleCredentialsForEmail.mockReturnValue([{ credentialId: 'cred-1', publicKey: 'cHVibGlj' }]);
    prepareCredentialsForServer.mockReturnValue([{ credentialId: 'cred-1', publicKey: 'cHVibGlj' }]);
    parseRequestOptionsFromJSON.mockReturnValue({ publicKey: {} });
    fetch.mockResolvedValueOnce(jsonResponse({ publicKey: {} }));
    get.mockRejectedValueOnce({ name: 'SecurityError', message: 'security issue' });

    await simpleAuthenticate();
    expect(showStatus).toHaveBeenCalledWith('simple', 'Security error - check your connection and try again', 'error');
  });

  it('maps registration InvalidState and Security errors to friendly messages', async () => {
    document.getElementById('simple-email').value = 'user@example.com';

    parseCreationOptionsFromJSON.mockReturnValue({ publicKey: {} });

    fetch.mockResolvedValueOnce(jsonResponse({ publicKey: {} }));
    create.mockRejectedValueOnce({ name: 'InvalidStateError', message: 'already registered' });
    await simpleRegister();
    expect(showStatus).toHaveBeenCalledWith('simple', 'Authenticator is already registered for this account', 'error');

    fetch.mockResolvedValueOnce(jsonResponse({ publicKey: {} }));
    create.mockRejectedValueOnce({ name: 'SecurityError', message: 'security issue' });
    await simpleRegister();
    expect(showStatus).toHaveBeenCalledWith('simple', 'Security error - check your connection and try again', 'error');
  });

  it('falls back to status-code auth failure message and maps InvalidState errors', async () => {
    document.getElementById('simple-email').value = 'user@example.com';

    getSimpleCredentialsForEmail.mockReturnValue([{ credentialId: 'cred-1', publicKey: 'cHVibGlj' }]);
    prepareCredentialsForServer.mockReturnValue([{ credentialId: 'cred-1', publicKey: 'cHVibGlj' }]);
    parseRequestOptionsFromJSON.mockReturnValue({ publicKey: {} });
    get.mockResolvedValueOnce({ toJSON: () => ({ id: 'cred-1' }) });
    fetch.mockResolvedValueOnce(jsonResponse({ publicKey: {} }));
    fetch.mockResolvedValueOnce({
      ok: false,
      status: 401,
      text: vi.fn().mockResolvedValue(''),
      json: vi.fn().mockRejectedValue(new Error('no json')),
    });

    await simpleAuthenticate();
    expect(showStatus).toHaveBeenCalledWith('simple', 'Authentication failed (401)', 'error');

    get.mockRejectedValueOnce({ name: 'InvalidStateError', message: 'invalid state' });
    fetch.mockResolvedValueOnce(jsonResponse({ publicKey: {} }));

    await simpleAuthenticate();
    expect(showStatus).toHaveBeenCalledWith('simple', 'Authenticator error or invalid credential', 'error');
  });

  it('reports begin-404 registration guidance and maps NotSupported auth errors', async () => {
    document.getElementById('simple-email').value = 'user@example.com';

    getSimpleCredentialsForEmail.mockReturnValue([{ credentialId: 'cred-1', publicKey: 'cHVibGlj' }]);
    prepareCredentialsForServer.mockReturnValue([{ credentialId: 'cred-1', publicKey: 'cHVibGlj' }]);

    fetch.mockResolvedValueOnce({
      ok: false,
      status: 404,
      text: vi.fn().mockResolvedValue('not found'),
      json: vi.fn().mockRejectedValue(new Error('no json')),
    });

    await simpleAuthenticate();
    expect(showStatus).toHaveBeenCalledWith('simple', 'No credentials found for this username. Please register first.', 'error');

    parseRequestOptionsFromJSON.mockReturnValue({ publicKey: {} });
    fetch.mockResolvedValueOnce(jsonResponse({ publicKey: {} }));
    get.mockRejectedValueOnce({ name: 'NotSupportedError', message: 'unsupported' });

    await simpleAuthenticate();
    expect(showStatus).toHaveBeenCalledWith('simple', 'WebAuthn is not supported in this browser', 'error');
  });

  it('handles missing stored credentials, begin server errors, and NotAllowed authentication mapping', async () => {
    document.getElementById('simple-email').value = 'user@example.com';

    getSimpleCredentialsForEmail.mockReturnValueOnce([]);
    await simpleAuthenticate();
    expect(showStatus).toHaveBeenCalledWith(
      'simple',
      'No credentials stored in this browser for the provided username. Please register first.',
      'error',
    );

    getSimpleCredentialsForEmail.mockReturnValueOnce([{ credentialId: 'cred-1', publicKey: 'cHVibGlj' }]);
    prepareCredentialsForServer.mockReturnValueOnce([{ credentialId: 'cred-1', publicKey: 'cHVibGlj' }]);
    fetch.mockResolvedValueOnce({
      ok: false,
      status: 500,
      text: vi.fn().mockResolvedValue('backend down'),
      json: vi.fn().mockRejectedValue(new Error('no json')),
    });
    await simpleAuthenticate();
    expect(showStatus).toHaveBeenCalledWith('simple', 'Server error: backend down', 'error');

    getSimpleCredentialsForEmail.mockReturnValueOnce([{ credentialId: 'cred-1', publicKey: 'cHVibGlj' }]);
    prepareCredentialsForServer.mockReturnValueOnce([{ credentialId: 'cred-1', publicKey: 'cHVibGlj' }]);
    parseRequestOptionsFromJSON.mockReturnValueOnce({ publicKey: {} });
    fetch.mockResolvedValueOnce(jsonResponse({ publicKey: {} }));

    const cancelled = new Error('cancelled');
    cancelled.name = 'NotAllowedError';
    get.mockRejectedValueOnce(cancelled);

    await simpleAuthenticate();
    expect(showStatus).toHaveBeenCalledWith('simple', 'User cancelled or authenticator not available', 'error');
  });
});

// What the simple tab shows when the server answers with an error. The bodies
// are the server's own (routes/errors.py, routes/simple/*).
const WERKZEUG_400 = '<!doctype html>\n<html lang=en>\n<title>400 Bad Request</title>\n<h1>Bad Request</h1>\n<p>The browser (or proxy) sent a request that this server could not understand.</p>\n';

function failedResponse(status, body, contentType = 'application/json') {
  const text = typeof body === 'string' ? body : JSON.stringify(body);
  return {
    ok: false,
    status,
    headers: new Headers({ 'Content-Type': contentType }),
    json: vi.fn(async () => JSON.parse(text)),
    text: vi.fn().mockResolvedValue(text),
  };
}

describe('simple tab messages for failed responses', () => {
  beforeEach(() => {
    document.body.innerHTML = '<input id="simple-email" value="user@example.com" />';
    vi.clearAllMocks();
    parseCreationOptionsFromJSON.mockImplementation((value) => value);
    parseRequestOptionsFromJSON.mockImplementation((value) => value);
    create.mockResolvedValue({ toJSON: () => ({ id: 'AQ' }) });
    get.mockResolvedValue({ toJSON: () => ({ id: 'AQ' }) });
    getSimpleCredentialsForEmail.mockReturnValue([{ credentialId: 'AQ', publicKey: 'cHVibGlj' }]);
  });

  async function registerAgainst(...responses) {
    responses.forEach((response) => fetch.mockResolvedValueOnce(response));
    await simpleRegister();
    return showStatus.mock.calls.at(-1)[1];
  }

  async function authenticateAgainst(...responses) {
    responses.forEach((response) => fetch.mockResolvedValueOnce(response));
    await simpleAuthenticate();
    return showStatus.mock.calls.at(-1)[1];
  }

  it('registration begin answering 503', async () => {
    expect(await registerAgainst(failedResponse(503, {
      error: 'The stored credentials could not be read. Please try again.',
    }))).toMatchInlineSnapshot(`"Server error: {"error":"The stored credentials could not be read. Please try again."}"`);
  });

  it('registration complete answering 409', async () => {
    expect(await registerAgainst(
      jsonResponse({ __session_state: 's', publicKey: {} }),
      failedResponse(409, {
        error: 'The stored credentials changed while this one was being saved, too many times, so the registration was not saved. Please try again.',
      }),
    )).toMatchInlineSnapshot(`"Registration failed: {"error":"The stored credentials changed while this one was being saved, too many times, so the registration was not saved. Please try again."}"`);
  });

  it('registration complete answering 413', async () => {
    expect(await registerAgainst(
      jsonResponse({ __session_state: 's', publicKey: {} }),
      failedResponse(413, { error: 'The request is larger than the limit of 8388608 bytes this server accepts.' }),
    )).toMatchInlineSnapshot(`"Registration failed: {"error":"The request is larger than the limit of 8388608 bytes this server accepts."}"`);
  });

  it('authentication complete answering 400 as HTML', async () => {
    expect(await authenticateAgainst(
      jsonResponse({ __session_state: 's', publicKey: {} }),
      failedResponse(400, WERKZEUG_400, 'text/html; charset=utf-8'),
    )).toMatchInlineSnapshot(`
      "<!doctype html>
      <html lang=en>
      <title>400 Bad Request</title>
      <h1>Bad Request</h1>
      <p>The browser (or proxy) sent a request that this server could not understand.</p>
      "
    `);
  });

  it('authentication complete answering 503 for the stored counter', async () => {
    expect(await authenticateAgainst(
      jsonResponse({ __session_state: 's', publicKey: {} }),
      failedResponse(503, {
        error: 'The stored signature counter could not be read, so authentication was rejected. Please try again.',
      }),
    )).toMatchInlineSnapshot(`"The stored signature counter could not be read, so authentication was rejected. Please try again."`);
  });
});
