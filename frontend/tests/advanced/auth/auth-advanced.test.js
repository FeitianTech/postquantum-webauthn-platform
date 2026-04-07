import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../../static/scripts/shared/webauthn-json.browser-ponyfill.js', () => ({
  create: vi.fn(),
  get: vi.fn(),
  parseCreationOptionsFromJSON: vi.fn((value) => value),
  parseRequestOptionsFromJSON: vi.fn((value) => value),
}));

vi.mock('../../../static/scripts/shared/binary-utils.js', () => ({
  convertExtensionsForClient: vi.fn((value) => value),
  normalizeClientExtensionResults: vi.fn((value) => value),
  bufferSourceToUint8Array: vi.fn((value) => {
    if (value instanceof ArrayBuffer) {
      return new Uint8Array(value);
    }
    if (ArrayBuffer.isView(value)) {
      return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
    }
    return null;
  }),
  bytesToHex: vi.fn((bytes) => Array.from(bytes || []).map((byte) => byte.toString(16).padStart(2, '0')).join('')),
}));

vi.mock('../../../static/scripts/advanced/hints.js', () => ({
  ensureAuthenticationHintsAllowed: vi.fn(() => []),
  applyAuthenticatorAttachmentPreference: vi.fn(),
  enforceAuthenticatorAttachmentWithHints: vi.fn(() => []),
}));

vi.mock('../../../static/scripts/shared/status.js', () => ({
  showStatus: vi.fn(),
  hideStatus: vi.fn(),
  showProgress: vi.fn(),
  hideProgress: vi.fn(),
}));

vi.mock('../../../static/scripts/advanced/forms.js', () => ({
  randomizeChallenge: vi.fn(),
  randomizePrfEval: vi.fn(),
  randomizeLargeBlobWrite: vi.fn(),
}));

vi.mock('../../../static/scripts/shared/username.js', () => ({
  randomizeUserIdentity: vi.fn(),
}));

vi.mock('../../../static/scripts/advanced/credential-display.js', () => ({
  showRegistrationResultModal: vi.fn().mockResolvedValue(undefined),
  loadSavedCredentials: vi.fn(),
  queueAuthenticatedCredentialFlash: vi.fn(),
  queueFailedCredentialFlash: vi.fn(),
  updateCredentialsDisplay: vi.fn(),
}));

vi.mock('../../../static/scripts/shared/auth-debug.js', () => ({
  printRegistrationDebug: vi.fn(),
  printAuthenticationDebug: vi.fn(),
}));

vi.mock('../../../static/scripts/shared/local-storage.js', () => ({
  saveAdvancedCredential: vi.fn(),
  prepareAdvancedCredentialsForServer: vi.fn(() => []),
  updateAdvancedCredentialSignCount: vi.fn(),
}));

import {
  create,
  get,
  parseCreationOptionsFromJSON,
  parseRequestOptionsFromJSON,
} from '../../../static/scripts/shared/webauthn-json.browser-ponyfill.js';
import {
  bufferSourceToUint8Array,
  bytesToHex,
  convertExtensionsForClient,
  normalizeClientExtensionResults,
} from '../../../static/scripts/shared/binary-utils.js';
import {
  applyAuthenticatorAttachmentPreference,
  enforceAuthenticatorAttachmentWithHints,
  ensureAuthenticationHintsAllowed,
} from '../../../static/scripts/advanced/hints.js';
import { hideProgress, showStatus } from '../../../static/scripts/shared/status.js';
import { randomizeChallenge, randomizeLargeBlobWrite, randomizePrfEval } from '../../../static/scripts/advanced/forms.js';
import { randomizeUserIdentity } from '../../../static/scripts/shared/username.js';
import {
  loadSavedCredentials,
  queueAuthenticatedCredentialFlash,
  queueFailedCredentialFlash,
  showRegistrationResultModal,
  updateCredentialsDisplay,
} from '../../../static/scripts/advanced/credential-display.js';
import { printAuthenticationDebug, printRegistrationDebug } from '../../../static/scripts/shared/auth-debug.js';
import {
  prepareAdvancedCredentialsForServer,
  saveAdvancedCredential,
  updateAdvancedCredentialSignCount,
} from '../../../static/scripts/shared/local-storage.js';
import { state } from '../../../static/scripts/shared/state.js';
import { advancedAuthenticate, advancedRegister } from '../../../static/scripts/advanced/auth-advanced.js';

function jsonResponse(payload, ok = true, status = 200) {
  return {
    ok,
    status,
    json: vi.fn().mockResolvedValue(payload),
    text: vi.fn().mockResolvedValue(typeof payload === 'string' ? payload : JSON.stringify(payload)),
  };
}

function buildDom() {
  document.body.innerHTML = `
    <textarea id="json-editor"></textarea>
    <input id="user-id" value="aabbccdd" />
    <input id="user-name" value="alice" />

    <input id="challenge-reg" value="abcdef" />
    <input id="prf-eval-first-reg" value="1111" />
    <input id="prf-eval-second-reg" value="2222" />
    <input id="fake-cred-length-reg" value="17" />
    <input id="min-pin-length" type="checkbox" />

    <input id="challenge-auth" value="fedcba" />
    <input id="prf-eval-first-auth" value="aaaa" />
    <input id="prf-eval-second-auth" value="bbbb" />
    <input id="large-blob-write" value="cccc" />
    <input id="fake-cred-length-auth" value="21" />

    <select id="hash-algorithm-auth">
      <option value="SHA-256">SHA-256</option>
      <option value="SHA-512" selected>SHA-512</option>
    </select>
  `;
}

describe('auth-advanced', () => {
  beforeEach(() => {
    buildDom();
    vi.clearAllMocks();
    vi.useFakeTimers();

    state.lastFakeCredLength = 0;
    window.lastFakeCredLength = 0;
  });

  afterEach(() => {
    vi.runOnlyPendingTimers();
    vi.useRealTimers();
  });

  it('completes advanced registration and persists resulting credential data', async () => {
    document.getElementById('min-pin-length').checked = true;
    document.getElementById('json-editor').value = JSON.stringify({
      publicKey: {
        rp: { name: 'RP' },
        user: { name: 'alice' },
        challenge: { $hex: 'abcd' },
        pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
        hints: ['client-device'],
        extensions: {},
      },
    });

    enforceAuthenticatorAttachmentWithHints.mockReturnValue(['platform']);
    parseCreationOptionsFromJSON.mockReturnValue({ publicKey: { rp: { id: 'example.com' } } });
    convertExtensionsForClient.mockReturnValue({ credProps: true });
    normalizeClientExtensionResults.mockImplementation((value) => value);

    const rawId = new Uint8Array([1, 2, 3]).buffer;
    create.mockResolvedValue({
      rawId,
      id: 'credential-from-browser',
      authenticatorAttachment: 'cross-platform',
      toJSON: () => ({
        id: 'credential-from-browser',
        clientExtensionResults: {
          appid: false,
        },
      }),
      getClientExtensionResults: () => ({
        credProps: { rk: true },
      }),
    });

    saveAdvancedCredential.mockReturnValue({ storageId: 'storage-1' });

    fetch.mockResolvedValueOnce(
      jsonResponse({
        __session_state: 'session-register-1',
        warnings: ['Registration begin warning'],
        publicKey: {
          challenge: { $base64url: 'AQID' },
          extensions: {
            credProps: true,
          },
        },
      }),
    );

    fetch.mockResolvedValueOnce(
      jsonResponse({
        algo: 'ES256',
        storedCredential: {
          credentialId: 'credential-from-server',
          userName: 'server-user',
        },
      }),
    );

    await advancedRegister();
    vi.runAllTimers();

    expect(fetch).toHaveBeenNthCalledWith(
      1,
      '/api/advanced/register/begin',
      expect.objectContaining({ method: 'POST' }),
    );

    expect(fetch).toHaveBeenNthCalledWith(
      2,
      '/api/advanced/register/complete',
      expect.objectContaining({ method: 'POST' }),
    );

    const completionPayload = JSON.parse(fetch.mock.calls[1][1].body);
    expect(completionPayload.__session_state).toBe('session-register-1');
    expect(completionPayload.__credential_response.clientExtensionResults).toEqual({
      appid: false,
      credProps: { rk: true },
    });

    expect(bufferSourceToUint8Array).toHaveBeenCalled();
    expect(bytesToHex).toHaveBeenCalled();
    expect(saveAdvancedCredential).toHaveBeenCalledWith(
      expect.objectContaining({
        credentialIdBase64Url: 'credential-from-browser',
        credentialIdHex: '010203',
        userName: 'server-user',
      }),
    );

    expect(showRegistrationResultModal).toHaveBeenCalledWith(
      expect.objectContaining({ id: 'credential-from-browser' }),
      null,
      { storageId: 'storage-1' },
    );

    expect(loadSavedCredentials).toHaveBeenCalled();
    expect(applyAuthenticatorAttachmentPreference).toHaveBeenCalled();
    expect(printRegistrationDebug).toHaveBeenCalled();

    expect(randomizeUserIdentity).toHaveBeenCalledTimes(1);
    expect(randomizeChallenge).toHaveBeenCalledWith('reg');
    expect(randomizePrfEval).toHaveBeenCalledWith('first', 'reg');
    expect(randomizePrfEval).toHaveBeenCalledWith('second', 'reg');

    expect(state.lastFakeCredLength).toBe(17);
    expect(window.lastFakeCredLength).toBe(17);

    expect(showStatus).toHaveBeenCalledWith(
      'advanced',
      'Advanced registration successful! Algorithm: ES256',
      'success',
    );
  });

  it('reports registration cancellation with unsupported feature hints', async () => {
    document.getElementById('json-editor').value = JSON.stringify({
      publicKey: {
        rp: { name: 'RP' },
        user: { name: 'alice' },
        challenge: { $hex: 'abcd' },
        pubKeyCredParams: [{ type: 'public-key', alg: -50 }],
        authenticatorSelection: {
          residentKey: 'required',
          userVerification: 'required',
        },
        extensions: {
          largeBlob: { support: 'required' },
        },
      },
    });

    parseCreationOptionsFromJSON.mockReturnValue({
      publicKey: {
        pubKeyCredParams: [{ type: 'public-key', alg: -50 }],
      },
    });

    fetch.mockResolvedValueOnce(
      jsonResponse({
        __session_state: 'session-register-2',
        publicKey: { challenge: { $base64url: 'AQID' } },
      }),
    );

    const cancelled = new Error('cancelled');
    cancelled.name = 'NotAllowedError';
    create.mockRejectedValue(cancelled);

    await advancedRegister();

    const finalStatusMessage = showStatus.mock.calls.at(-1)[1];
    expect(finalStatusMessage).toContain('Credential registration failed: User cancelled or authenticator not available');
    expect(finalStatusMessage).toContain('The authenticator may not support');
    expect(hideProgress).toHaveBeenCalledWith('advanced');
  });

  it('completes advanced authentication and updates sign-count state', async () => {
    document.getElementById('json-editor').value = JSON.stringify({
      publicKey: {
        challenge: { $hex: '1234' },
      },
    });

    ensureAuthenticationHintsAllowed.mockReturnValue([]);
    prepareAdvancedCredentialsForServer.mockReturnValue([
      { credentialId: 'credential-1', publicKey: 'PUB' },
    ]);

    parseRequestOptionsFromJSON.mockReturnValue({ publicKey: {} });
    convertExtensionsForClient.mockReturnValue({ largeBlob: { read: true } });
    normalizeClientExtensionResults.mockImplementation((value) => value);

    get.mockResolvedValue({
      authenticatorAttachment: 'platform',
      toJSON: () => ({
        id: 'assertion-1',
        clientExtensionResults: {
          appid: true,
        },
      }),
      getClientExtensionResults: () => ({
        prf: { results: true },
      }),
    });

    fetch.mockResolvedValueOnce(
      jsonResponse({
        __session_state: 'session-auth-1',
        publicKey: {
          challenge: { $base64url: 'AQID' },
        },
      }),
    );

    fetch.mockResolvedValueOnce(
      jsonResponse({
        authenticatedCredentialId: 'credential-1',
        signCount: 42,
      }),
    );

    await advancedAuthenticate();

    const completionPayload = JSON.parse(fetch.mock.calls[1][1].body);
    expect(completionPayload.__session_state).toBe('session-auth-1');
    expect(completionPayload.__hash_algorithm).toBe('SHA-512');

    expect(updateAdvancedCredentialSignCount).toHaveBeenCalledWith('credential-1', 42);
    expect(queueAuthenticatedCredentialFlash).toHaveBeenCalledWith('credential-1');
    expect(loadSavedCredentials).toHaveBeenCalled();

    expect(randomizeChallenge).toHaveBeenCalledWith('auth');
    expect(randomizePrfEval).toHaveBeenCalledWith('first', 'auth');
    expect(randomizePrfEval).toHaveBeenCalledWith('second', 'auth');
    expect(randomizeLargeBlobWrite).toHaveBeenCalledTimes(1);

    expect(printAuthenticationDebug).toHaveBeenCalled();
    expect(showStatus).toHaveBeenCalledWith('advanced', 'Advanced authentication successful!', 'success');
  });

  it('handles authentication completion errors and flashes failed credentials', async () => {
    document.getElementById('json-editor').value = JSON.stringify({
      publicKey: {
        challenge: { $hex: '1234' },
      },
    });

    ensureAuthenticationHintsAllowed.mockReturnValue([]);
    parseRequestOptionsFromJSON.mockReturnValue({ publicKey: {} });

    get.mockResolvedValue({
      toJSON: () => ({ id: 'assertion-1' }),
    });

    fetch.mockResolvedValueOnce(
      jsonResponse({
        __session_state: 'session-auth-2',
        publicKey: {
          challenge: { $base64url: 'AQID' },
        },
      }),
    );

    fetch.mockResolvedValueOnce({
      ok: false,
      status: 400,
      json: vi.fn().mockRejectedValue(new Error('no-json')),
      text: vi.fn().mockResolvedValue(
        JSON.stringify({
          error: 'Bad assertion from authenticator',
          failedCredentialId: 'credential-failed',
        }),
      ),
    });

    await advancedAuthenticate();

    expect(queueFailedCredentialFlash).toHaveBeenCalledWith('credential-failed');
    expect(updateCredentialsDisplay).toHaveBeenCalled();

    const finalMessage = showStatus.mock.calls.at(-1)[1];
    expect(finalMessage).toContain('Advanced authentication failed: Bad assertion from authenticator');
    expect(hideProgress).toHaveBeenCalledWith('advanced');
  });

  it('short-circuits authentication when hint validation fails', async () => {
    document.getElementById('json-editor').value = JSON.stringify({
      publicKey: {
        challenge: { $hex: '1234' },
      },
    });

    ensureAuthenticationHintsAllowed.mockImplementation(() => {
      throw new Error('Invalid hint configuration for test');
    });

    await advancedAuthenticate();

    expect(fetch).not.toHaveBeenCalled();
    expect(showStatus).toHaveBeenCalledWith('advanced', 'Invalid hint configuration for test', 'error');
    expect(hideProgress).toHaveBeenCalledWith('advanced');
  });

  it('maps advanced authentication InvalidState and Security errors to friendly messages', async () => {
    document.getElementById('json-editor').value = JSON.stringify({
      publicKey: {
        challenge: { $hex: '1234' },
      },
    });

    ensureAuthenticationHintsAllowed.mockReturnValue([]);
    parseRequestOptionsFromJSON.mockReturnValue({ publicKey: {} });
    fetch.mockResolvedValue(jsonResponse({ publicKey: { challenge: { $base64url: 'AQID' } } }));

    const invalidState = new Error('invalid state');
    invalidState.name = 'InvalidStateError';
    get.mockRejectedValueOnce(invalidState);
    await advancedAuthenticate();
    expect(showStatus).toHaveBeenCalledWith(
      'advanced',
      'Advanced authentication failed: Invalid authenticator state - please try again',
      'error',
    );

    const securityError = new Error('security issue');
    securityError.name = 'SecurityError';
    get.mockRejectedValueOnce(securityError);
    await advancedAuthenticate();
    expect(showStatus).toHaveBeenCalledWith(
      'advanced',
      'Advanced authentication failed: Security error - check your connection and try again',
      'error',
    );
  });

  it('surfaces hint-enforcement failures during advanced registration', async () => {
    document.getElementById('json-editor').value = JSON.stringify({
      publicKey: {
        rp: { id: 'example.com', name: 'Example RP' },
        user: {
          id: { $hex: 'aabbccdd' },
          name: 'alice',
          displayName: 'Alice',
        },
        challenge: { $hex: 'abcd' },
        pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
      },
    });

    enforceAuthenticatorAttachmentWithHints.mockImplementation(() => {
      throw new Error('Unsupported hint combination');
    });

    parseCreationOptionsFromJSON.mockReturnValue({ publicKey: {} });
    fetch.mockResolvedValueOnce(jsonResponse({ publicKey: { challenge: { $base64url: 'AQID' } } }));

    await advancedRegister();

    expect(showStatus).toHaveBeenCalledWith('advanced', 'Unsupported hint combination', 'error');
    const finalMessage = showStatus.mock.calls.at(-1)[1];
    expect(finalMessage).toContain('Credential registration failed: Unsupported hint combination');
  });
});
