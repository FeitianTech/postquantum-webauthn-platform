import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../static/scripts/shared/webauthn-json.browser-ponyfill.js', () => ({
  create: vi.fn(),
  get: vi.fn(),
  parseCreationOptionsFromJSON: vi.fn((value) => value),
  parseRequestOptionsFromJSON: vi.fn((value) => value),
}));

vi.mock('../../static/scripts/shared/binary-utils.js', () => ({
  convertExtensionsForClient: vi.fn((value) => value),
}));

vi.mock('../../static/scripts/shared/status.js', () => ({
  hideProgress: vi.fn(),
  hideStatus: vi.fn(),
  showProgress: vi.fn(),
  showStatus: vi.fn(),
}));

vi.mock('../../static/scripts/advanced/credential-display.js', () => ({
  loadSavedCredentials: vi.fn(),
  queueAuthenticatedCredentialFlash: vi.fn(),
  queueFailedCredentialFlash: vi.fn(),
  updateCredentialsDisplay: vi.fn(),
}));

vi.mock('../../static/scripts/shared/auth-debug.js', () => ({
  printAuthenticationDebug: vi.fn(),
  printRegistrationDebug: vi.fn(),
}));

vi.mock('../../static/scripts/shared/local-storage.js', () => ({
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
} from '../../static/scripts/shared/webauthn-json.browser-ponyfill.js';
import { convertExtensionsForClient } from '../../static/scripts/shared/binary-utils.js';
import { loadSavedCredentials, queueAuthenticatedCredentialFlash, queueFailedCredentialFlash, updateCredentialsDisplay } from '../../static/scripts/advanced/credential-display.js';
import { getSimpleCredentialsForEmail, prepareCredentialsForServer, saveSimpleCredential, updateSimpleCredentialSignCount } from '../../static/scripts/shared/local-storage.js';
import { hideProgress, showStatus } from '../../static/scripts/shared/status.js';
import { state } from '../../static/scripts/shared/state.js';
import { simpleAuthenticate, simpleRegister } from '../../static/scripts/simple/auth-simple.js';

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
});
