import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../static/scripts/shared/binary-utils.js', () => {
  const decodeToHex = (value) => {
    if (!value || typeof value !== 'string') {
      return '';
    }
    const cleaned = value.trim();
    if (!cleaned) {
      return '';
    }

    let base64 = cleaned.replace(/-/g, '+').replace(/_/g, '/');
    while (base64.length % 4) {
      base64 += '=';
    }

    try {
      const binary = atob(base64);
      return Array.from(binary)
        .map((char) => char.charCodeAt(0).toString(16).padStart(2, '0'))
        .join('');
    } catch (error) {
      return cleaned.toLowerCase();
    }
  };

  const deepSort = (value) => {
    if (Array.isArray(value)) {
      return value.map((item) => deepSort(item));
    }
    if (!value || typeof value !== 'object') {
      return value;
    }

    const output = {};
    Object.keys(value)
      .sort((a, b) => a.localeCompare(b))
      .forEach((key) => {
        output[key] = deepSort(value[key]);
      });
    return output;
  };

  return {
    base64ToHex: vi.fn((value) => decodeToHex(value)),
    base64UrlToHex: vi.fn((value) => decodeToHex(value)),
    convertFormat: vi.fn((value) => value),
    currentFormatToJsonFormat: vi.fn((value) => ({ $hex: String(value || '').toLowerCase() })),
    getCurrentBinaryFormat: vi.fn(() => 'hex'),
    sortObjectKeys: vi.fn((value) => deepSort(value)),
  };
});

vi.mock('../../static/scripts/advanced/hints.js', () => ({
  collectSelectedHints: vi.fn((scope) => (scope === 'authentication' ? ['hybrid'] : ['client-device'])),
  deriveAllowedAttachmentsFromHints: vi.fn((hints) => {
    const result = [];
    (hints || []).forEach((hint) => {
      if (hint === 'client-device' && !result.includes('platform')) {
        result.push('platform');
      }
      if ((hint === 'hybrid' || hint === 'security-key') && !result.includes('cross-platform')) {
        result.push('cross-platform');
      }
    });
    return result;
  }),
  enforceAuthenticatorAttachmentWithHints: vi.fn((publicKey) => {
    if (!publicKey.authenticatorSelection) {
      publicKey.authenticatorSelection = {};
    }
    if (!publicKey.authenticatorSelection.authenticatorAttachment) {
      publicKey.authenticatorSelection.authenticatorAttachment = 'platform';
    }
  }),
  applyHintsToCheckboxes: vi.fn(),
  registerHintsChangeCallback: vi.fn(),
}));

vi.mock('../../static/scripts/advanced/credential-utils.js', () => ({
  getCredentialIdHex: vi.fn((cred) => cred?.credentialIdHex || ''),
  getCredentialUserHandleHex: vi.fn((cred) => cred?.userHandleHex || ''),
  getStoredCredentialAttachment: vi.fn((cred) => cred?.attachment || null),
  extractHexFromJsonFormat: vi.fn((value) => {
    if (!value) {
      return '';
    }
    if (typeof value === 'string') {
      return value.trim().toLowerCase();
    }
    if (typeof value === 'object') {
      if (typeof value.$hex === 'string' && value.$hex.trim()) {
        return value.$hex.trim().toLowerCase();
      }
      if (typeof value.$base64 === 'string' && value.$base64.trim()) {
        return 'base64hex';
      }
      if (typeof value.$base64url === 'string' && value.$base64url.trim()) {
        return 'base64urlhex';
      }
    }
    return '';
  }),
}));

vi.mock('../../static/scripts/shared/status.js', () => ({
  showStatus: vi.fn(),
}));

vi.mock('../../static/scripts/advanced/exclude-credentials.js', () => ({
  getFakeExcludeCredentials: vi.fn(() => ['ff99']),
  getFakeAllowCredentials: vi.fn(() => ['ee88']),
  setFakeExcludeCredentials: vi.fn(),
}));

import { applyHintsToCheckboxes } from '../../static/scripts/advanced/hints.js';
import {
  getFakeAllowCredentials,
  getFakeExcludeCredentials,
  setFakeExcludeCredentials,
} from '../../static/scripts/advanced/exclude-credentials.js';
import { showStatus } from '../../static/scripts/shared/status.js';
import { state } from '../../static/scripts/shared/state.js';
import {
  applyJsonChanges,
  cancelJsonEdit,
  editAssertOptions,
  editCreateOptions,
  getAdvancedAssertOptions,
  getAdvancedCreateOptions,
  getCredentialCreationOptions,
  getCredentialRequestOptions,
  resetJsonEditor,
  saveJsonEditor,
  updateAuthenticationFormFromJson,
  updateJsonEditor,
  updateJsonFromForm,
  updateRegistrationFormFromJson,
} from '../../static/scripts/advanced/json-editor.js';

function buildDom() {
  document.body.innerHTML = `
    <div class="json-editor-column"><h3>JSON Editor</h3></div>
    <textarea id="json-editor"></textarea>
    <button id="apply-json" style="display:none"></button>
    <button id="cancel-json" style="display:none"></button>

    <input id="user-id" value="aabbccdd" />
    <input id="user-name" value="alice" />
    <input id="user-display-name" value="Alice" />
    <input id="challenge-reg" value="abcd" />
    <input id="challenge-auth" value="1122" />

    <input id="timeout-reg" value="60000" />
    <input id="timeout-auth" value="45000" />

    <select id="attestation">
      <option value="direct" selected>direct</option>
      <option value="none">none</option>
    </select>

    <select id="authenticator-attachment">
      <option value="cross-platform" selected>cross-platform</option>
      <option value="platform">platform</option>
      <option value="unspecified">unspecified</option>
    </select>

    <select id="resident-key">
      <option value="discouraged">discouraged</option>
      <option value="preferred">preferred</option>
      <option value="required" selected>required</option>
    </select>

    <select id="user-verification-reg">
      <option value="preferred">preferred</option>
      <option value="required" selected>required</option>
      <option value="discouraged">discouraged</option>
    </select>

    <select id="user-verification-auth">
      <option value="preferred" selected>preferred</option>
      <option value="required">required</option>
      <option value="discouraged">discouraged</option>
    </select>

    <select id="allow-credentials">
      <option value="all" selected>all</option>
      <option value="empty">empty</option>
      <option value="aa11">aa11</option>
      <option value="bb22">bb22</option>
    </select>

    <input id="exclude-credentials" type="checkbox" checked />
    <input id="cred-props" type="checkbox" checked />
    <input id="min-pin-length" type="checkbox" checked />

    <select id="cred-protect">
      <option value="">none</option>
      <option value="userVerificationOptionalWithCredentialIDList" selected>uv-list</option>
      <option value="userVerificationRequired">uv-required</option>
    </select>
    <input id="enforce-cred-protect" type="checkbox" checked />

    <select id="large-blob-reg">
      <option value="">none</option>
      <option value="preferred">preferred</option>
      <option value="required" selected>required</option>
    </select>

    <select id="large-blob-auth">
      <option value="">none</option>
      <option value="read">read</option>
      <option value="write" selected>write</option>
    </select>

    <input id="large-blob-write" value="facefeed" />

    <input id="prf-reg" type="checkbox" checked />
    <input id="prf-eval-first-reg" value="0102" />
    <input id="prf-eval-second-reg" value="0304" />
    <input id="prf-eval-first-auth" value="0506" />
    <input id="prf-eval-second-auth" value="0708" />

    <input id="fake-cred-length-reg" value="64" />
    <input id="fake-cred-length-auth" value="32" />

    <input id="param-mldsa44" type="checkbox" />
    <input id="param-mldsa65" type="checkbox" />
    <input id="param-mldsa87" type="checkbox" />
    <input id="param-eddsa" type="checkbox" checked />
    <input id="param-es256" type="checkbox" checked />
    <input id="param-rs256" type="checkbox" checked />
    <input id="param-es384" type="checkbox" />
    <input id="param-es512" type="checkbox" />
    <input id="param-rs384" type="checkbox" />
    <input id="param-rs512" type="checkbox" />
    <input id="param-rs1" type="checkbox" />
    <input id="param-ed25519" type="checkbox" />
    <input id="param-es256k" type="checkbox" />
    <input id="param-esp256" type="checkbox" />
    <input id="param-esp384" type="checkbox" />
    <input id="param-esp512" type="checkbox" />
    <input id="param-ps256" type="checkbox" />
    <input id="param-ps384" type="checkbox" />
    <input id="param-ps512" type="checkbox" />
    <input id="param-ed448" type="checkbox" />
  `;
}

describe('json-editor', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    buildDom();

    state.currentSubTab = 'registration';
    state.currentJsonMode = null;
    state.currentJsonData = {};
    state.storedCredentials = [
      {
        credentialIdHex: 'aa11',
        userHandleHex: 'aabbccdd',
        attachment: 'platform',
      },
      {
        credentialIdHex: 'bb22',
        userHandleHex: 'ffffffff',
        attachment: 'cross-platform',
      },
    ];
  });

  it('builds creation/request options from form state and stored credentials', () => {
    const createOptions = getCredentialCreationOptions();

    expect(createOptions.publicKey.rp.name).toContain('FIDO2/WebAuthn PQC Developer Tools');
    expect(createOptions.publicKey.user.id).toEqual({ $hex: 'aabbccdd' });
    expect(createOptions.publicKey.pubKeyCredParams).toEqual(
      expect.arrayContaining([
        { type: 'public-key', alg: -8 },
        { type: 'public-key', alg: -7 },
        { type: 'public-key', alg: -257 },
      ]),
    );

    expect(createOptions.publicKey.excludeCredentials).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ id: { $hex: 'aa11' } }),
        expect.objectContaining({ id: { $hex: 'ff99' } }),
      ]),
    );

    expect(createOptions.publicKey.extensions).toEqual(
      expect.objectContaining({
        credProps: true,
        minPinLength: true,
        credentialProtectionPolicy: 'userVerificationOptionalWithCredentialIDList',
        enforceCredentialProtectionPolicy: true,
        largeBlob: { support: 'required' },
      }),
    );
    expect(createOptions.publicKey.extensions.prf.eval.first).toEqual({ $hex: '0102' });
    expect(createOptions.publicKey.extensions.prf.eval.second).toEqual({ $hex: '0304' });
    expect(createOptions.publicKey.hints).toEqual(['client-device']);

    const requestOptions = getCredentialRequestOptions();

    expect(requestOptions.publicKey.challenge).toEqual({ $hex: '1122' });
    expect(requestOptions.publicKey.rpId).toBe(window.location.hostname);
    expect(requestOptions.publicKey.allowCredentials).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ id: { $hex: 'bb22' } }),
        expect.objectContaining({ id: { $hex: 'ee88' } }),
      ]),
    );

    expect(requestOptions.publicKey.extensions.largeBlob).toEqual({ write: { $hex: 'facefeed' } });
    expect(requestOptions.publicKey.extensions.prf.eval.first).toEqual({ $hex: '0506' });
    expect(requestOptions.publicKey.extensions.prf.eval.second).toEqual({ $hex: '0708' });
    expect(requestOptions.publicKey.hints).toEqual(['hybrid']);

    expect(getFakeExcludeCredentials).toHaveBeenCalled();
    expect(getFakeAllowCredentials).toHaveBeenCalled();
  });

  it('updates JSON editor content and title for registration/authentication subtabs', () => {
    state.currentSubTab = 'registration';
    updateJsonEditor();

    expect(document.querySelector('.json-editor-column h3').textContent).toContain('CredentialCreationOptions');
    const registrationParsed = JSON.parse(document.getElementById('json-editor').value);
    expect(registrationParsed.publicKey).toBeDefined();

    state.currentSubTab = 'authentication';
    updateJsonEditor();

    expect(document.querySelector('.json-editor-column h3').textContent).toContain('CredentialRequestOptions');
    const authenticationParsed = JSON.parse(document.getElementById('json-editor').value);
    expect(authenticationParsed.publicKey).toBeDefined();
  });

  it('saves valid registration JSON, validates structure, and reports success', () => {
    state.currentSubTab = 'registration';

    document.getElementById('json-editor').value = JSON.stringify({
      publicKey: {
        rp: {
          name: 'RP Name',
          id: 'example.com',
        },
        user: {
          id: { $hex: 'aa55' },
          name: 'bob@example.com',
          displayName: 'Bob',
        },
        challenge: { $hex: '1234' },
        timeout: 12345,
        pubKeyCredParams: [
          { type: 'public-key', alg: -7 },
        ],
        authenticatorSelection: {
          authenticatorAttachment: 'platform',
          residentKey: 'required',
          requireResidentKey: true,
          userVerification: 'required',
        },
        attestation: 'direct',
        excludeCredentials: [
          {
            type: 'public-key',
            id: { $hex: 'aa11' },
            transports: ['usb'],
          },
        ],
        hints: ['client-device'],
        extensions: {
          credProps: true,
          minPinLength: true,
          largeBlob: { support: 'required' },
          prf: {
            eval: {
              first: { $hex: 'cafe' },
            },
          },
        },
      },
    });

    saveJsonEditor();

    expect(document.getElementById('user-name').value).toBe('bob@example.com');
    expect(document.getElementById('user-display-name').value).toBe('Bob');
    expect(document.getElementById('timeout-reg').value).toBe('12345');
    expect(document.getElementById('authenticator-attachment').value).toBe('platform');

    expect(showStatus).toHaveBeenCalledWith(
      'advanced',
      'JSON changes saved successfully!',
      'success',
    );

    const parsedAfterSave = JSON.parse(document.getElementById('json-editor').value);
    expect(parsedAfterSave.publicKey).toBeDefined();
  });

  it('handles invalid save payloads and reset behavior for malformed editor JSON', () => {
    state.currentSubTab = 'registration';
    document.getElementById('json-editor').value = JSON.stringify({ invalid: true });
    saveJsonEditor();

    const saveError = showStatus.mock.calls.at(-1)[1];
    expect(saveError).toContain('JSON validation failed');

    state.currentSubTab = 'authentication';
    document.getElementById('json-editor').value = '{ malformed';
    resetJsonEditor();

    expect(showStatus).toHaveBeenCalledWith(
      'advanced',
      'JSON editor reset to current settings.',
      'info',
    );

    const parsedAfterReset = JSON.parse(document.getElementById('json-editor').value);
    expect(parsedAfterReset.publicKey).toBeDefined();
  });

  it('updates registration and authentication forms from provided publicKey JSON', () => {
    updateRegistrationFormFromJson({
      user: {
        id: { $hex: 'beef' },
        name: 'updated-user',
        displayName: 'Updated User',
      },
      challenge: { $hex: 'c0de' },
      timeout: 777,
      attestation: 'none',
      pubKeyCredParams: [
        { alg: -7 },
        { alg: -257 },
      ],
      authenticatorSelection: {
        authenticatorAttachment: 'platform',
        residentKey: 'required',
        userVerification: 'required',
        requireResidentKey: true,
      },
      excludeCredentials: [
        { id: { $hex: 'aa11' } },
        { id: { $hex: 'ff99' } },
      ],
      extensions: {
        credProps: true,
        minPinLength: true,
        credentialProtectionPolicy: 'userVerificationRequired',
        enforceCredentialProtectionPolicy: true,
        prf: {
          eval: {
            first: { $hex: '1111' },
            second: { $hex: '2222' },
          },
        },
      },
      hints: ['client-device'],
    });

    expect(document.getElementById('user-name').value).toBe('updated-user');
    expect(document.getElementById('user-display-name').value).toBe('Updated User');
    expect(document.getElementById('challenge-reg').value).toBe('c0de');
    expect(document.getElementById('attestation').value).toBe('none');
    expect(document.getElementById('param-es256').checked).toBe(true);
    expect(document.getElementById('param-rs256').checked).toBe(true);
    expect(document.getElementById('authenticator-attachment').value).toBe('platform');
    expect(document.getElementById('exclude-credentials').checked).toBe(true);
    expect(setFakeExcludeCredentials).toHaveBeenCalledWith(['ff99']);

    updateAuthenticationFormFromJson({
      challenge: { $hex: 'd00d' },
      timeout: 333,
      allowCredentials: [
        { id: { $hex: 'bb22' } },
      ],
      userVerification: 'required',
      extensions: {
        prf: {
          eval: {
            first: { $hex: 'aaaa' },
            second: { $hex: 'bbbb' },
          },
        },
        largeBlob: {
          write: { $hex: '1234' },
        },
      },
      hints: ['hybrid'],
    });

    expect(document.getElementById('challenge-auth').value).toBe('d00d');
    expect(document.getElementById('timeout-auth').value).toBe('333');
    expect(document.getElementById('allow-credentials').value).toBe('bb22');
    expect(document.getElementById('user-verification-auth').value).toBe('required');
    expect(document.getElementById('large-blob-auth').value).toBe('write');
    expect(document.getElementById('large-blob-write').value).toBe('1234');

    expect(applyHintsToCheckboxes).toHaveBeenCalledWith(['client-device'], 'registration');
    expect(applyHintsToCheckboxes).toHaveBeenCalledWith(['hybrid'], 'authentication');
  });

  it('supports advanced JSON edit/apply/cancel and in-mode refresh behavior', () => {
    const createOptions = getAdvancedCreateOptions();
    expect(createOptions.username).toBe('alice');
    expect(createOptions.challenge).toBe('abcd');
    expect(createOptions.extensions.credProps).toBe(true);

    document.getElementById('allow-credentials').value = 'bb22';
    const assertOptions = getAdvancedAssertOptions();
    expect(assertOptions.allowCredentials).toBe('bb22');
    expect(assertOptions.specificCredentialId).toBe('bb22');
    expect(assertOptions.challenge).toBe('1122');

    editCreateOptions();
    expect(state.currentJsonMode).toBe('create');
    expect(document.getElementById('apply-json').style.display).toBe('inline-block');

    document.getElementById('json-editor').value = JSON.stringify({
      username: 'new-user',
      displayName: 'New User',
      attestation: 'none',
      userVerification: 'discouraged',
      residentKey: 'preferred',
      authenticatorAttachment: 'platform',
    });

    applyJsonChanges();
    expect(document.getElementById('user-name').value).toBe('new-user');
    expect(document.getElementById('attestation').value).toBe('none');
    expect(state.currentJsonMode).toBeNull();
    expect(document.getElementById('apply-json').style.display).toBe('none');

    editAssertOptions();
    expect(state.currentJsonMode).toBe('assert');

    document.getElementById('json-editor').value = JSON.stringify({
      userVerification: 'required',
    });
    applyJsonChanges();
    expect(document.getElementById('user-verification-auth').value).toBe('required');

    state.currentJsonMode = 'create';
    document.getElementById('json-editor').value = '{ invalid';
    applyJsonChanges();
    const invalidMessage = showStatus.mock.calls.at(-1)[1];
    expect(invalidMessage).toContain('Invalid JSON');

    state.currentJsonMode = 'create';
    updateJsonFromForm();
    expect(document.getElementById('json-editor').value).toContain('"username"');

    state.currentJsonMode = 'assert';
    updateJsonFromForm();
    expect(document.getElementById('json-editor').value).toContain('"allowCredentials"');

    cancelJsonEdit();
    expect(document.getElementById('json-editor').value).toBe('');
    expect(state.currentJsonMode).toBeNull();
  });
});
