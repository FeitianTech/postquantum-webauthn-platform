import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../static/scripts/shared/binary-utils.js', () => ({
  base64ToHex: vi.fn((value) => String(value || '').toLowerCase()),
  base64UrlToHex: vi.fn((value) => String(value || '').toLowerCase()),
  convertFormat: vi.fn((value) => value),
  currentFormatToJsonFormat: vi.fn((value) => ({ $hex: String(value || '').toLowerCase() })),
  getCurrentBinaryFormat: vi.fn(() => 'hex'),
  sortObjectKeys: vi.fn((value) => value),
}));

vi.mock('../../static/scripts/advanced/hints.js', () => ({
  collectSelectedHints: vi.fn((scope) => (scope === 'authentication' ? ['hybrid'] : ['client-device'])),
  deriveAllowedAttachmentsFromHints: vi.fn(() => []),
  enforceAuthenticatorAttachmentWithHints: vi.fn(),
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
    if (typeof value === 'object' && typeof value.$hex === 'string') {
      return value.$hex.trim().toLowerCase();
    }
    return '';
  }),
}));

vi.mock('../../static/scripts/shared/status.js', () => ({
  showStatus: vi.fn(),
}));

vi.mock('../../static/scripts/advanced/exclude-credentials.js', () => ({
  getFakeExcludeCredentials: vi.fn(() => []),
  getFakeAllowCredentials: vi.fn(() => []),
  setFakeExcludeCredentials: vi.fn(),
}));

import { currentFormatToJsonFormat } from '../../static/scripts/shared/binary-utils.js';
import { showStatus } from '../../static/scripts/shared/status.js';
import { state } from '../../static/scripts/shared/state.js';
import {
  applyJsonChanges,
  resetJsonEditor,
  saveJsonEditor,
  updateAuthenticationFormFromJson,
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

    <select id="attestation"><option value="direct" selected>direct</option><option value="none">none</option></select>

    <select id="authenticator-attachment">
      <option value="cross-platform" selected>cross-platform</option>
      <option value="platform">platform</option>
      <option value="unspecified">unspecified</option>
    </select>

    <select id="resident-key"><option value="discouraged">discouraged</option><option value="preferred">preferred</option><option value="required" selected>required</option></select>
    <select id="user-verification-reg"><option value="preferred">preferred</option><option value="required" selected>required</option><option value="discouraged">discouraged</option></select>
    <select id="user-verification-auth"><option value="preferred" selected>preferred</option><option value="required">required</option><option value="discouraged">discouraged</option></select>

    <select id="allow-credentials">
      <option value="all" selected>all</option>
      <option value="empty">empty</option>
      <option value="aa11">aa11</option>
    </select>

    <input id="exclude-credentials" type="checkbox" />
    <input id="cred-props" type="checkbox" />
    <input id="min-pin-length" type="checkbox" />

    <select id="cred-protect"><option value="">none</option><option value="userVerificationRequired">required</option></select>
    <input id="enforce-cred-protect" type="checkbox" checked />

    <select id="large-blob-reg"><option value="">none</option><option value="required">required</option></select>
    <select id="large-blob-auth"><option value="">none</option><option value="read">read</option><option value="write">write</option></select>

    <input id="large-blob-write" value="facefeed" />

    <input id="prf-reg" type="checkbox" />
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
    <input id="param-es256" type="checkbox" />
    <input id="param-rs256" type="checkbox" />
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

describe('json-editor validation edge cases', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    buildDom();

    state.currentSubTab = 'registration';
    state.currentJsonMode = null;
    state.currentJsonData = {};
    state.storedCredentials = [
      { credentialIdHex: 'aa11', userHandleHex: 'aabbccdd', attachment: 'platform' },
    ];
  });

  it('reports validation failure for unsupported authentication publicKey properties', () => {
    state.currentSubTab = 'authentication';
    document.getElementById('json-editor').value = JSON.stringify({
      publicKey: {
        challenge: { $hex: 'beef' },
        timeout: 1000,
        userVerification: 'preferred',
        unknownTopLevelField: true,
      },
    });

    saveJsonEditor();

    const message = showStatus.mock.calls.at(-1)[1];
    expect(message).toContain('JSON validation failed');
    expect(message).toContain('unsupported properties: unknownTopLevelField');
  });

  it('reports reset errors when form-derived registration options become invalid', () => {
    state.currentSubTab = 'registration';
    document.getElementById('json-editor').value = '{}';

    currentFormatToJsonFormat.mockReturnValueOnce(null).mockReturnValueOnce(null);
    resetJsonEditor();

    const message = showStatus.mock.calls.at(-1)[1];
    expect(message).toContain('Unable to reset JSON editor');
    expect(message).toContain('publicKey.user.id is required.');
  });

  it('applies create-mode attachment fallback via legacy event dispatch when Event constructor fails', () => {
    state.currentJsonMode = 'create';

    const attachmentSelect = document.getElementById('authenticator-attachment');
    const dispatchSpy = vi.spyOn(attachmentSelect, 'dispatchEvent');
    const OriginalEvent = globalThis.Event;

    try {
      globalThis.Event = class Event {
        constructor() {
          throw new Error('Event construction unavailable');
        }
      };

      document.getElementById('json-editor').value = JSON.stringify({
        authenticatorAttachment: 'unsupported',
      });

      applyJsonChanges();
    } finally {
      globalThis.Event = OriginalEvent;
    }

    expect(attachmentSelect.value).toBe('cross-platform');
    expect(dispatchSpy).toHaveBeenCalled();
    expect(showStatus).toHaveBeenCalledWith('advanced', 'JSON changes applied successfully!', 'success');
  });

  it('handles allowCredentials fallback semantics when updating authentication form', () => {
    const allowSelect = document.getElementById('allow-credentials');

    allowSelect.value = 'all';
    updateAuthenticationFormFromJson({
      challenge: { $hex: '1234' },
    });
    expect(allowSelect.value).toBe('empty');

    allowSelect.value = 'aa11';
    updateAuthenticationFormFromJson({
      challenge: { $hex: '5678' },
      allowCredentials: [],
    });
    expect(allowSelect.value).toBe('aa11');
  });
});
