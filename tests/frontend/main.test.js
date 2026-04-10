import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../frontend/static/scripts/shared/webauthn/json-ponyfill.js', () => ({
  create: vi.fn(),
  get: vi.fn(),
  parseCreationOptionsFromJSON: vi.fn(),
  parseRequestOptionsFromJSON: vi.fn(),
}));

vi.mock('../../frontend/static/scripts/shared/ui/navigation.js', () => ({
  switchTab: vi.fn(),
  switchSubTab: vi.fn(),
  toggleSection: vi.fn(),
  initializeNavigationMenu: vi.fn(() => ({
    open: vi.fn(),
    close: vi.fn(),
  })),
}));

vi.mock('../../frontend/static/scripts/shared/ui/core.js', () => ({
  showInfoPopup: vi.fn(),
  hideInfoPopup: vi.fn(),
  toggleLanguage: vi.fn(),
  toggleJsonEditorExpansion: vi.fn(),
  updateGlobalScrollLock: vi.fn(),
  closeModal: vi.fn(),
  initializeStickyHeader: vi.fn(),
}));

vi.mock('../../frontend/static/scripts/advanced/auth/forms.js', () => ({
  updateFieldLabels: vi.fn(),
  randomizeChallenge: vi.fn(),
  randomizePrfEval: vi.fn(),
  randomizeLargeBlobWrite: vi.fn(),
  validatePrfInputs: vi.fn(),
  validateUserIdInput: vi.fn(),
  validateChallengeInputs: vi.fn(),
  validatePrfEvalInputs: vi.fn(),
  validateLargeBlobWriteInput: vi.fn(),
  checkLargeBlobCapability: vi.fn(),
  updateAuthenticationExtensionAvailability: vi.fn(),
}));

vi.mock('../../frontend/static/scripts/advanced/ui/resets.js', () => ({
  resetRegistrationForm: vi.fn(),
  resetAuthenticationForm: vi.fn(),
}));

vi.mock('../../frontend/static/scripts/shared/auth/username.js', () => ({
  initializeSimpleUsername: vi.fn(),
  randomizeUserIdentity: vi.fn(),
  randomizeSimpleUsername: vi.fn(),
}));

vi.mock('../../frontend/static/scripts/simple/auth-simple.js', () => ({
  simpleRegister: vi.fn(),
  simpleAuthenticate: vi.fn(),
}));

vi.mock('../../frontend/static/scripts/advanced/auth/advanced.js', () => ({
  advancedRegister: vi.fn(),
  advancedAuthenticate: vi.fn(),
}));

vi.mock('../../frontend/static/scripts/decoder/codec.js', () => ({
  processCodec: vi.fn(),
  clearCodec: vi.fn(),
  toggleRawCodec: vi.fn(),
  switchCodecMode: vi.fn(),
}));

vi.mock('../../frontend/static/scripts/advanced/json-editor.js', () => ({
  saveJsonEditor: vi.fn(),
  resetJsonEditor: vi.fn(),
  updateJsonEditor: vi.fn(),
  updateJsonFromForm: vi.fn(),
  editCreateOptions: vi.fn(),
  editAssertOptions: vi.fn(),
  applyJsonChanges: vi.fn(),
  cancelJsonEdit: vi.fn(),
}));

vi.mock('../../frontend/static/scripts/advanced/credential-display.js', () => ({
  loadSavedCredentials: vi.fn().mockResolvedValue(undefined),
  showCredentialDetails: vi.fn(),
  navigateToMdsAuthenticator: vi.fn(),
  closeCredentialModal: vi.fn(),
  closeRegistrationResultModal: vi.fn(),
  closeRegistrationDetailModal: vi.fn(),
  deleteCredential: vi.fn(),
  clearAllCredentials: vi.fn(),
  updateAllowCredentialsDropdown: vi.fn(),
}));

vi.mock('../../frontend/static/scripts/advanced/mds.js', () => ({
  waitForMetadataLoad: vi.fn().mockResolvedValue(true),
}));

vi.mock('../../frontend/static/scripts/advanced/auth/hints.js', () => ({
  registerHintsChangeCallback: vi.fn(),
}));

vi.mock('../../frontend/static/scripts/advanced/json-editor-utils.js', () => ({
  handleJsonEditorKeydown: vi.fn(),
}));

vi.mock('../../frontend/static/scripts/advanced/auth/exclude-credentials.js', () => ({
  createFakeExcludeCredential: vi.fn(() => true),
  removeFakeExcludeCredential: vi.fn(() => true),
  renderFakeExcludeCredentialList: vi.fn(),
  createFakeAllowCredential: vi.fn(() => true),
  removeFakeAllowCredential: vi.fn(() => true),
  renderFakeAllowCredentialList: vi.fn(),
}));

vi.mock('../../frontend/static/scripts/advanced/ui/settings-nav.js', () => ({
  initializeAdvancedSettingsNavigation: vi.fn(),
}));

vi.mock('../../frontend/static/scripts/shared/browser/analyze.js', () => ({
  initializeAnalyzeBrowser: vi.fn(),
}));

vi.mock('../../frontend/static/scripts/shared/utils/loader.js', () => ({
  initializeLoader: vi.fn(),
  loaderComplete: vi.fn(),
  loaderSetPhase: vi.fn(),
}));

import { createFakeAllowCredential, createFakeExcludeCredential, removeFakeAllowCredential, removeFakeExcludeCredential } from '../../frontend/static/scripts/advanced/auth/exclude-credentials.js';
import { checkLargeBlobCapability, randomizeChallenge, randomizeLargeBlobWrite, randomizePrfEval, updateAuthenticationExtensionAvailability, updateFieldLabels, validateChallengeInputs, validateLargeBlobWriteInput, validatePrfEvalInputs, validatePrfInputs, validateUserIdInput } from '../../frontend/static/scripts/advanced/auth/forms.js';
import { registerHintsChangeCallback } from '../../frontend/static/scripts/advanced/auth/hints.js';
import { waitForMetadataLoad } from '../../frontend/static/scripts/advanced/mds.js';
import { initializeAdvancedSettingsNavigation } from '../../frontend/static/scripts/advanced/ui/settings-nav.js';
import { loadSavedCredentials, updateAllowCredentialsDropdown } from '../../frontend/static/scripts/advanced/credential-display.js';
import { updateJsonEditor, updateJsonFromForm } from '../../frontend/static/scripts/advanced/json-editor.js';
import { handleJsonEditorKeydown } from '../../frontend/static/scripts/advanced/json-editor-utils.js';
import { initializeNavigationMenu } from '../../frontend/static/scripts/shared/ui/navigation.js';
import { initializeSimpleUsername, randomizeUserIdentity } from '../../frontend/static/scripts/shared/auth/username.js';
import { closeModal, initializeStickyHeader, toggleJsonEditorExpansion } from '../../frontend/static/scripts/shared/ui/core.js';
import { initializeAnalyzeBrowser } from '../../frontend/static/scripts/shared/browser/analyze.js';
import { initializeLoader, loaderComplete, loaderSetPhase } from '../../frontend/static/scripts/shared/utils/loader.js';

function buildDom() {
  document.body.innerHTML = `
    <div class="header">
      <button data-header-menu-toggle aria-expanded="false"></button>
      <div data-header-nav>
        <div class="nav-tabs">
          <button class="nav-tab" data-tab="simple">Simple</button>
          <button class="nav-tab" data-tab="advanced">Advanced</button>
        </div>
      </div>
      <div data-header-overlay hidden aria-hidden="true"></div>
    </div>

    <div id="advanced-tab">
      <input id="user-name" value="alice" />
      <input id="user-display-name" value="" />
      <input id="user-id" value="abcd" />
      <input id="challenge-reg" value="1111" />
      <input id="challenge-auth" value="2222" />
      <input id="prf-eval-first-reg" value="aaaa" />
      <input id="prf-eval-second-reg" value="bbbb" />
      <input id="prf-eval-first-auth" value="cccc" />
      <input id="prf-eval-second-auth" value="dddd" />
      <input id="large-blob-write" value="eeee" />
      <select id="authenticator-attachment"><option value="platform" selected>platform</option></select>
      <select id="large-blob-auth"><option value="write" selected>write</option></select>
      <select id="allow-credentials"><option value="all" selected>all</option></select>
      <select id="cred-protect"><option value="" selected>none</option><option value="required">required</option></select>
      <select id="resident-key"><option value="required" selected>required</option></select>
      <select id="user-verification-reg"><option value="preferred" selected>preferred</option></select>
      <select id="user-verification-auth"><option value="preferred" selected>preferred</option></select>

      <input id="hint-client-device" type="checkbox" />
      <input id="hint-hybrid" type="checkbox" />
      <input id="hint-security-key" type="checkbox" />

      <input id="fake-cred-length-reg" value="32" />
      <button id="fake-cred-generate">gen</button>
      <div id="fake-cred-generated-list">
        <button data-fake-credential-index="0">remove</button>
      </div>

      <input id="fake-cred-length-auth" value="32" />
      <button id="fake-cred-generate-auth">gen-auth</button>
      <div id="fake-cred-auth-generated-list">
        <button data-fake-credential-index="0">remove-auth</button>
      </div>

      <input id="enforce-cred-protect" type="checkbox" checked />
      <select id="large-blob-reg"><option value="required" selected>required</option></select>

      <div id="json-editor-container">
        <textarea id="json-editor"></textarea>
        <button id="json-editor-close">close</button>
      </div>
    </div>

    <div class="modal" id="modal-a"><div>inner</div></div>
    <div id="simple-tab" class="tab-content active"></div>
    <div id="advanced-tab-content" class="tab-content"></div>
    <div id="mds-tab"></div>
  `;
}

async function importMainFresh() {
  vi.resetModules();
  return import('../../frontend/static/scripts/main.js');
}

describe('main startup and wiring', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.useFakeTimers();
    buildDom();
  });

  it('runs startup flow on DOMContentLoaded and binds key UI listeners', async () => {
    await importMainFresh();

    expect(initializeAnalyzeBrowser).toHaveBeenCalledTimes(1);
    expect(registerHintsChangeCallback).toHaveBeenCalledTimes(1);

    document.dispatchEvent(new Event('DOMContentLoaded'));
    await vi.runAllTimersAsync();

    expect(initializeLoader).toHaveBeenCalledTimes(1);
    expect(loaderSetPhase).toHaveBeenCalledWith('Loading saved credentials…', { progress: 12 });
    expect(initializeNavigationMenu).toHaveBeenCalledTimes(1);
    expect(initializeStickyHeader).toHaveBeenCalledTimes(1);
    expect(updateFieldLabels).toHaveBeenCalledTimes(1);
    expect(initializeAdvancedSettingsNavigation).toHaveBeenCalledTimes(1);
    expect(loadSavedCredentials).toHaveBeenCalledTimes(1);
    expect(waitForMetadataLoad).toHaveBeenCalledTimes(1);
    expect(loaderComplete).toHaveBeenCalledWith({
      message: 'Application ready!',
      delay: 420,
    });

    expect(initializeSimpleUsername).toHaveBeenCalledTimes(1);
    expect(randomizeUserIdentity).toHaveBeenCalledTimes(1);
    expect(randomizeChallenge).toHaveBeenCalledWith('reg');
    expect(randomizeChallenge).toHaveBeenCalledWith('auth');
    expect(randomizeLargeBlobWrite).toHaveBeenCalledTimes(1);
    expect(updateJsonEditor).toHaveBeenCalled();
    expect(updateAuthenticationExtensionAvailability).toHaveBeenCalled();
    expect(checkLargeBlobCapability).toHaveBeenCalled();

    document.getElementById('user-name').dispatchEvent(new Event('input', { bubbles: true }));
    expect(document.getElementById('user-display-name').value).toBe('alice');
    expect(updateJsonEditor).toHaveBeenCalled();

    document.getElementById('allow-credentials').dispatchEvent(new Event('change', { bubbles: true }));
    expect(updateAuthenticationExtensionAvailability).toHaveBeenCalled();

    document.getElementById('fake-cred-generate').dispatchEvent(new Event('click', { bubbles: true }));
    expect(createFakeExcludeCredential).toHaveBeenCalled();

    document.querySelector('#fake-cred-generated-list button').dispatchEvent(new MouseEvent('click', { bubbles: true }));
    expect(removeFakeExcludeCredential).toHaveBeenCalled();

    document.getElementById('fake-cred-generate-auth').dispatchEvent(new Event('click', { bubbles: true }));
    expect(createFakeAllowCredential).toHaveBeenCalled();

    document.querySelector('#fake-cred-auth-generated-list button').dispatchEvent(new MouseEvent('click', { bubbles: true }));
    expect(removeFakeAllowCredential).toHaveBeenCalled();

    document.getElementById('json-editor').dispatchEvent(new Event('click', { bubbles: true }));
    document.getElementById('json-editor').dispatchEvent(new Event('focus', { bubbles: true }));
    expect(toggleJsonEditorExpansion).toHaveBeenCalled();

    document.getElementById('json-editor').dispatchEvent(new KeyboardEvent('keydown', { key: 'A', bubbles: true }));
    expect(handleJsonEditorKeydown).toHaveBeenCalled();

    document.getElementById('json-editor-container').classList.add('expanded');
    document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true }));
    expect(toggleJsonEditorExpansion).toHaveBeenCalledWith(true);

    document.getElementById('json-editor-close').dispatchEvent(new Event('click', { bubbles: true }));
    expect(toggleJsonEditorExpansion).toHaveBeenCalledWith(true);

    document.getElementById('user-id').dispatchEvent(new Event('input', { bubbles: true }));
    document.getElementById('challenge-reg').dispatchEvent(new Event('blur', { bubbles: true }));
    document.getElementById('prf-eval-first-auth').dispatchEvent(new Event('change', { bubbles: true }));
    document.getElementById('large-blob-write').dispatchEvent(new Event('input', { bubbles: true }));

    expect(validateUserIdInput).toHaveBeenCalled();
    expect(validateChallengeInputs).toHaveBeenCalled();
    expect(validatePrfInputs).toHaveBeenCalled();
    expect(validatePrfEvalInputs).toHaveBeenCalled();
    expect(validateLargeBlobWriteInput).toHaveBeenCalled();

    document.getElementById('authenticator-attachment').dispatchEvent(new Event('change', { bubbles: true }));
    expect(updateAllowCredentialsDropdown).toHaveBeenCalled();

    document.getElementById('hint-client-device').dispatchEvent(new Event('change', { bubbles: true }));
    expect(updateAllowCredentialsDropdown).toHaveBeenCalled();

    const modal = document.getElementById('modal-a');
    modal.dispatchEvent(new MouseEvent('click', { bubbles: true }));
    expect(closeModal).toHaveBeenCalledWith('modal-a');

    expect(window.simpleRegister).toBeDefined();
    expect(window.advancedAuthenticate).toBeDefined();
    expect(window.clearDecoder).toBeDefined();
  });

  it('completes startup with limited metadata when metadata wait fails', async () => {
    waitForMetadataLoad.mockRejectedValueOnce(new Error('metadata failure'));

    await importMainFresh();
    document.dispatchEvent(new Event('DOMContentLoaded'));
    await vi.runAllTimersAsync();

    expect(loaderComplete).toHaveBeenCalledWith({
      message: 'Application ready with limited metadata.',
      delay: 420,
    });
  });

  it('falls back to partial startup when initialization throws', async () => {
    initializeNavigationMenu.mockImplementationOnce(() => {
      throw new Error('navigation bootstrap failed');
    });

    await importMainFresh();
    document.dispatchEvent(new Event('DOMContentLoaded'));
    await vi.runAllTimersAsync();

    expect(loaderSetPhase).toHaveBeenCalledWith('Opening workspace with limited startup…', { progress: 96 });
    expect(loaderComplete).toHaveBeenCalledWith({
      message: 'Application ready with partial startup.',
      delay: 420,
    });
  });

  it('handles deferred listener edge branches and mutation-driven spellcheck hardening', async () => {
    await importMainFresh();

    document.dispatchEvent(new Event('DOMContentLoaded'));
    await vi.runAllTimersAsync();

    const largeBlobAuth = document.getElementById('large-blob-auth');
    largeBlobAuth.dispatchEvent(new Event('change', { bubbles: true }));

    const credProtect = document.getElementById('cred-protect');
    const enforceCredProtect = document.getElementById('enforce-cred-protect');
    credProtect.value = 'required';
    credProtect.dispatchEvent(new Event('change', { bubbles: true }));
    expect(enforceCredProtect.disabled).toBe(false);

    const residentKey = document.getElementById('resident-key');
    const largeBlobReg = document.getElementById('large-blob-reg');
    residentKey.value = 'preferred';
    largeBlobReg.value = 'required';
    residentKey.dispatchEvent(new Event('change', { bubbles: true }));
    expect(largeBlobReg.value).toBe('');

    const removeExcludeBefore = removeFakeExcludeCredential.mock.calls.length;
    document.getElementById('fake-cred-generated-list').dispatchEvent(new MouseEvent('click', { bubbles: true }));
    expect(removeFakeExcludeCredential).toHaveBeenCalledTimes(removeExcludeBefore);

    const removeAllowBefore = removeFakeAllowCredential.mock.calls.length;
    document.getElementById('fake-cred-auth-generated-list').dispatchEvent(new MouseEvent('click', { bubbles: true }));
    expect(removeFakeAllowCredential).toHaveBeenCalledTimes(removeAllowBefore);

    document.getElementById('prf-eval-first-reg').dispatchEvent(new Event('input', { bubbles: true }));
    document.getElementById('prf-eval-first-auth').dispatchEvent(new Event('blur', { bubbles: true }));
    expect(validatePrfInputs).toHaveBeenCalled();
    expect(validatePrfEvalInputs).toHaveBeenCalled();

    const dynamicInput = document.createElement('input');
    dynamicInput.type = 'text';
    document.body.appendChild(dynamicInput);

    const editable = document.createElement('div');
    editable.contentEditable = 'true';
    document.body.appendChild(editable);

    const roleTextbox = document.createElement('div');
    roleTextbox.setAttribute('role', 'textbox');
    document.body.appendChild(roleTextbox);

    await Promise.resolve();
    await Promise.resolve();

    expect(dynamicInput.getAttribute('spellcheck')).toBe('false');
    expect(roleTextbox.getAttribute('spellcheck')).toBe('false');
  });
});
