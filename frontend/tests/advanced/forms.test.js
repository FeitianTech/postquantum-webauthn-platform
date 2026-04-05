import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../static/scripts/advanced/json-editor.js', () => ({
  updateJsonEditor: vi.fn(),
}));

vi.mock('../../static/scripts/shared/status.js', () => ({
  showStatus: vi.fn(),
}));

import { state } from '../../static/scripts/shared/state.js';
import { updateJsonEditor } from '../../static/scripts/advanced/json-editor.js';

async function loadFormsModule() {
  return import('../../static/scripts/advanced/forms.js');
}

async function loadFormsModuleWithBinaryOverrides(overrides = {}) {
  vi.resetModules();
  vi.doMock('../../static/scripts/shared/binary-utils.js', async () => {
    const actual = await vi.importActual('../../static/scripts/shared/binary-utils.js');
    return {
      ...actual,
      ...overrides,
    };
  });

  const module = await import('../../static/scripts/advanced/forms.js');
  vi.doUnmock('../../static/scripts/shared/binary-utils.js');
  return module;
}

function buildFormDom() {
  document.body.innerHTML = `
    <label for="user-id">User ID</label>
    <input id="user-id" />
    <div id="user-id-error"></div>
    <label for="challenge-reg">Challenge</label>
    <input id="challenge-reg" />
    <div id="challenge-reg-error"></div>
    <label for="challenge-auth">Challenge</label>
    <input id="challenge-auth" />
    <div id="challenge-auth-error"></div>
    <label for="prf-eval-first-auth">prf</label>
    <input id="prf-eval-first-auth" /><button></button>
    <div id="prf-eval-first-auth-error"></div>
    <input id="prf-eval-second-auth" /><button></button>
    <div id="prf-eval-second-auth-error"></div>
    <input id="prf-eval-first-reg" /><button></button>
    <div id="prf-eval-first-reg-error"></div>
    <input id="prf-eval-second-reg" /><button></button>
    <div id="prf-eval-second-reg-error"></div>
    <label for="large-blob-write">Blob</label>
    <input id="large-blob-write" /><button></button>
    <div id="large-blob-write-error"></div>
    <select id="large-blob-auth">
      <option value=""></option>
      <option value="read">read</option>
      <option value="write">write</option>
    </select>
    <div id="large-blob-capability-message"></div>
    <div id="prf-capability-message"></div>
    <select id="allow-credentials">
      <option value="all">all</option>
      <option value="414243">credential</option>
    </select>
  `;
}

describe('forms', () => {
  beforeEach(() => {
    buildFormDom();
    state.storedCredentials = [];
  });

  it('updates labels, validates input, and randomizes values', async () => {
    const {
      randomizeChallenge,
      randomizeLargeBlobWrite,
      randomizePrfEval,
      randomizeUserId,
      updateFieldLabels,
      validateChallengeInputs,
      validateHexInput,
      validateLargeBlobWriteInput,
      validatePrfEvalInputs,
      validatePrfInputs,
      validateUserIdInput,
    } = await loadFormsModule();

    updateFieldLabels();
    expect(document.querySelector('label[for="user-id"]').textContent).toContain('(hex)');

    document.getElementById('user-id').value = 'zz';
    expect(validateUserIdInput()).toBe(false);
    document.getElementById('user-id').value = 'aa';
    expect(validateUserIdInput()).toBe(true);

    document.getElementById('challenge-reg').value = 'aa';
    expect(validateChallengeInputs()).toBe(false);
    document.getElementById('challenge-reg').value = 'a'.repeat(32);
    document.getElementById('challenge-auth').value = 'b'.repeat(32);
    expect(validateChallengeInputs()).toBe(true);

    randomizeUserId();
    randomizeChallenge('reg');
    randomizePrfEval('first', 'auth');
    randomizeLargeBlobWrite();
    expect(updateJsonEditor).toHaveBeenCalled();

    document.getElementById('prf-eval-first-auth').value = 'a'.repeat(64);
    validatePrfInputs('auth');
    expect(document.getElementById('prf-eval-second-auth').disabled).toBe(false);
    expect(validatePrfEvalInputs()).toBe(true);
    expect(validateHexInput('large-blob-write', 'large-blob-write-error', 1)).toBe(true);
    expect(validateLargeBlobWriteInput()).toBe(true);
  });

  it('updates authentication extension availability from stored credentials', async () => {
    const {
      checkLargeBlobCapability,
      updateAuthenticationExtensionAvailability,
    } = await loadFormsModule();

    state.storedCredentials = [
      {
        credentialIdHex: '414243',
        largeBlobSupported: true,
        clientExtensionOutputs: { prf: { results: true } },
      },
    ];

    document.getElementById('large-blob-auth').value = 'write';
    updateAuthenticationExtensionAvailability();

    expect(document.getElementById('large-blob-auth').disabled).toBe(false);
    expect(document.getElementById('large-blob-write').disabled).toBe(false);
    expect(document.getElementById('prf-eval-first-auth').disabled).toBe(false);

    checkLargeBlobCapability({ selectedCredential: { largeBlobSupported: false } });
    expect(document.getElementById('large-blob-capability-message').textContent).toContain('Selected credential does not support largeBlob.');
  });

  it('resolves selected credential by id and disables unsupported auth extensions', async () => {
    const { updateAuthenticationExtensionAvailability } = await loadFormsModule();

    state.storedCredentials = [
      {
        credentialIdHex: '414243',
        largeBlobSupported: false,
        clientExtensionOutputs: {},
      },
    ];

    document.getElementById('allow-credentials').value = '414243';
    updateAuthenticationExtensionAvailability();

    expect(document.getElementById('large-blob-auth').disabled).toBe(true);
    expect(document.getElementById('prf-eval-first-auth').disabled).toBe(true);
    expect(document.getElementById('prf-capability-message').textContent).toContain('Selected credential does not support the prf extension.');
  });

  it('hides prf message when auth inputs are missing and reports no-credential support message', async () => {
    const { updateAuthenticationExtensionAvailability } = await loadFormsModule();

    document.getElementById('prf-eval-first-auth').remove();
    document.getElementById('prf-eval-second-auth').remove();

    state.storedCredentials = [];
    updateAuthenticationExtensionAvailability();

    expect(document.getElementById('prf-capability-message').style.display).toBe('none');
    expect(document.getElementById('large-blob-capability-message').textContent).toContain('No largeBlob capable credentials available');
  });

  it('shows no-prf-capability message when no credentials are available', async () => {
    const { updateAuthenticationExtensionAvailability } = await loadFormsModule();

    state.storedCredentials = [];
    document.getElementById('allow-credentials').value = 'all';

    updateAuthenticationExtensionAvailability();

    expect(document.getElementById('prf-capability-message').textContent).toContain('No credentials with prf support available.');
    expect(document.getElementById('prf-eval-first-auth').disabled).toBe(true);
  });

  it('shows no-prf-capability message when stored credentials exist but none support prf', async () => {
    const { updateAuthenticationExtensionAvailability } = await loadFormsModule();

    state.storedCredentials = [
      {
        credentialIdHex: 'aa11',
        largeBlobSupported: true,
        clientExtensionOutputs: {},
      },
    ];
    document.getElementById('allow-credentials').value = 'all';

    updateAuthenticationExtensionAvailability();

    expect(document.getElementById('prf-capability-message').textContent).toContain('No credentials with prf support available.');
    expect(document.getElementById('prf-eval-first-auth').disabled).toBe(true);
  });

  it('validates alternate binary formats, malformed values, and missing controls safely', async () => {
    const { validateHexInput, validateLargeBlobWriteInput, validatePrfInputs } = await loadFormsModule();

    window.__binaryFormat = 'b64';
    document.getElementById('user-id').value = 'QQ==';
    expect(validateHexInput('user-id', 'user-id-error', 1)).toBe(true);

    window.__binaryFormat = 'b64u';
    document.getElementById('user-id').value = 'QQ';
    expect(validateHexInput('user-id', 'user-id-error', 1)).toBe(true);

    window.__binaryFormat = 'js';
    document.getElementById('user-id').value = 'new Uint8Array([65, 66])';
    expect(validateHexInput('user-id', 'user-id-error', 1)).toBe(true);

    window.__binaryFormat = 'b64';
    document.getElementById('user-id').value = '@@@@';
    expect(validateHexInput('user-id', 'user-id-error', 1)).toBe(false);

    expect(validateHexInput('missing-input', 'missing-error', 1)).toBe(true);

    document.getElementById('prf-eval-first-auth').remove();
    document.getElementById('prf-eval-second-auth').remove();
    expect(validatePrfInputs('auth')).toBeUndefined();

    const largeBlobInput = document.getElementById('large-blob-write');
    largeBlobInput.disabled = true;
    largeBlobInput.value = '';
    expect(validateLargeBlobWriteInput()).toBe(true);

    delete window.__binaryFormat;
  });

  it('evaluates largeBlob/prf capability across object, scalar, and property-backed credential payloads', async () => {
    const { checkLargeBlobCapability, updateAuthenticationExtensionAvailability } = await loadFormsModule();

    state.storedCredentials = [null];
    checkLargeBlobCapability();
    expect(document.getElementById('large-blob-capability-message').textContent).toContain(
      'No largeBlob capable credentials available',
    );

    document.getElementById('large-blob-auth').value = 'write';
    checkLargeBlobCapability({ selectedCredential: { clientExtensionOutputs: { largeBlob: { supported: true } } } });
    expect(document.getElementById('large-blob-auth').disabled).toBe(false);
    expect(document.getElementById('large-blob-write').disabled).toBe(false);

    checkLargeBlobCapability({ selectedCredential: { clientExtensionOutputs: { largeBlob: 'present' } } });
    expect(document.getElementById('large-blob-auth').disabled).toBe(false);

    checkLargeBlobCapability({ selectedCredential: { properties: { largeBlob: true } } });
    expect(document.getElementById('large-blob-auth').disabled).toBe(false);

    const allowSelect = document.getElementById('allow-credentials');
    allowSelect.value = '414243';

    state.storedCredentials = [{ credentialIdHex: '414243', clientExtensionOutputs: { prf: { custom: true } } }];
    updateAuthenticationExtensionAvailability();
    expect(document.getElementById('prf-eval-first-auth').disabled).toBe(false);

    state.storedCredentials = [{ credentialIdHex: '414243', clientExtensionOutputs: { prf: 'supported' } }];
    updateAuthenticationExtensionAvailability();
    expect(document.getElementById('prf-eval-first-auth').disabled).toBe(false);

    state.storedCredentials = [{ credentialIdHex: '414243', properties: { prf: true } }];
    updateAuthenticationExtensionAvailability();
    expect(document.getElementById('prf-eval-first-auth').disabled).toBe(false);
  });

  it('disables secondary PRF inputs when formatted random output is empty', async () => {
    const { randomizePrfEval } = await loadFormsModuleWithBinaryOverrides({
      convertFormat: vi.fn(() => ''),
      generateRandomHex: vi.fn(() => 'aa'),
    });

    const secondInput = document.getElementById('prf-eval-second-auth');
    const secondButton = secondInput.nextElementSibling;
    secondInput.value = 'deadbeef';
    secondInput.disabled = false;
    secondButton.disabled = false;

    randomizePrfEval('first', 'auth');

    expect(secondInput.disabled).toBe(true);
    expect(secondButton.disabled).toBe(true);
    expect(secondInput.value).toBe('');
  });
});
