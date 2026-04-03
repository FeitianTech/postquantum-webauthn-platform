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
});
