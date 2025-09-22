import { state } from './state.js';
import {
    convertFormat,
    generateRandomHex,
    getCurrentBinaryFormat,
    base64ToHex,
    base64UrlToHexFixed,
    jsToHex
} from './binary-utils.js';
import { getStoredCredentialAttachment } from './credential-utils.js';
import { showStatus } from './status.js';
import { updateJsonEditor } from './json-editor.js';

export function changeBinaryFormat() {
    const newFormat = getCurrentBinaryFormat();
    const oldFormat = window.currentBinaryFormat || 'hex';

    const fieldIds = [
        'user-id', 'challenge-reg', 'challenge-auth',
        'prf-eval-first-reg', 'prf-eval-second-reg',
        'prf-eval-first-auth', 'prf-eval-second-auth',
        'large-blob-write'
    ];

    fieldIds.forEach(fieldId => {
        const input = document.getElementById(fieldId);
        if (input && input.value) {
            const convertedValue = convertFormat(input.value, oldFormat, newFormat);
            input.value = convertedValue;
        }
    });

    updateFieldLabels(newFormat);
    updateJsonEditor();
    window.currentBinaryFormat = newFormat;
}

export function updateFieldLabels(format) {
    const labelMappings = [
        { id: 'user-id', text: `User ID (${format})` },
        { id: 'challenge-reg', text: `Challenge (${format})` },
        { id: 'challenge-auth', text: `Challenge (${format})` },
        { id: 'prf-eval-first-reg', text: `prf eval first (${format})` },
        { id: 'prf-eval-second-reg', text: `prf eval second (${format})` },
        { id: 'prf-eval-first-auth', text: `prf eval first (${format})` },
        { id: 'prf-eval-second-auth', text: `prf eval second (${format})` },
        { id: 'large-blob-write', text: `largeBlob write (${format})` }
    ];

    labelMappings.forEach(mapping => {
        const input = document.getElementById(mapping.id);
        if (input) {
            const label = document.querySelector(`label[for="${mapping.id}"]`);
            if (label) {
                label.textContent = mapping.text;
            }
        }
    });
}

export function validateHexInput(inputId, errorId, minBytes = 0) {
    const input = document.getElementById(inputId);
    const error = document.getElementById(errorId);
    if (!input || !error) {
        return true;
    }
    const value = input.value.trim();
    const format = getCurrentBinaryFormat();

    if (!value) {
        error.style.display = 'none';
        input.classList.remove('error');
        return true;
    }

    let isValid = false;
    let hexValue = '';

    try {
        switch (format) {
            case 'hex':
                isValid = /^[0-9a-fA-F]+$/.test(value) && value.length >= minBytes * 2;
                hexValue = value;
                break;
            case 'b64':
                hexValue = base64ToHex(value);
                isValid = hexValue.length >= minBytes * 2;
                break;
            case 'b64u':
                hexValue = base64UrlToHexFixed(value);
                isValid = hexValue.length >= minBytes * 2;
                break;
            case 'js':
                hexValue = jsToHex(value);
                isValid = hexValue.length >= minBytes * 2;
                break;
        }
    } catch (e) {
        isValid = false;
    }

    if (!isValid) {
        error.style.display = 'block';
        input.classList.add('error');
        return false;
    } else {
        error.style.display = 'none';
        input.classList.remove('error');
        return true;
    }
}

export function randomizeUserId() {
    const userId = generateRandomHex(32);
    const format = getCurrentBinaryFormat();
    const formattedValue = convertFormat(userId, 'hex', format);
    const input = document.getElementById('user-id');
    if (input) {
        input.value = formattedValue;
    }
    updateJsonEditor();
}

export function randomizeChallenge(type) {
    const challenge = generateRandomHex(32);
    const format = getCurrentBinaryFormat();
    const formattedValue = convertFormat(challenge, 'hex', format);
    const input = document.getElementById('challenge-' + type);
    if (input) {
        input.value = formattedValue;
    }
    updateJsonEditor();
}

export function randomizePrfEval(evalType, formType) {
    const prfValue = generateRandomHex(32);
    const format = getCurrentBinaryFormat();
    const formattedValue = convertFormat(prfValue, 'hex', format);
    const input = document.getElementById('prf-eval-' + evalType + '-' + formType);
    if (input) {
        input.value = formattedValue;
    }

    if (evalType === 'first') {
        const secondInput = document.getElementById('prf-eval-second-' + formType);
        const secondButton = secondInput?.nextElementSibling;
        if (secondInput && secondButton) {
            if (formattedValue) {
                secondInput.disabled = false;
                secondButton.disabled = false;
            } else {
                secondInput.disabled = true;
                secondButton.disabled = true;
                secondInput.value = '';
            }
        }
    }

    updateJsonEditor();
}

export function randomizeLargeBlobWrite() {
    const blobValue = generateRandomHex(32);
    const format = getCurrentBinaryFormat();
    const formattedValue = convertFormat(blobValue, 'hex', format);
    const input = document.getElementById('large-blob-write');
    if (input) {
        input.value = formattedValue;
    }
    updateJsonEditor();
}

export function validatePrfInputs(formType) {
    const firstInput = document.getElementById('prf-eval-first-' + formType);
    const secondInput = document.getElementById('prf-eval-second-' + formType);
    const secondButton = secondInput?.nextElementSibling;

    if (!firstInput || !secondInput || !secondButton) {
        return;
    }

    if (firstInput.value.trim() === '') {
        secondInput.disabled = true;
        secondButton.disabled = true;
        secondInput.value = '';
    } else {
        secondInput.disabled = false;
        secondButton.disabled = false;
    }

    updateJsonEditor();
}

export function validateUserIdInput() {
    return validateHexInput('user-id', 'user-id-error', 1);
}

export function validateChallengeInputs() {
    let valid = true;
    const challengeRegInput = document.getElementById('challenge-reg');
    const challengeAuthInput = document.getElementById('challenge-auth');

    if (challengeRegInput) valid &= validateHexInput('challenge-reg', 'challenge-reg-error', 16);
    if (challengeAuthInput) valid &= validateHexInput('challenge-auth', 'challenge-auth-error', 16);

    return Boolean(valid);
}

export function validatePrfEvalInputs() {
    const prfInputs = [
        'prf-eval-first-reg',
        'prf-eval-second-reg',
        'prf-eval-first-auth',
        'prf-eval-second-auth'
    ];

    let valid = true;
    prfInputs.forEach(inputId => {
        const input = document.getElementById(inputId);
        if (input && !input.disabled && input.value.trim()) {
            valid &= validateHexInput(inputId, inputId + '-error', 32);
        }
    });

    return Boolean(valid);
}

export function validateLargeBlobWriteInput() {
    const input = document.getElementById('large-blob-write');
    if (input && !input.disabled && input.value.trim()) {
        return validateHexInput('large-blob-write', 'large-blob-write-error', 1);
    }
    return true;
}

export function validateLargeBlobDependency() {
    const largeBlobReg = document.getElementById('large-blob-reg')?.value;
    const residentKey = document.getElementById('resident-key')?.value;

    if (largeBlobReg && (largeBlobReg === 'preferred' || largeBlobReg === 'required')) {
        if (residentKey !== 'required') {
            showStatus('advanced', 'Resident key must be set to "Required" for largeBlob to be enabled. Please change the Resident Key setting to "Required" before proceeding.', 'error');
            return false;
        }
    }
    return true;
}

export function checkLargeBlobCapability() {
    let hasLargeBlobCapability = false;

    if (state.storedCredentials && state.storedCredentials.length > 0) {
        hasLargeBlobCapability = state.storedCredentials.some(cred => cred.largeBlob === true);
    }

    const largeBlobSelect = document.getElementById('large-blob-auth');
    const largeBlobWriteInput = document.getElementById('large-blob-write');
    const largeBlobWriteButton = largeBlobWriteInput?.nextElementSibling;
    const messageElement = document.getElementById('large-blob-capability-message');
    const readOption = largeBlobSelect?.querySelector('option[value="read"]');
    const writeOption = largeBlobSelect?.querySelector('option[value="write"]');

    if (hasLargeBlobCapability) {
        if (readOption) readOption.disabled = false;
        if (writeOption) writeOption.disabled = false;
        if (messageElement) messageElement.style.display = 'none';

        const currentValue = largeBlobSelect?.value;
        if (largeBlobWriteInput && largeBlobWriteButton) {
            if (currentValue === 'write') {
                largeBlobWriteInput.disabled = false;
                largeBlobWriteButton.disabled = false;
            } else {
                largeBlobWriteInput.disabled = true;
                largeBlobWriteButton.disabled = true;
            }
        }
    } else {
        if (readOption) readOption.disabled = true;
        if (writeOption) writeOption.disabled = true;
        if (largeBlobWriteInput) largeBlobWriteInput.disabled = true;
        if (largeBlobWriteButton) largeBlobWriteButton.disabled = true;
        if (messageElement) messageElement.style.display = 'block';

        if (largeBlobSelect) largeBlobSelect.value = '';
    }
}
