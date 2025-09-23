import { state } from './state.js';
import { generateRandomHex, convertFormat, getCurrentBinaryFormat } from './binary-utils.js';
import { showStatus } from './status.js';

function ensureList() {
    if (!Array.isArray(state.generatedExcludeCredentials)) {
        state.generatedExcludeCredentials = [];
    }
    return state.generatedExcludeCredentials;
}

function normaliseHex(value) {
    if (typeof value !== 'string') {
        return '';
    }
    const trimmed = value.trim();
    if (!trimmed) {
        return '';
    }
    const hex = trimmed.replace(/[^0-9a-fA-F]/g, '').toLowerCase();
    return hex;
}

function getListContainer() {
    return document.getElementById('fake-cred-generated-list');
}

function formatDisplayValue(hexValue) {
    const format = getCurrentBinaryFormat();
    try {
        if (format === 'hex') {
            return hexValue;
        }
        return convertFormat(hexValue, 'hex', format);
    } catch (error) {
        return hexValue;
    }
}

export function renderFakeExcludeCredentialList() {
    const container = getListContainer();
    if (!container) {
        return;
    }

    const list = ensureList();
    container.innerHTML = '';

    if (!list.length) {
        const empty = document.createElement('div');
        empty.className = 'fake-credential-empty';
        empty.textContent = 'No fake credential IDs added.';
        container.appendChild(empty);
        container.scrollTop = 0;
        container.scrollLeft = 0;
        return;
    }

    list.forEach((hex, index) => {
        if (typeof hex !== 'string' || !hex) {
            return;
        }
        const item = document.createElement('div');
        item.className = 'fake-credential-item';

        const value = document.createElement('code');
        value.className = 'fake-credential-value';
        value.textContent = formatDisplayValue(hex);
        item.appendChild(value);

        const footer = document.createElement('div');
        footer.className = 'fake-credential-footer';

        const meta = document.createElement('div');
        meta.className = 'fake-credential-meta';
        meta.textContent = `${Math.floor(hex.length / 2)} bytes`;
        footer.appendChild(meta);

        const actions = document.createElement('div');
        actions.className = 'fake-credential-actions';

        const removeButton = document.createElement('button');
        removeButton.type = 'button';
        removeButton.className = 'btn btn-small btn-danger fake-credential-delete';
        removeButton.dataset.fakeCredentialIndex = String(index);
        removeButton.textContent = 'Delete';
        actions.appendChild(removeButton);

        footer.appendChild(actions);
        item.appendChild(footer);
        container.appendChild(item);
    });

    container.scrollTop = 0;
    container.scrollLeft = 0;
}

export function getFakeExcludeCredentials() {
    return ensureList().slice();
}

export function setFakeExcludeCredentials(hexList) {
    const list = ensureList();
    list.splice(0, list.length);
    if (Array.isArray(hexList)) {
        hexList.forEach(value => {
            const normalised = normaliseHex(value);
            if (normalised) {
                list.push(normalised);
            }
        });
    }
    renderFakeExcludeCredentialList();
}

export function clearFakeExcludeCredentials() {
    setFakeExcludeCredentials([]);
}

export function createFakeExcludeCredential(length) {
    const parsed = Number.parseInt(length, 10);
    if (!Number.isFinite(parsed) || parsed <= 0) {
        showStatus('advanced', 'Please enter a valid fake credential ID length (at least 1 byte).', 'error');
        return null;
    }

    const safeLength = Math.min(parsed, 4096);
    if (parsed !== safeLength) {
        showStatus('advanced', 'Credential IDs are limited to 4096 bytes. Generated value truncated to maximum length.', 'info');
    }

    const hexValue = generateRandomHex(safeLength);
    const list = ensureList();
    list.push(hexValue);
    renderFakeExcludeCredentialList();
    return hexValue;
}

export function removeFakeExcludeCredential(index) {
    const list = ensureList();
    const parsed = Number.parseInt(index, 10);
    if (!Number.isInteger(parsed) || parsed < 0 || parsed >= list.length) {
        return false;
    }
    list.splice(parsed, 1);
    renderFakeExcludeCredentialList();
    return true;
}
