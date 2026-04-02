import { state } from '../shared/state.js';
import { generateRandomHex, convertFormat, getCurrentBinaryFormat } from '../shared/binary-utils.js';
import { showStatus } from '../shared/status.js';

const LIST_CONFIG = {
    exclude: {
        stateKey: 'generatedExcludeCredentials',
        containerId: 'fake-cred-generated-list',
        emptyMessage: 'No fake credential IDs added.',
    },
    allow: {
        stateKey: 'generatedAllowCredentials',
        containerId: 'fake-cred-auth-generated-list',
        emptyMessage: 'No fake allow credential IDs added.',
    },
};

function getConfig(type = 'exclude') {
    return LIST_CONFIG[type] || LIST_CONFIG.exclude;
}

function ensureList(type = 'exclude') {
    const config = getConfig(type);
    const current = state[config.stateKey];
    if (!Array.isArray(current)) {
        state[config.stateKey] = [];
    }
    return state[config.stateKey];
}

function normaliseHex(value) {
    if (typeof value !== 'string') {
        return '';
    }
    const trimmed = value.trim();
    if (!trimmed) {
        return '';
    }
    return trimmed.replace(/[^0-9a-fA-F]/g, '').toLowerCase();
}

function getListContainer(type = 'exclude') {
    const { containerId } = getConfig(type);
    return document.getElementById(containerId);
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

function renderFakeCredentialList(type = 'exclude') {
    const container = getListContainer(type);
    if (!container) {
        return;
    }

    const list = ensureList(type);
    container.innerHTML = '';

    if (!list.length) {
        const empty = document.createElement('div');
        empty.className = 'fake-credential-empty';
        empty.textContent = getConfig(type).emptyMessage;
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

function getFakeCredentials(type = 'exclude') {
    return ensureList(type).slice();
}

function setFakeCredentials(type = 'exclude', hexList = []) {
    const list = ensureList(type);
    list.splice(0, list.length);
    if (Array.isArray(hexList)) {
        hexList.forEach(value => {
            const normalised = normaliseHex(value);
            if (normalised) {
                list.push(normalised);
            }
        });
    }
    renderFakeCredentialList(type);
}

function clearFakeCredentials(type = 'exclude') {
    setFakeCredentials(type, []);
}

function createFakeCredential(type = 'exclude', length) {
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
    const list = ensureList(type);
    list.push(hexValue);
    renderFakeCredentialList(type);
    return hexValue;
}

function removeFakeCredential(type = 'exclude', index) {
    const list = ensureList(type);
    const parsed = Number.parseInt(index, 10);
    if (!Number.isInteger(parsed) || parsed < 0 || parsed >= list.length) {
        return false;
    }
    list.splice(parsed, 1);
    renderFakeCredentialList(type);
    return true;
}

export function renderFakeExcludeCredentialList() {
    renderFakeCredentialList('exclude');
}

export function renderFakeAllowCredentialList() {
    renderFakeCredentialList('allow');
}

export function getFakeExcludeCredentials() {
    return getFakeCredentials('exclude');
}

export function getFakeAllowCredentials() {
    return getFakeCredentials('allow');
}

export function setFakeExcludeCredentials(hexList) {
    setFakeCredentials('exclude', hexList);
}

export function clearFakeExcludeCredentials() {
    clearFakeCredentials('exclude');
}

export function clearFakeAllowCredentials() {
    clearFakeCredentials('allow');
}

export function createFakeExcludeCredential(length) {
    return createFakeCredential('exclude', length);
}

export function createFakeAllowCredential(length) {
    return createFakeCredential('allow', length);
}

export function removeFakeExcludeCredential(index) {
    return removeFakeCredential('exclude', index);
}

export function removeFakeAllowCredential(index) {
    return removeFakeCredential('allow', index);
}
