import { state } from '../../shared/state.js';
import { generateRandomHex, convertFormat, getCurrentBinaryFormat } from '../../shared/utils/binary.js';
import { showStatus } from '../../shared/ui/status.js';
import {
    FAKE_CREDENTIAL_TEXT,
    fakeCredentialLength,
    fakeCredentialSize,
    normaliseFakeCredentialList,
    withoutFakeCredential,
} from './fake-credentials.js';

const LIST_CONFIG = {
    exclude: {
        stateKey: 'generatedExcludeCredentials',
        containerId: 'fake-cred-generated-list',
        emptyMessage: FAKE_CREDENTIAL_TEXT.noExclude,
    },
    allow: {
        stateKey: 'generatedAllowCredentials',
        containerId: 'fake-cred-auth-generated-list',
        emptyMessage: FAKE_CREDENTIAL_TEXT.noAllow,
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
    container.replaceChildren();

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
        meta.textContent = fakeCredentialSize(hex);
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
    list.splice(0, list.length, ...normaliseFakeCredentialList(hexList));
    renderFakeCredentialList(type);
}

function clearFakeCredentials(type = 'exclude') {
    setFakeCredentials(type, []);
}

function createFakeCredential(type = 'exclude', length) {
    const { bytes, error, notice } = fakeCredentialLength(length);
    if (error) {
        showStatus('advanced', error, 'error');
        return null;
    }
    if (notice) {
        showStatus('advanced', notice, 'info');
    }

    const hexValue = generateRandomHex(bytes);
    const list = ensureList(type);
    list.push(hexValue);
    renderFakeCredentialList(type);
    return hexValue;
}

function removeFakeCredential(type = 'exclude', index) {
    const list = ensureList(type);
    const remaining = withoutFakeCredential(list, index);
    if (!remaining) {
        return false;
    }
    list.splice(0, list.length, ...remaining);
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

export function setFakeAllowCredentials(hexList) {
    setFakeCredentials('allow', hexList);
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
