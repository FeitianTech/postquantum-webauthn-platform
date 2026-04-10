import {normalizeToHex} from '../../shared/utils/binary.js';
import {
    clearPendingCredentialFlash,
    getPendingCredentialFlash,
    setPendingCredentialFlash,
} from './state.js';

const CREDENTIAL_FLASH_CLASS_BY_VARIANT = {
    success: 'credential-item--recent-auth-success',
    failure: 'credential-item--recent-auth-failure',
};

function normaliseCredentialIdToHex(credentialId) {
    if (typeof credentialId !== 'string') {
        return '';
    }
    const normalized = normalizeToHex(credentialId.trim());
    return normalized ? normalized.toLowerCase() : '';
}

export function queueAuthenticatedCredentialFlash(credentialId) {
    const credentialHex = normaliseCredentialIdToHex(credentialId);
    setPendingCredentialFlash(credentialHex
        ? { credentialHex, variant: 'success' }
        : null);
}

export function queueFailedCredentialFlash(credentialId) {
    const credentialHex = normaliseCredentialIdToHex(credentialId);
    setPendingCredentialFlash(credentialHex
        ? { credentialHex, variant: 'failure' }
        : null);
}

function getVisibleCredentialLists() {
    return Array.from(document.querySelectorAll('[data-credentials-list]')).filter(list => {
        const tabContent = list.closest('.tab-content');
        return !(tabContent instanceof HTMLElement) || tabContent.classList.contains('active');
    });
}

function playCredentialFlash(element, variant) {
    if (!(element instanceof HTMLElement)) {
        return;
    }

    const flashClass = CREDENTIAL_FLASH_CLASS_BY_VARIANT[variant] || CREDENTIAL_FLASH_CLASS_BY_VARIANT.success;
    const allFlashClasses = Object.values(CREDENTIAL_FLASH_CLASS_BY_VARIANT);
    allFlashClasses.forEach(className => element.classList.remove(className));

    void element.offsetWidth;
    element.classList.add(flashClass);

    let cleanupTimer = null;
    const cleanup = () => {
        if (cleanupTimer !== null) {
            window.clearTimeout(cleanupTimer);
            cleanupTimer = null;
        }
        element.classList.remove(flashClass);
        element.removeEventListener('animationend', cleanup);
    };

    element.addEventListener('animationend', cleanup);
    cleanupTimer = window.setTimeout(cleanup, 2200);
}

export function triggerCredentialFlash(flashRequest) {
    if (!flashRequest || !flashRequest.credentialHex) {
        return;
    }

    const selector = `.credential-item[data-credential-id="${flashRequest.credentialHex}"]`;
    getVisibleCredentialLists().forEach(list => {
        list.querySelectorAll(selector).forEach(item => playCredentialFlash(item, flashRequest.variant));
    });
}

export function readPendingCredentialFlash() {
    return getPendingCredentialFlash();
}

export function clearCredentialFlashQueue() {
    clearPendingCredentialFlash();
}
