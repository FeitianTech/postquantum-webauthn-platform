import {hideProgress, showProgress, showStatus} from '../../shared/status.js';

const SHARED_CREDENTIAL_STATUS_TABS = ['advanced', 'simple'];

export function showSharedCredentialStatus(message, type) {
    SHARED_CREDENTIAL_STATUS_TABS.forEach(tabId => {
        showStatus(tabId, message, type);
    });
}

export function showSharedCredentialProgress(message) {
    SHARED_CREDENTIAL_STATUS_TABS.forEach(tabId => {
        showProgress(tabId, message);
    });
}

export function hideSharedCredentialProgress() {
    SHARED_CREDENTIAL_STATUS_TABS.forEach(tabId => {
        hideProgress(tabId);
    });
}
