export const registrationDetailState = {
    attestationObject: null,
    attestationCertificates: [],
    visibleAttestationCertificateIndices: [],
    authenticatorData: null,
    authenticatorDataHash: '',
    authenticatorDataHex: '',
};

let globalCursorApplyCount = 0;
let globalCursorPreviousValues = [];
let pendingCredentialFlash = null;
let credentialBackgroundWarmupPromise = null;
let credentialDeletionInProgress = false;

export function getGlobalCursorApplyCount() {
    return globalCursorApplyCount;
}

export function setGlobalCursorApplyCount(value) {
    globalCursorApplyCount = Number.isFinite(value) ? value : 0;
}

export function getGlobalCursorPreviousValues() {
    return globalCursorPreviousValues;
}

export function setGlobalCursorPreviousValues(value) {
    globalCursorPreviousValues = Array.isArray(value) ? value : [];
}

export function getPendingCredentialFlash() {
    return pendingCredentialFlash;
}

export function setPendingCredentialFlash(value) {
    pendingCredentialFlash = value || null;
}

export function clearPendingCredentialFlash() {
    pendingCredentialFlash = null;
}

export function getCredentialBackgroundWarmupPromise() {
    return credentialBackgroundWarmupPromise;
}

export function setCredentialBackgroundWarmupPromise(value) {
    credentialBackgroundWarmupPromise = value || null;
}

export function isCredentialDeletionInProgress() {
    return credentialDeletionInProgress;
}

export function setCredentialDeletionInProgressFlag(value) {
    credentialDeletionInProgress = Boolean(value);
}

export function resetRegistrationDetailState() {
    registrationDetailState.attestationObject = null;
    registrationDetailState.attestationCertificates = [];
    registrationDetailState.visibleAttestationCertificateIndices = [];
    registrationDetailState.authenticatorData = null;
    registrationDetailState.authenticatorDataHash = '';
    registrationDetailState.authenticatorDataHex = '';
}
