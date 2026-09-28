import { state } from '../../shared/state.js';
import { collectSelectedHints } from '../auth/hints.js';
import { getFakeAllowCredentials } from '../auth/exclude-credentials.js';
import { buildRequestOptions } from './authentication-request.js';

/** The authentication form's settings as its fields hold them (./authentication-request.js). */
export function readAuthenticationForm() {
    const valueOf = id => document.getElementById(id)?.value || '';
    return {
        userVerification: valueOf('user-verification-auth'),
        allowCredentials: valueOf('allow-credentials'),
        fakeCredLength: valueOf('fake-cred-length-auth'),
        challenge: valueOf('challenge-auth'),
        timeout: valueOf('timeout-auth'),
        hints: collectSelectedHints('authentication'),
        hashAlgorithm: valueOf('hash-algorithm-auth'),
        largeBlob: valueOf('large-blob-auth'),
        largeBlobWrite: valueOf('large-blob-write'),
        prfFirst: valueOf('prf-eval-first-auth'),
        prfSecond: valueOf('prf-eval-second-auth'),
    };
}

export function getCredentialRequestOptions() {
    return buildRequestOptions(readAuthenticationForm(), {
        hostname: window.location.hostname,
        storedCredentials: state.storedCredentials,
        fakeAllowCredentials: getFakeAllowCredentials(),
    });
}
