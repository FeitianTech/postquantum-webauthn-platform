import { state } from '../../shared/state.js';
import {
    collectSelectedHints,
    enforceAuthenticatorAttachmentWithHints,
} from '../auth/hints.js';
import { getFakeExcludeCredentials } from '../auth/exclude-credentials.js';
import { appendSelectedAlgorithmParams } from './algorithms.js';
import { buildCreationOptions } from './registration-request.js';

const RP_NAME = 'FIDO2/WebAuthn PQC Developer Tools';

/** The registration form's settings as its fields hold them (./registration-request.js). */
export function readRegistrationForm() {
    const valueOf = id => document.getElementById(id)?.value || '';
    const checked = id => Boolean(document.getElementById(id)?.checked);
    const params = [];
    appendSelectedAlgorithmParams(params);
    return {
        userId: valueOf('user-id'),
        userName: valueOf('user-name'),
        displayName: valueOf('user-display-name'),
        challenge: valueOf('challenge-reg'),
        timeout: valueOf('timeout-reg'),
        attachment: valueOf('authenticator-attachment'),
        residentKey: valueOf('resident-key'),
        userVerification: valueOf('user-verification-reg'),
        attestation: valueOf('attestation'),
        excludeCredentials: checked('exclude-credentials'),
        fakeCredLength: valueOf('fake-cred-length-reg'),
        algorithms: params.map(param => param.alg),
        hints: collectSelectedHints('registration'),
        credProps: checked('cred-props'),
        minPinLength: checked('min-pin-length'),
        credProtect: valueOf('cred-protect'),
        enforceCredProtect: checked('enforce-cred-protect'),
        largeBlob: valueOf('large-blob-reg'),
        prf: checked('prf-reg'),
        prfFirst: valueOf('prf-eval-first-reg'),
        prfSecond: valueOf('prf-eval-second-reg'),
    };
}

export function getCredentialCreationOptions() {
    const settings = readRegistrationForm();
    const options = buildCreationOptions(settings, {
        rpName: RP_NAME,
        hostname: window.location.hostname,
        storedCredentials: state.storedCredentials,
        fakeExcludeCredentials: settings.excludeCredentials ? getFakeExcludeCredentials() : [],
    });

    enforceAuthenticatorAttachmentWithHints(options.publicKey);

    return options;
}
