import {
    randomizeChallenge,
    validatePrfInputs,
    updateAuthenticationExtensionAvailability
} from '../auth/forms.js';
import { randomizeUserIdentity } from '../../shared/auth/username.js';
import { rebuildJsonEditor } from '../editor/index.js';
import { clearFakeExcludeCredentials, clearFakeAllowCredentials } from '../auth/exclude-credentials.js';
import { updateAllowCredentialsDropdown } from '../credentials/index.js';
import { bindActions, callWith } from '../../shared/ui/actions.js';
import { HINT_VALUES } from '../auth/hint-rules.js';
import { ALGORITHM_OPTIONS } from '../json-editor/algorithm-options.js';
import { registrationDefaults } from '../json-editor/registration-request.js';
import { authenticationDefaults } from '../json-editor/authentication-request.js';

export function resetRegistrationForm() {
    randomizeUserIdentity();
    const defaults = registrationDefaults();

    document.getElementById('authenticator-attachment').value = defaults.attachment;
    document.getElementById('resident-key').value = defaults.residentKey;
    document.getElementById('user-verification-reg').value = defaults.userVerification;
    document.getElementById('attestation').value = defaults.attestation;
    document.getElementById('exclude-credentials').checked = defaults.excludeCredentials;
    document.getElementById('fake-cred-length-reg').value = defaults.fakeCredLength;

    randomizeChallenge('reg');
    document.getElementById('timeout-reg').value = defaults.timeout;
    // A page may leave the ML-DSA checkboxes out.
    ALGORITHM_OPTIONS.forEach(({ key, alg, pqc }) => {
        const checkbox = document.getElementById(`param-${key}`);
        if (checkbox || !pqc) {
            checkbox.checked = defaults.algorithms.includes(alg);
        }
    });
    HINT_VALUES.forEach(hint => {
        document.getElementById(`hint-${hint}`).checked = defaults.hints.includes(hint);
    });

    document.getElementById('cred-props').checked = defaults.credProps;
    document.getElementById('min-pin-length').checked = defaults.minPinLength;
    document.getElementById('cred-protect').value = defaults.credProtect;
    document.getElementById('enforce-cred-protect').checked = defaults.enforceCredProtect;
    document.getElementById('enforce-cred-protect').disabled = true;
    document.getElementById('large-blob-reg').value = defaults.largeBlob;
    document.getElementById('prf-reg').checked = defaults.prf;
    document.getElementById('prf-eval-first-reg').value = defaults.prfFirst;
    document.getElementById('prf-eval-second-reg').value = defaults.prfSecond;
    document.getElementById('prf-eval-second-reg').disabled = true;

    clearFakeExcludeCredentials();

    updateAllowCredentialsDropdown();
    rebuildJsonEditor();
}

export function resetAuthenticationForm() {
    const defaults = authenticationDefaults();
    document.getElementById('user-verification-auth').value = defaults.userVerification;
    document.getElementById('allow-credentials').value = defaults.allowCredentials;
    document.getElementById('fake-cred-length-auth').value = defaults.fakeCredLength;

    randomizeChallenge('auth');
    document.getElementById('timeout-auth').value = defaults.timeout;
    HINT_VALUES.forEach(hint => {
        document.getElementById(`hint-${hint}-auth`).checked = defaults.hints.includes(hint);
    });

    ['param-mldsa44', 'param-mldsa65', 'param-mldsa87'].forEach(id => {
        const checkbox = document.getElementById(id);
        if (checkbox) {
            checkbox.checked = true;
        }
    });

    document.getElementById('large-blob-auth').value = defaults.largeBlob;
    document.getElementById('large-blob-write').value = defaults.largeBlobWrite;
    document.getElementById('large-blob-write').disabled = true;
    document.getElementById('prf-eval-first-auth').value = defaults.prfFirst;
    document.getElementById('prf-eval-second-auth').value = defaults.prfSecond;
    document.getElementById('prf-eval-second-auth').disabled = true;

    clearFakeAllowCredentials();

    validatePrfInputs('reg');
    validatePrfInputs('auth');
    updateAuthenticationExtensionAvailability();
    rebuildJsonEditor();
}

export const resetActions = {
    'reset-registration-form': callWith(resetRegistrationForm),
    'reset-authentication-form': callWith(resetAuthenticationForm),
};

export function bindResetActions() {
    return bindActions(document.getElementById('advanced-tab'), resetActions);
}
