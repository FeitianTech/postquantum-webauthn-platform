import {
    randomizeChallenge,
    validatePrfInputs,
    updateAuthenticationExtensionAvailability
} from './forms.js';
import { randomizeUserIdentity } from './username.js';
import { updateJsonEditor } from './json-editor.js';
import { clearFakeExcludeCredentials, clearFakeAllowCredentials } from './exclude-credentials.js';

export function resetRegistrationForm() {
    randomizeUserIdentity();

    document.getElementById('authenticator-attachment').value = 'cross-platform';
    document.getElementById('resident-key').value = 'discouraged';
    document.getElementById('user-verification-reg').value = 'preferred';
    document.getElementById('attestation').value = 'direct';
    document.getElementById('exclude-credentials').checked = true;
    document.getElementById('fake-cred-length-reg').value = '128';

    randomizeChallenge('reg');
    document.getElementById('timeout-reg').value = '90000';
    document.getElementById('param-eddsa').checked = true;
    document.getElementById('param-es256').checked = true;
    document.getElementById('param-rs256').checked = true;
    document.getElementById('param-es384').checked = false;
    document.getElementById('param-es512').checked = false;
    document.getElementById('param-rs384').checked = false;
    document.getElementById('param-rs512').checked = false;
    document.getElementById('param-rs1').checked = false;
    if (document.getElementById('param-mldsa44')) document.getElementById('param-mldsa44').checked = false;
    if (document.getElementById('param-mldsa65')) document.getElementById('param-mldsa65').checked = false;
    if (document.getElementById('param-mldsa87')) document.getElementById('param-mldsa87').checked = false;
    document.getElementById('hint-client-device').checked = false;
    document.getElementById('hint-hybrid').checked = false;
    document.getElementById('hint-security-key').checked = false;

    document.getElementById('cred-props').checked = true;
    document.getElementById('min-pin-length').checked = false;
    document.getElementById('cred-protect').value = '';
    document.getElementById('enforce-cred-protect').checked = true;
    document.getElementById('enforce-cred-protect').disabled = true;
    document.getElementById('large-blob-reg').value = '';
    document.getElementById('prf-reg').checked = false;
    document.getElementById('prf-eval-first-reg').value = '';
    document.getElementById('prf-eval-second-reg').value = '';
    document.getElementById('prf-eval-second-reg').disabled = true;

    clearFakeExcludeCredentials();

    updateJsonEditor();
}

export function resetAuthenticationForm() {
    document.getElementById('user-verification-auth').value = 'preferred';
    document.getElementById('allow-credentials').value = 'all';
    document.getElementById('fake-cred-length-auth').value = '256';

    randomizeChallenge('auth');
    document.getElementById('timeout-auth').value = '90000';
    document.getElementById('hint-client-device-auth').checked = false;
    document.getElementById('hint-hybrid-auth').checked = false;
    document.getElementById('hint-security-key-auth').checked = false;

    document.getElementById('large-blob-auth').value = '';
    document.getElementById('large-blob-write').value = '';
    document.getElementById('large-blob-write').disabled = true;
    document.getElementById('prf-eval-first-auth').value = '';
    document.getElementById('prf-eval-second-auth').value = '';
    document.getElementById('prf-eval-second-auth').disabled = true;

    clearFakeAllowCredentials();

    validatePrfInputs('reg');
    validatePrfInputs('auth');
    updateAuthenticationExtensionAvailability();
    updateJsonEditor();
}
