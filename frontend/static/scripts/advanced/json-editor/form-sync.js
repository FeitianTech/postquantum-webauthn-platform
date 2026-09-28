import { state } from '../../shared/state.js';
import { applyHintsToCheckboxes } from '../auth/hints.js';
import { setFakeExcludeCredentials } from '../auth/exclude-credentials.js';
import {
    applyRegistrationAlgorithmSelection,
    clearRegistrationAlgorithmCheckboxesForFormSync,
} from './algorithms.js';
import { dispatchChangeEvent } from './dom-helpers.js';
import { readRegistrationForm } from './creation-options.js';
import { readCreationOptions } from './registration-request.js';
import { readRequestOptions } from './authentication-request.js';
import { readAuthenticationForm } from './request-options.js';

// The registration form set to what the request says (./registration-request.js),
// in the order the fields were always written; Authenticator Attachment is
// announced as changed.
export function updateRegistrationFormFromJson(publicKey) {
    const { settings, fakeExcludeCredentials } = readCreationOptions(publicKey, readRegistrationForm(), {
        storedCredentials: state.storedCredentials,
    });
    const field = id => document.getElementById(id);
    const setValue = (id, value) => {
        if (field(id)) {
            field(id).value = value;
        }
    };
    const setChecked = (id, checked) => {
        if (field(id)) {
            field(id).checked = checked;
        }
    };

    setValue('user-id', settings.userId);
    setValue('user-name', settings.userName);
    setValue('user-display-name', settings.displayName);
    setValue('challenge-reg', settings.challenge);
    setValue('timeout-reg', settings.timeout);
    setValue('attestation', settings.attestation);

    if (Array.isArray(publicKey.pubKeyCredParams)) {
        clearRegistrationAlgorithmCheckboxesForFormSync();
        settings.algorithms.forEach(applyRegistrationAlgorithmSelection);
    }

    const attachmentElement = field('authenticator-attachment');
    if (attachmentElement) {
        attachmentElement.value = settings.attachment;
        dispatchChangeEvent(attachmentElement);
    }
    setValue('resident-key', settings.residentKey);
    setValue('user-verification-reg', settings.userVerification);

    const excludeCredentialsCheckbox = field('exclude-credentials');
    if (excludeCredentialsCheckbox) {
        excludeCredentialsCheckbox.checked = settings.excludeCredentials;
        setFakeExcludeCredentials(fakeExcludeCredentials);
    }

    setChecked('cred-props', settings.credProps);
    setChecked('min-pin-length', settings.minPinLength);
    const credProtectSelect = field('cred-protect');
    const enforceCredProtectCheckbox = field('enforce-cred-protect');
    if (credProtectSelect && enforceCredProtectCheckbox) {
        credProtectSelect.value = settings.credProtect;
        enforceCredProtectCheckbox.checked = settings.enforceCredProtect;
        enforceCredProtectCheckbox.disabled = !settings.credProtect;
    }
    setValue('large-blob-reg', settings.largeBlob);
    setChecked('prf-reg', settings.prf);
    setValue('prf-eval-first-reg', settings.prfFirst);
    setValue('prf-eval-second-reg', settings.prfSecond);

    applyHintsToCheckboxes(settings.hints, 'registration');
}

// The authentication form set to what the request says
// (./authentication-request.js): the fields it changes, Allow Credentials
// announced as changed. A request without extensions also clears the
// registration form's credProps, minPinLength and credProtect.
export function updateAuthenticationFormFromJson(publicKey) {
    const field = id => document.getElementById(id);
    const allowCredentialsSelect = field('allow-credentials');
    const previous = readAuthenticationForm();
    const { settings } = readRequestOptions(publicKey, previous, {
        choices: allowCredentialsSelect ? Array.from(allowCredentialsSelect.options).map(option => option.value) : [],
    });
    const setChanged = (id, key) => {
        if (settings[key] !== previous[key]) {
            field(id).value = settings[key];
        }
    };

    setChanged('challenge-auth', 'challenge');
    setChanged('timeout-auth', 'timeout');
    if (allowCredentialsSelect && allowCredentialsSelect.value !== settings.allowCredentials) {
        allowCredentialsSelect.value = settings.allowCredentials;
        dispatchChangeEvent(allowCredentialsSelect);
    }
    setChanged('user-verification-auth', 'userVerification');

    if (publicKey.extensions) {
        setChanged('prf-eval-first-auth', 'prfFirst');
        setChanged('prf-eval-second-auth', 'prfSecond');
        setChanged('large-blob-auth', 'largeBlob');
        setChanged('large-blob-write', 'largeBlobWrite');
    } else {
        const credPropsCheckbox = document.getElementById('cred-props');
        if (credPropsCheckbox) {
            credPropsCheckbox.checked = false;
        }

        const minPinLengthCheckbox = document.getElementById('min-pin-length');
        if (minPinLengthCheckbox) {
            minPinLengthCheckbox.checked = false;
        }

        const credProtectSelect = document.getElementById('cred-protect');
        const enforceCredProtectCheckbox = document.getElementById('enforce-cred-protect');
        if (credProtectSelect && enforceCredProtectCheckbox) {
            credProtectSelect.value = '';
            enforceCredProtectCheckbox.checked = true;
            enforceCredProtectCheckbox.disabled = true;
        }
    }

    if (Array.isArray(publicKey.hints)) {
        applyHintsToCheckboxes(publicKey.hints, 'authentication');
    }
}
