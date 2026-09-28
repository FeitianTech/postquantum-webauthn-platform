import { state } from '../../shared/state.js';
import { applyHintsToCheckboxes } from '../auth/hints.js';
import { extractHexFromJsonFormat } from '../credentials/utils.js';
import { setFakeExcludeCredentials } from '../auth/exclude-credentials.js';
import {
    applyRegistrationAlgorithmSelection,
    clearRegistrationAlgorithmCheckboxesForFormSync,
} from './algorithms.js';
import {
    decodeJsonBinaryToHex,
    dispatchChangeEvent,
} from './dom-helpers.js';
import { readRegistrationForm } from './creation-options.js';
import { readCreationOptions } from './registration-request.js';

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

export function updateAuthenticationFormFromJson(publicKey) {
    if (publicKey.challenge) {
        const challengeValue = decodeJsonBinaryToHex(publicKey.challenge);
        if (challengeValue) {
            document.getElementById('challenge-auth').value = challengeValue;
        }
    }

    if (publicKey.timeout) {
        document.getElementById('timeout-auth').value = publicKey.timeout.toString();
    }

    const allowCredentialsSelect = document.getElementById('allow-credentials');
    if (allowCredentialsSelect) {
        let desiredValue = 'all';
        let shouldUpdateSelect = true;

        if (!Object.prototype.hasOwnProperty.call(publicKey, 'allowCredentials')) {
            desiredValue = 'empty';
        } else if (Array.isArray(publicKey.allowCredentials)) {
            if (publicKey.allowCredentials.length === 0) {
                shouldUpdateSelect = false;
            } else if (publicKey.allowCredentials.length === 1) {
                const descriptor = publicKey.allowCredentials[0];
                if (descriptor && typeof descriptor === 'object') {
                    const extractedHex = extractHexFromJsonFormat(descriptor.id);
                    if (extractedHex) {
                        const hasOption = Array.from(allowCredentialsSelect.options)
                            .some(option => option.value === extractedHex);
                        if (hasOption) {
                            desiredValue = extractedHex;
                        }
                    }
                }
            }
        }

        if (shouldUpdateSelect && desiredValue !== 'all' && desiredValue !== 'empty') {
            const available = Array.from(allowCredentialsSelect.options)
                .some(option => option.value === desiredValue);
            if (!available) {
                desiredValue = 'all';
            }
        }

        if (shouldUpdateSelect && allowCredentialsSelect.value !== desiredValue) {
            allowCredentialsSelect.value = desiredValue;
            dispatchChangeEvent(allowCredentialsSelect);
        }
    }

    if (Object.prototype.hasOwnProperty.call(publicKey, 'userVerification')) {
        document.getElementById('user-verification-auth').value = publicKey.userVerification || 'preferred';
    }

    if (publicKey.extensions) {
        if (publicKey.extensions.prf && publicKey.extensions.prf.eval) {
            if (publicKey.extensions.prf.eval.first) {
                const prfFirstValue = decodeJsonBinaryToHex(publicKey.extensions.prf.eval.first);
                if (prfFirstValue) {
                    document.getElementById('prf-eval-first-auth').value = prfFirstValue;
                }
            }
            if (publicKey.extensions.prf.eval.second) {
                const prfSecondValue = decodeJsonBinaryToHex(publicKey.extensions.prf.eval.second);
                if (prfSecondValue) {
                    document.getElementById('prf-eval-second-auth').value = prfSecondValue;
                }
            }
        }

        if (publicKey.extensions.largeBlob) {
            if (publicKey.extensions.largeBlob.read) {
                document.getElementById('large-blob-auth').value = 'read';
            } else if (publicKey.extensions.largeBlob.write) {
                document.getElementById('large-blob-auth').value = 'write';
                const largeBlobValue = decodeJsonBinaryToHex(publicKey.extensions.largeBlob.write);
                if (largeBlobValue) {
                    document.getElementById('large-blob-write').value = largeBlobValue;
                }
            }
        }
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
