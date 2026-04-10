import { state } from '../../shared/state.js';
import { applyHintsToCheckboxes } from '../auth/hints.js';
import {
    extractHexFromJsonFormat,
    getCredentialIdHex,
} from '../credential-utils.js';
import { setFakeExcludeCredentials } from '../auth/exclude-credentials.js';
import {
    applyRegistrationAlgorithmSelection,
    clearRegistrationAlgorithmCheckboxesForFormSync,
} from './algorithms.js';
import {
    decodeJsonBinaryToHex,
    dispatchChangeEvent,
} from './dom-helpers.js';

export function updateRegistrationFormFromJson(publicKey) {
    if (publicKey.user) {
        if (publicKey.user.id) {
            const userIdValue = decodeJsonBinaryToHex(publicKey.user.id);
            if (userIdValue) {
                document.getElementById('user-id').value = userIdValue;
            }
        }
        if (publicKey.user.name) {
            document.getElementById('user-name').value = publicKey.user.name;
        }
        if (publicKey.user.displayName) {
            document.getElementById('user-display-name').value = publicKey.user.displayName;
        }
    }

    if (publicKey.challenge) {
        const challengeValue = decodeJsonBinaryToHex(publicKey.challenge);
        if (challengeValue) {
            document.getElementById('challenge-reg').value = challengeValue;
        }
    }

    if (publicKey.timeout) {
        document.getElementById('timeout-reg').value = publicKey.timeout.toString();
    }

    if (Object.prototype.hasOwnProperty.call(publicKey, 'attestation')) {
        document.getElementById('attestation').value = publicKey.attestation || 'direct';
    }

    if (publicKey.pubKeyCredParams && Array.isArray(publicKey.pubKeyCredParams)) {
        clearRegistrationAlgorithmCheckboxesForFormSync();

        publicKey.pubKeyCredParams.forEach(param => {
            if (param && Object.prototype.hasOwnProperty.call(param, 'alg')) {
                applyRegistrationAlgorithmSelection(param.alg);
            }
        });
    }

    if (publicKey.authenticatorSelection) {
        const attachmentElement = document.getElementById('authenticator-attachment');
        if (attachmentElement) {
            const attachmentValue = publicKey.authenticatorSelection.authenticatorAttachment;
            let normalizedAttachment = 'cross-platform';
            if (attachmentValue === 'platform' || attachmentValue === 'cross-platform') {
                normalizedAttachment = attachmentValue;
            } else if (attachmentValue === 'unspecified') {
                normalizedAttachment = 'unspecified';
            }
            attachmentElement.value = normalizedAttachment;
            dispatchChangeEvent(attachmentElement);
        }

        const residentKeyElement = document.getElementById('resident-key');
        if (residentKeyElement) {
            let residentKeySetting = publicKey.authenticatorSelection.residentKey || 'discouraged';
            if (publicKey.authenticatorSelection.requireResidentKey === true) {
                residentKeySetting = 'required';
            }
            residentKeyElement.value = residentKeySetting;
        }

        if (Object.prototype.hasOwnProperty.call(publicKey.authenticatorSelection, 'userVerification')) {
            const userVerificationValue = publicKey.authenticatorSelection.userVerification || 'preferred';
            document.getElementById('user-verification-reg').value = userVerificationValue;
        }
    } else {
        const attachmentElement = document.getElementById('authenticator-attachment');
        if (attachmentElement) {
            attachmentElement.value = 'cross-platform';
            dispatchChangeEvent(attachmentElement);
        }
    }

    const excludeCredentialsCheckbox = document.getElementById('exclude-credentials');
    if (excludeCredentialsCheckbox) {
        const excludeArray = Array.isArray(publicKey.excludeCredentials)
            ? publicKey.excludeCredentials
            : [];
        excludeCredentialsCheckbox.checked = excludeArray.length > 0;

        const storedIds = new Set(
            (state.storedCredentials || [])
                .map(cred => (cred.credentialIdHex || getCredentialIdHex(cred) || '').toLowerCase())
                .filter(Boolean),
        );

        const fakeHexList = [];
        excludeArray.forEach(entry => {
            if (!entry || typeof entry !== 'object') {
                return;
            }
            const hexValue = extractHexFromJsonFormat(entry.id);
            if (!hexValue) {
                return;
            }
            const normalised = hexValue.toLowerCase();
            if (!storedIds.has(normalised)) {
                fakeHexList.push(hexValue);
            }
        });

        setFakeExcludeCredentials(fakeHexList);
    }

    if (publicKey.extensions) {
        const credPropsCheckbox = document.getElementById('cred-props');
        if (credPropsCheckbox) {
            credPropsCheckbox.checked = !!publicKey.extensions.credProps;
        }

        const minPinLengthCheckbox = document.getElementById('min-pin-length');
        if (minPinLengthCheckbox) {
            minPinLengthCheckbox.checked = !!publicKey.extensions.minPinLength;
        }

        const credProtectSelect = document.getElementById('cred-protect');
        const enforceCredProtectCheckbox = document.getElementById('enforce-cred-protect');
        if (credProtectSelect && enforceCredProtectCheckbox) {
            const policy = publicKey.extensions.credentialProtectionPolicy || '';
            credProtectSelect.value = policy;
            if (policy) {
                enforceCredProtectCheckbox.disabled = false;
                enforceCredProtectCheckbox.checked = !!publicKey.extensions.enforceCredentialProtectionPolicy;
            } else {
                enforceCredProtectCheckbox.checked = true;
                enforceCredProtectCheckbox.disabled = true;
            }
        }

        if (publicKey.extensions.prf && publicKey.extensions.prf.eval) {
            if (publicKey.extensions.prf.eval.first) {
                const prfFirstValue = decodeJsonBinaryToHex(publicKey.extensions.prf.eval.first);
                if (prfFirstValue) {
                    document.getElementById('prf-eval-first-reg').value = prfFirstValue;
                }
            }
            if (publicKey.extensions.prf.eval.second) {
                const prfSecondValue = decodeJsonBinaryToHex(publicKey.extensions.prf.eval.second);
                if (prfSecondValue) {
                    document.getElementById('prf-eval-second-reg').value = prfSecondValue;
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
        applyHintsToCheckboxes(publicKey.hints, 'registration');
    } else {
        applyHintsToCheckboxes([], 'registration');
    }
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
