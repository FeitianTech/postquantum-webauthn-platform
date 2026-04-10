import { state } from '../../shared/state.js';
import {
    convertFormat,
    currentFormatToJsonFormat,
    getCurrentBinaryFormat,
} from '../../shared/utils/binary.js';
import {
    collectSelectedHints,
    enforceAuthenticatorAttachmentWithHints,
} from '../auth/hints.js';
import {
    getCredentialIdHex,
    getCredentialUserHandleHex,
} from '../credentials/utils.js';
import { getFakeExcludeCredentials } from '../auth/exclude-credentials.js';
import { appendSelectedAlgorithmParams } from './algorithms.js';

export function getCredentialCreationOptions() {
    const userId = document.getElementById('user-id')?.value || '';
    const userName = document.getElementById('user-name')?.value || '';
    const userDisplayName = document.getElementById('user-display-name')?.value || '';
    const challenge = document.getElementById('challenge-reg')?.value || '';

    const publicKey = {
        rp: {
            name: 'FIDO2/WebAuthn PQC Developer Tools',
            id: window.location.hostname,
        },
        user: {
            id: currentFormatToJsonFormat(userId),
            name: userName,
            displayName: userDisplayName,
        },
        challenge: currentFormatToJsonFormat(challenge),
        pubKeyCredParams: [],
        timeout: parseInt(document.getElementById('timeout-reg')?.value) || 90000,
        authenticatorSelection: {},
        attestation: document.getElementById('attestation')?.value || 'direct',
        extensions: {},
    };

    const authenticatorAttachment = document.getElementById('authenticator-attachment')?.value || 'cross-platform';
    if (authenticatorAttachment && authenticatorAttachment !== 'unspecified') {
        publicKey.authenticatorSelection.authenticatorAttachment = authenticatorAttachment;
    }

    appendSelectedAlgorithmParams(publicKey.pubKeyCredParams);

    const residentKeyValue = document.getElementById('resident-key')?.value || 'discouraged';
    publicKey.authenticatorSelection.residentKey = residentKeyValue;
    publicKey.authenticatorSelection.requireResidentKey = residentKeyValue === 'required';

    const userVerification = document.getElementById('user-verification-reg')?.value;
    if (userVerification) {
        publicKey.authenticatorSelection.userVerification = userVerification;
    }

    const excludeList = [];
    const includeExcludes = document.getElementById('exclude-credentials')?.checked;
    if (includeExcludes) {
        const currentBinaryFormat = getCurrentBinaryFormat();
        const userIdHex = (convertFormat(userId, currentBinaryFormat, 'hex') || '').toLowerCase();

        if (userIdHex && Array.isArray(state.storedCredentials) && state.storedCredentials.length > 0) {
            state.storedCredentials.forEach(cred => {
                const handleHex = getCredentialUserHandleHex(cred);
                const credentialIdHex = getCredentialIdHex(cred);

                if (handleHex && credentialIdHex && handleHex === userIdHex) {
                    excludeList.push({
                        type: 'public-key',
                        id: {
                            $hex: credentialIdHex,
                        },
                    });
                }
            });
        }

        getFakeExcludeCredentials().forEach(hexValue => {
            if (!hexValue) {
                return;
            }

            let idValue = { $hex: hexValue };
            try {
                const formattedValue = convertFormat(hexValue, 'hex', currentBinaryFormat);
                const jsonValue = currentFormatToJsonFormat(formattedValue);
                if (jsonValue && typeof jsonValue === 'object') {
                    idValue = jsonValue;
                }
            } catch (error) {
                // Fall back to hex representation on conversion errors
            }

            excludeList.push({
                type: 'public-key',
                id: idValue,
            });
        });
    }

    publicKey.excludeCredentials = excludeList;

    if (document.getElementById('cred-props')?.checked) {
        publicKey.extensions.credProps = true;
    }
    if (document.getElementById('min-pin-length')?.checked) {
        publicKey.extensions.minPinLength = true;
    }

    const credentialProtection = document.getElementById('cred-protect')?.value;
    if (credentialProtection) {
        publicKey.extensions.credentialProtectionPolicy = credentialProtection;
        if (document.getElementById('enforce-cred-protect')?.checked) {
            publicKey.extensions.enforceCredentialProtectionPolicy = true;
        }
    }

    const largeBlobReg = document.getElementById('large-blob-reg')?.value;
    if (largeBlobReg) {
        publicKey.extensions.largeBlob = { support: largeBlobReg };
    }

    if (document.getElementById('prf-reg')?.checked) {
        const prfFirst = document.getElementById('prf-eval-first-reg')?.value;
        const prfSecond = document.getElementById('prf-eval-second-reg')?.value;
        if (prfFirst) {
            publicKey.extensions.prf = {
                eval: {
                    first: currentFormatToJsonFormat(prfFirst),
                },
            };
            if (prfSecond) {
                publicKey.extensions.prf.eval.second = currentFormatToJsonFormat(prfSecond);
            }
        }
    }

    const hints = collectSelectedHints('registration');
    if (hints.length > 0) {
        publicKey.hints = hints;
    }

    enforceAuthenticatorAttachmentWithHints(publicKey);

    return { publicKey };
}
