import { state } from './state.js';
import {
    base64ToHex,
    base64UrlToHex,
    convertFormat,
    currentFormatToBase64Url,
    currentFormatToJsonFormat,
    getCurrentBinaryFormat,
    sortObjectKeys
} from './binary-utils.js';
import {
    collectSelectedHints,
    deriveAllowedAttachmentsFromHints,
    enforceAuthenticatorAttachmentWithHints,
    applyHintsToCheckboxes,
    registerHintsChangeCallback,
    ensureAuthenticationHintsAllowed,
    applyAuthenticatorAttachmentPreference
} from './hints.js';
import {
    getCredentialIdHex,
    getCredentialUserHandleHex,
    getStoredCredentialAttachment,
    extractHexFromJsonFormat
} from './credential-utils.js';
import {
    showStatus,
    hideStatus
} from './status.js';
import {
    getFakeExcludeCredentials,
    getFakeAllowCredentials,
    setFakeExcludeCredentials
} from './exclude-credentials.js';

registerHintsChangeCallback(() => updateJsonEditor());

function setJsonEditorContent(content) {
    const jsonEditor = document.getElementById('json-editor');
    if (!jsonEditor) {
        return;
    }
    jsonEditor.value = content;
    jsonEditor.scrollTop = 0;
    jsonEditor.scrollLeft = 0;
}

export function getCredentialCreationOptions() {
    const userId = document.getElementById('user-id')?.value || '';
    const userName = document.getElementById('user-name')?.value || '';
    const userDisplayName = document.getElementById('user-display-name')?.value || '';
    const challenge = document.getElementById('challenge-reg')?.value || '';

    const publicKey = {
        rp: {
            name: 'WebAuthn FIDO2 Test Application',
            id: window.location.hostname
        },
        user: {
            id: currentFormatToJsonFormat(userId),
            name: userName,
            displayName: userDisplayName
        },
        challenge: currentFormatToJsonFormat(challenge),
        pubKeyCredParams: [],
        timeout: parseInt(document.getElementById('timeout-reg')?.value) || 90000,
        authenticatorSelection: {},
        attestation: document.getElementById('attestation')?.value || 'direct',
        extensions: {}
    };

    const authenticatorAttachment = document.getElementById('authenticator-attachment')?.value || 'cross-platform';
    if (authenticatorAttachment && authenticatorAttachment !== 'unspecified') {
        publicKey.authenticatorSelection.authenticatorAttachment = authenticatorAttachment;
    }

    if (document.getElementById('param-mldsa44')?.checked) {
        publicKey.pubKeyCredParams.push({type: 'public-key', alg: -48});
    }
    if (document.getElementById('param-mldsa65')?.checked) {
        publicKey.pubKeyCredParams.push({type: 'public-key', alg: -49});
    }
    if (document.getElementById('param-mldsa87')?.checked) {
        publicKey.pubKeyCredParams.push({type: 'public-key', alg: -50});
    }
    if (document.getElementById('param-eddsa')?.checked) {
        publicKey.pubKeyCredParams.push({type: 'public-key', alg: -8});
    }
    if (document.getElementById('param-es256')?.checked) {
        publicKey.pubKeyCredParams.push({type: 'public-key', alg: -7});
    }
    if (document.getElementById('param-rs256')?.checked) {
        publicKey.pubKeyCredParams.push({type: 'public-key', alg: -257});
    }
    if (document.getElementById('param-es384')?.checked) {
        publicKey.pubKeyCredParams.push({type: 'public-key', alg: -35});
    }
    if (document.getElementById('param-es512')?.checked) {
        publicKey.pubKeyCredParams.push({type: 'public-key', alg: -36});
    }
    if (document.getElementById('param-rs384')?.checked) {
        publicKey.pubKeyCredParams.push({type: 'public-key', alg: -258});
    }
    if (document.getElementById('param-rs512')?.checked) {
        publicKey.pubKeyCredParams.push({type: 'public-key', alg: -259});
    }
    if (document.getElementById('param-rs1')?.checked) {
        publicKey.pubKeyCredParams.push({type: 'public-key', alg: -65535});
    }

    const residentKeyValue = document.getElementById('resident-key')?.value || 'discouraged';
    publicKey.authenticatorSelection.residentKey = residentKeyValue;
    publicKey.authenticatorSelection.requireResidentKey = residentKeyValue === 'required';

    const userVerification = document.getElementById('user-verification-reg')?.value;
    if (userVerification) publicKey.authenticatorSelection.userVerification = userVerification;

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
                            '$hex': credentialIdHex
                        }
                    });
                }
            });
        }

        getFakeExcludeCredentials().forEach(hexValue => {
            if (!hexValue) {
                return;
            }

            let idValue = { '$hex': hexValue };
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

    if (document.getElementById('cred-props')?.checked) publicKey.extensions.credProps = true;
    if (document.getElementById('min-pin-length')?.checked) publicKey.extensions.minPinLength = true;

    const credentialProtection = document.getElementById('cred-protect')?.value;
    if (credentialProtection) {
        publicKey.extensions.credentialProtectionPolicy = credentialProtection;
        if (document.getElementById('enforce-cred-protect')?.checked) {
            publicKey.extensions.enforceCredentialProtectionPolicy = true;
        }
    }

    const largeBlobReg = document.getElementById('large-blob-reg')?.value;
    if (largeBlobReg) publicKey.extensions.largeBlob = {support: largeBlobReg};

    if (document.getElementById('prf-reg')?.checked) {
        const prfFirst = document.getElementById('prf-eval-first-reg')?.value;
        const prfSecond = document.getElementById('prf-eval-second-reg')?.value;
        if (prfFirst) {
            publicKey.extensions.prf = {
                eval: {
                    first: currentFormatToJsonFormat(prfFirst)
                }
            };
            if (prfSecond) {
                publicKey.extensions.prf.eval.second = currentFormatToJsonFormat(prfSecond);
            }
        }
    }

    const hints = collectSelectedHints('registration');
    if (hints.length > 0) publicKey.hints = hints;

    enforceAuthenticatorAttachmentWithHints(publicKey);

    return { publicKey };
}

export function getCredentialRequestOptions() {
    const challenge = document.getElementById('challenge-auth')?.value || '';
    const hints = collectSelectedHints('authentication');
    const allowedAttachments = deriveAllowedAttachmentsFromHints(hints);

    const publicKey = {
        challenge: currentFormatToJsonFormat(challenge),
        timeout: parseInt(document.getElementById('timeout-auth')?.value) || 90000,
        rpId: window.location.hostname,
        allowCredentials: [],
        userVerification: document.getElementById('user-verification-auth')?.value || 'preferred',
        extensions: {},
    };

    const allowCreds = document.getElementById('allow-credentials')?.value;
    let shouldRemoveAllowCredentials = false;

    if (allowCreds === 'empty') {
        publicKey.allowCredentials = [];
        shouldRemoveAllowCredentials = true;
    } else if (allowCreds === 'all') {
        const credentialSource = (state.storedCredentials || []).filter(cred => {
            if (allowedAttachments.length === 0) {
                return true;
            }
            const attachment = getStoredCredentialAttachment(cred);
            return attachment && allowedAttachments.includes(attachment);
        });

        const allCredentials = credentialSource
            .map(cred => {
                const credentialIdHex = cred.credentialIdHex || getCredentialIdHex(cred);
                if (!credentialIdHex) {
                    return null;
                }

                const formatValue = convertFormat(credentialIdHex, 'hex', getCurrentBinaryFormat());
                const formattedId = currentFormatToJsonFormat(formatValue);
                if (!formattedId || typeof formattedId !== 'object') {
                    return null;
                }

                return {
                    type: 'public-key',
                    id: formattedId,
                };
            })
            .filter(Boolean);
        publicKey.allowCredentials = allCredentials;
    } else {
        const selectedCred = (state.storedCredentials || []).find(
            cred => (cred.credentialIdHex || getCredentialIdHex(cred)) === allowCreds
        );
        if (selectedCred) {
            const attachment = getStoredCredentialAttachment(selectedCred);
            if (allowedAttachments.length > 0 && (!attachment || !allowedAttachments.includes(attachment))) {
                publicKey.allowCredentials = [];
            } else {
                const credentialIdHex = selectedCred.credentialIdHex || getCredentialIdHex(selectedCred);
                const formatValue = convertFormat(credentialIdHex, 'hex', getCurrentBinaryFormat());
                const formattedId = currentFormatToJsonFormat(formatValue);
                if (formattedId && typeof formattedId === 'object') {
                    publicKey.allowCredentials = [{
                        type: 'public-key',
                        id: formattedId,
                    }];
                }
            }
        } else {
            const fallbackSource = (state.storedCredentials || []).filter(cred => {
                if (allowedAttachments.length === 0) {
                    return true;
                }
                const attachment = getStoredCredentialAttachment(cred);
                return attachment && allowedAttachments.includes(attachment);
            });
            const fallbackCredentials = fallbackSource
                .map(cred => {
                    const credentialIdHex = cred.credentialIdHex || getCredentialIdHex(cred);
                    if (!credentialIdHex) {
                        return null;
                    }

                    const formatValue = convertFormat(credentialIdHex, 'hex', getCurrentBinaryFormat());
                    const formattedId = currentFormatToJsonFormat(formatValue);
                    if (!formattedId || typeof formattedId !== 'object') {
                        return null;
                    }

                    return {
                        type: 'public-key',
                        id: formattedId,
                    };
                })
                .filter(Boolean);
            publicKey.allowCredentials = fallbackCredentials;
        }
    }

    const fakeAllowCredentials = getFakeAllowCredentials();
    if (Array.isArray(fakeAllowCredentials) && fakeAllowCredentials.length) {
        if (!Array.isArray(publicKey.allowCredentials)) {
            publicKey.allowCredentials = [];
        }

        fakeAllowCredentials.forEach(hexValue => {
            if (!hexValue) {
                return;
            }

            let idValue = { '$hex': hexValue };
            try {
                const formattedValue = convertFormat(hexValue, 'hex', getCurrentBinaryFormat());
                const jsonValue = currentFormatToJsonFormat(formattedValue);
                if (jsonValue && typeof jsonValue === 'object') {
                    idValue = jsonValue;
                }
            } catch (error) {
                // Fallback to hex representation if conversion fails.
            }

            publicKey.allowCredentials.push({
                type: 'public-key',
                id: idValue,
            });
        });

        shouldRemoveAllowCredentials = false;
    }

    if (shouldRemoveAllowCredentials && (!publicKey.allowCredentials || !publicKey.allowCredentials.length)) {
        delete publicKey.allowCredentials;
    }

    const largeBlobAuth = document.getElementById('large-blob-auth')?.value;
    if (largeBlobAuth) {
        if (largeBlobAuth === 'read') {
            publicKey.extensions.largeBlob = {read: true};
        } else if (largeBlobAuth === 'write') {
            const largeBlobWrite = document.getElementById('large-blob-write')?.value;
            if (largeBlobWrite) {
                publicKey.extensions.largeBlob = {
                    write: currentFormatToJsonFormat(largeBlobWrite)
                };
            }
        }
    }

    const prfFirst = document.getElementById('prf-eval-first-auth')?.value;
    const prfSecond = document.getElementById('prf-eval-second-auth')?.value;
    if (prfFirst) {
        publicKey.extensions.prf = {
            eval: {
                first: currentFormatToJsonFormat(prfFirst)
            }
        };
        if (prfSecond) {
            publicKey.extensions.prf.eval.second = currentFormatToJsonFormat(prfSecond);
        }
    }

    if (hints.length > 0) publicKey.hints = hints;

    return { publicKey };
}

export function updateJsonEditor() {
    let options = {};
    let title = 'JSON Editor';

    if (state.currentSubTab === 'registration') {
        options = getCredentialCreationOptions();
        title = 'JSON Editor (CredentialCreationOptions)';
    } else if (state.currentSubTab === 'authentication') {
        options = getCredentialRequestOptions();
        title = 'JSON Editor (CredentialRequestOptions)';
    }

    const sortedOptions = sortObjectKeys(options);
    setJsonEditorContent(JSON.stringify(sortedOptions, null, 2));

    const titleElement = document.querySelector('.json-editor-column h3');
    if (titleElement) {
        titleElement.textContent = title;
    }
}

export function saveJsonEditor() {
    try {
        const jsonText = document.getElementById('json-editor').value;
        const parsed = JSON.parse(jsonText);

        if (!parsed.publicKey) {
            throw new Error('Invalid JSON structure: Missing "publicKey" property');
        }

        const publicKey = parsed.publicKey;

        if (state.currentSubTab === 'registration') {
            if (!publicKey.rp || !publicKey.user || !publicKey.challenge) {
                throw new Error('Invalid CredentialCreationOptions: Missing required properties (rp, user, challenge)');
            }

            updateRegistrationFormFromJson(publicKey);
        } else if (state.currentSubTab === 'authentication') {
            if (!publicKey.challenge) {
                throw new Error('Invalid CredentialRequestOptions: Missing required challenge property');
            }

            updateAuthenticationFormFromJson(publicKey);
        }

        const statusDiv = document.querySelector('#advanced-tab .status') ||
                        document.querySelector('#advanced-status');
        if (statusDiv) {
            statusDiv.textContent = 'JSON changes saved successfully!';
            statusDiv.className = 'status success';
            statusDiv.style.display = 'block';
            setTimeout(() => {
                statusDiv.style.display = 'none';
            }, 3000);
        }

    } catch (error) {
        const statusDiv = document.querySelector('#advanced-tab .status') ||
                        document.querySelector('#advanced-status');
        if (statusDiv) {
            statusDiv.textContent = `JSON validation failed: ${error.message}`;
            statusDiv.className = 'status error';
            statusDiv.style.display = 'block';
            setTimeout(() => {
                statusDiv.style.display = 'none';
            }, 5000);
        }
    }
}

export function resetJsonEditor() {
    updateJsonEditor();

    const statusDiv = document.querySelector('#advanced-tab .status') ||
                    document.querySelector('#advanced-status');
    if (statusDiv) {
        statusDiv.textContent = 'JSON editor reset to current settings';
        statusDiv.className = 'status info';
        statusDiv.style.display = 'block';
        setTimeout(() => {
            statusDiv.style.display = 'none';
        }, 2000);
    }
}

export function updateRegistrationFormFromJson(publicKey) {
    if (publicKey.user) {
        if (publicKey.user.id) {
            let userIdValue = '';
            if (publicKey.user.id.$base64) {
                userIdValue = base64UrlToHex(publicKey.user.id.$base64);
            } else if (publicKey.user.id.$base64url) {
                userIdValue = base64UrlToHex(publicKey.user.id.$base64url);
            } else if (publicKey.user.id.$hex) {
                userIdValue = publicKey.user.id.$hex;
            } else if (typeof publicKey.user.id === 'string') {
                userIdValue = base64UrlToHex(publicKey.user.id);
            }
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
        let challengeValue = '';
        if (publicKey.challenge.$base64) {
            challengeValue = base64UrlToHex(publicKey.challenge.$base64);
        } else if (publicKey.challenge.$base64url) {
            challengeValue = base64UrlToHex(publicKey.challenge.$base64url);
        } else if (publicKey.challenge.$hex) {
            challengeValue = publicKey.challenge.$hex;
        } else if (typeof publicKey.challenge === 'string') {
            challengeValue = base64UrlToHex(publicKey.challenge);
        }
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
        if (document.getElementById('param-mldsa44')) document.getElementById('param-mldsa44').checked = false;
        if (document.getElementById('param-mldsa65')) document.getElementById('param-mldsa65').checked = false;
        if (document.getElementById('param-mldsa87')) document.getElementById('param-mldsa87').checked = false;
        document.getElementById('param-eddsa').checked = false;
        document.getElementById('param-es256').checked = false;
        document.getElementById('param-rs256').checked = false;
        document.getElementById('param-es384').checked = false;
        document.getElementById('param-es512').checked = false;
        document.getElementById('param-rs384').checked = false;
        document.getElementById('param-rs512').checked = false;
        document.getElementById('param-rs1').checked = false;

        publicKey.pubKeyCredParams.forEach(param => {
            if (param && Object.prototype.hasOwnProperty.call(param, 'alg')) {
                const rawAlg = param.alg;
                const algValue = typeof rawAlg === 'string' ? parseInt(rawAlg, 10) : rawAlg;
                if (Number.isNaN(algValue)) {
                    return;
                }
                switch(algValue) {
                    case -48:
                        if (document.getElementById('param-mldsa44')) document.getElementById('param-mldsa44').checked = true;
                        break;
                    case -49:
                        if (document.getElementById('param-mldsa65')) document.getElementById('param-mldsa65').checked = true;
                        break;
                    case -50:
                        if (document.getElementById('param-mldsa87')) document.getElementById('param-mldsa87').checked = true;
                        break;
                    case -8:
                        document.getElementById('param-eddsa').checked = true;
                        break;
                    case -7:
                        document.getElementById('param-es256').checked = true;
                        break;
                    case -257:
                        document.getElementById('param-rs256').checked = true;
                        break;
                    case -35:
                        document.getElementById('param-es384').checked = true;
                        break;
                    case -36:
                        document.getElementById('param-es512').checked = true;
                        break;
                    case -258:
                        document.getElementById('param-rs384').checked = true;
                        break;
                    case -259:
                        document.getElementById('param-rs512').checked = true;
                        break;
                    case -65535:
                        document.getElementById('param-rs1').checked = true;
                        break;
                }
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
            try {
                attachmentElement.dispatchEvent(new Event('change', { bubbles: true }));
            } catch (error) {
                const changeEvent = document.createEvent('Event');
                changeEvent.initEvent('change', true, true);
                attachmentElement.dispatchEvent(changeEvent);
            }
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
            try {
                attachmentElement.dispatchEvent(new Event('change', { bubbles: true }));
            } catch (error) {
                const changeEvent = document.createEvent('Event');
                changeEvent.initEvent('change', true, true);
                attachmentElement.dispatchEvent(changeEvent);
            }
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
                .filter(Boolean)
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
                let prfFirstValue = '';
                if (publicKey.extensions.prf.eval.first.$base64) {
                    prfFirstValue = base64UrlToHex(publicKey.extensions.prf.eval.first.$base64);
                } else if (publicKey.extensions.prf.eval.first.$base64url) {
                    prfFirstValue = base64UrlToHex(publicKey.extensions.prf.eval.first.$base64url);
                } else if (publicKey.extensions.prf.eval.first.$hex) {
                    prfFirstValue = publicKey.extensions.prf.eval.first.$hex;
                } else if (typeof publicKey.extensions.prf.eval.first === 'string') {
                    prfFirstValue = base64UrlToHex(publicKey.extensions.prf.eval.first);
                }
                if (prfFirstValue) {
                    document.getElementById('prf-eval-first-reg').value = prfFirstValue;
                }
            }
            if (publicKey.extensions.prf.eval.second) {
                let prfSecondValue = '';
                if (publicKey.extensions.prf.eval.second.$base64) {
                    prfSecondValue = base64UrlToHex(publicKey.extensions.prf.eval.second.$base64);
                } else if (publicKey.extensions.prf.eval.second.$base64url) {
                    prfSecondValue = base64UrlToHex(publicKey.extensions.prf.eval.second.$base64url);
                } else if (publicKey.extensions.prf.eval.second.$hex) {
                    prfSecondValue = publicKey.extensions.prf.eval.second.$hex;
                } else if (typeof publicKey.extensions.prf.eval.second === 'string') {
                    prfSecondValue = base64UrlToHex(publicKey.extensions.prf.eval.second);
                }
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
        let challengeValue = '';
        if (publicKey.challenge.$base64) {
            challengeValue = base64UrlToHex(publicKey.challenge.$base64);
        } else if (publicKey.challenge.$base64url) {
            challengeValue = base64UrlToHex(publicKey.challenge.$base64url);
        } else if (publicKey.challenge.$hex) {
            challengeValue = publicKey.challenge.$hex;
        } else if (typeof publicKey.challenge === 'string') {
            challengeValue = base64UrlToHex(publicKey.challenge);
        }
        if (challengeValue) {
            document.getElementById('challenge-auth').value = challengeValue;
        }
    }

    if (publicKey.timeout) {
        document.getElementById('timeout-auth').value = publicKey.timeout.toString();
    }

    if (Object.prototype.hasOwnProperty.call(publicKey, 'userVerification')) {
        document.getElementById('user-verification-auth').value = publicKey.userVerification || 'preferred';
    }

    if (publicKey.extensions) {
        if (publicKey.extensions.prf && publicKey.extensions.prf.eval) {
            if (publicKey.extensions.prf.eval.first) {
                let prfFirstValue = '';
                if (publicKey.extensions.prf.eval.first.$base64) {
                    prfFirstValue = base64UrlToHex(publicKey.extensions.prf.eval.first.$base64);
                } else if (publicKey.extensions.prf.eval.first.$base64url) {
                    prfFirstValue = base64UrlToHex(publicKey.extensions.prf.eval.first.$base64url);
                } else if (publicKey.extensions.prf.eval.first.$hex) {
                    prfFirstValue = publicKey.extensions.prf.eval.first.$hex;
                } else if (typeof publicKey.extensions.prf.eval.first === 'string') {
                    prfFirstValue = base64UrlToHex(publicKey.extensions.prf.eval.first);
                }
                if (prfFirstValue) {
                    document.getElementById('prf-eval-first-auth').value = prfFirstValue;
                }
            }
            if (publicKey.extensions.prf.eval.second) {
                let prfSecondValue = '';
                if (publicKey.extensions.prf.eval.second.$base64) {
                    prfSecondValue = base64UrlToHex(publicKey.extensions.prf.eval.second.$base64);
                } else if (publicKey.extensions.prf.eval.second.$base64url) {
                    prfSecondValue = base64UrlToHex(publicKey.extensions.prf.eval.second.$base64url);
                } else if (publicKey.extensions.prf.eval.second.$hex) {
                    prfSecondValue = publicKey.extensions.prf.eval.second.$hex;
                } else if (typeof publicKey.extensions.prf.eval.second === 'string') {
                    prfSecondValue = base64UrlToHex(publicKey.extensions.prf.eval.second);
                }
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
                let largeBlobValue = '';
                if (publicKey.extensions.largeBlob.write.$base64) {
                    largeBlobValue = base64UrlToHex(publicKey.extensions.largeBlob.write.$base64);
                } else if (publicKey.extensions.largeBlob.write.$base64url) {
                    largeBlobValue = base64UrlToHex(publicKey.extensions.largeBlob.write.$base64url);
                } else if (publicKey.extensions.largeBlob.write.$hex) {
                    largeBlobValue = publicKey.extensions.largeBlob.write.$hex;
                } else if (typeof publicKey.extensions.largeBlob.write === 'string') {
                    largeBlobValue = base64UrlToHex(publicKey.extensions.largeBlob.write);
                }
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

export function getAdvancedCreateOptions() {
    const currentFormat = getCurrentBinaryFormat();

    const options = {
        username: document.getElementById('user-name').value,
        displayName: document.getElementById('user-display-name').value || document.getElementById('user-name').value,
        userId: convertFormat(document.getElementById('user-id').value, currentFormat, 'hex'),

        attestation: document.getElementById('attestation').value,
        userVerification: document.getElementById('user-verification-reg').value,
        residentKey: document.getElementById('resident-key').value,
        authenticatorAttachment: document.getElementById('authenticator-attachment').value || 'cross-platform',

        excludeCredentials: document.getElementById('exclude-credentials').checked,
        fakeCredLength: parseInt(document.getElementById('fake-cred-length-reg').value) || 0,

        challenge: convertFormat(document.getElementById('challenge-reg').value, currentFormat, 'hex'),
        timeout: parseInt(document.getElementById('timeout-reg').value) || 90000,

        pubKeyCredParams: [],
        hints: [],
        extensions: {}
    };

    if (document.getElementById('param-mldsa44')?.checked) options.pubKeyCredParams.push('ML-DSA-44');
    if (document.getElementById('param-mldsa65')?.checked) options.pubKeyCredParams.push('ML-DSA-65');
    if (document.getElementById('param-mldsa87')?.checked) options.pubKeyCredParams.push('ML-DSA-87');
    if (document.getElementById('param-eddsa')?.checked) options.pubKeyCredParams.push('EdDSA');
    if (document.getElementById('param-es256')?.checked) options.pubKeyCredParams.push('ES256');
    if (document.getElementById('param-rs256')?.checked) options.pubKeyCredParams.push('RS256');
    if (document.getElementById('param-es384')?.checked) options.pubKeyCredParams.push('ES384');
    if (document.getElementById('param-es512')?.checked) options.pubKeyCredParams.push('ES512');
    if (document.getElementById('param-rs384')?.checked) options.pubKeyCredParams.push('RS384');
    if (document.getElementById('param-rs512')?.checked) options.pubKeyCredParams.push('RS512');
    if (document.getElementById('param-rs1')?.checked) options.pubKeyCredParams.push('RS1');

    options.hints = collectSelectedHints('registration');
    if (document.getElementById('cred-props')?.checked) {
        options.extensions.credProps = true;
    }

    if (document.getElementById('min-pin-length')?.checked) {
        options.extensions.minPinLength = true;
    }

    const credProtect = document.getElementById('cred-protect')?.value;
    if (credProtect && credProtect !== '') {
        options.extensions.credentialProtectionPolicy = credProtect;
        if (document.getElementById('enforce-cred-protect')?.checked) {
            options.extensions.enforceCredentialProtectionPolicy = true;
        }
    }

    const largeBlob = document.getElementById('large-blob-reg')?.value;
    if (largeBlob && largeBlob !== '') {
        options.extensions.largeBlob = { support: largeBlob };
    }

    if (document.getElementById('prf-reg')?.checked) {
        const prfFirst = document.getElementById('prf-eval-first-reg')?.value;
        const prfSecond = document.getElementById('prf-eval-second-reg')?.value;
        if (prfFirst) {
            options.extensions.prf = {
                eval: {
                    first: currentFormatToJsonFormat(prfFirst)
                }
            };
            if (prfSecond) {
                options.extensions.prf.eval.second = currentFormatToJsonFormat(prfSecond);
            }
        }
    }

    return options;
}

export function getAdvancedAssertOptions() {
    const allowCreds = document.getElementById('allow-credentials').value;
    const currentFormat = getCurrentBinaryFormat();

    const options = {
        userVerification: document.getElementById('user-verification-auth').value,
        allowCredentials: allowCreds,
        fakeCredLength: parseInt(document.getElementById('fake-cred-length-auth').value) || 0,
        challenge: convertFormat(document.getElementById('challenge-auth').value, currentFormat, 'hex'),
        timeout: parseInt(document.getElementById('timeout-auth').value) || 90000,
        extensions: {}
    };

    if (allowCreds !== 'all' && allowCreds !== 'empty') {
        options.specificCredentialId = allowCreds;
    }

    const largeBlob = document.getElementById('large-blob-auth')?.value;
    if (largeBlob === 'read') {
        options.extensions.largeBlob = { read: true };
    } else if (largeBlob === 'write') {
        const largeBlobWrite = document.getElementById('large-blob-write')?.value;
        if (largeBlobWrite) {
            options.extensions.largeBlob = {
                write: currentFormatToJsonFormat(largeBlobWrite)
            };
        }
    }

    const prfFirst = document.getElementById('prf-eval-first-auth')?.value;
    const prfSecond = document.getElementById('prf-eval-second-auth')?.value;
    if (prfFirst || prfSecond) {
        const prfEval = {};
        if (prfFirst) {
            prfEval.first = currentFormatToJsonFormat(prfFirst);
        }
        if (prfSecond) {
            prfEval.second = currentFormatToJsonFormat(prfSecond);
        }
        if (Object.keys(prfEval).length > 0) {
            options.extensions.prf = { eval: prfEval };
        }
    }

    options.hints = collectSelectedHints('authentication');
    return options;
}

export function extractBinaryValue(value) {
    if (!value) return '';

    if (typeof value === 'string') {
        return value;
    }

    if (typeof value === 'object') {
        if (value.$hex) return value.$hex;
        if (value.$base64) return base64ToHex(value.$base64);
        if (value.$base64url) return base64UrlToHex(value.$base64url);
        if (value.$js) return value.$js;
    }

    return '';
}

export function editCreateOptions() {
    const options = getAdvancedCreateOptions();
    state.currentJsonMode = 'create';
    state.currentJsonData = options;

    const sortedOptions = sortObjectKeys(options);
    setJsonEditorContent(JSON.stringify(sortedOptions, null, 2));
    document.getElementById('apply-json').style.display = 'inline-block';
    document.getElementById('cancel-json').style.display = 'inline-block';
}

export function editAssertOptions() {
    const options = getAdvancedAssertOptions();
    state.currentJsonMode = 'assert';
    state.currentJsonData = options;

    const sortedOptions = sortObjectKeys(options);
    setJsonEditorContent(JSON.stringify(sortedOptions, null, 2));
    document.getElementById('apply-json').style.display = 'inline-block';
    document.getElementById('cancel-json').style.display = 'inline-block';
}

export function applyJsonChanges() {
    try {
        const jsonText = document.getElementById('json-editor').value;
        const parsed = JSON.parse(jsonText);

        if (state.currentJsonMode === 'create') {
            if (parsed.username) document.getElementById('user-name').value = parsed.username;
            if (parsed.displayName) document.getElementById('user-display-name').value = parsed.displayName;
            if (Object.prototype.hasOwnProperty.call(parsed, 'attestation')) {
                document.getElementById('attestation').value = parsed.attestation || 'direct';
            }
            if (Object.prototype.hasOwnProperty.call(parsed, 'userVerification')) {
                document.getElementById('user-verification-reg').value = parsed.userVerification || 'preferred';
            }
            if (parsed.residentKey) document.getElementById('resident-key').value = parsed.residentKey;
            if (Object.prototype.hasOwnProperty.call(parsed, 'authenticatorAttachment')) {
                const attachmentSelect = document.getElementById('authenticator-attachment');
                if (attachmentSelect) {
                    const rawValue = parsed.authenticatorAttachment;
                    const normalized = rawValue === 'platform' || rawValue === 'cross-platform' || rawValue === 'unspecified'
                        ? rawValue
                        : 'cross-platform';
                    attachmentSelect.value = normalized;
                    try {
                        attachmentSelect.dispatchEvent(new Event('change', { bubbles: true }));
                    } catch (error) {
                        const changeEvent = document.createEvent('Event');
                        changeEvent.initEvent('change', true, true);
                        attachmentSelect.dispatchEvent(changeEvent);
                    }
                }
            }
        } else if (state.currentJsonMode === 'assert') {
            if (Object.prototype.hasOwnProperty.call(parsed, 'userVerification')) {
                document.getElementById('user-verification-auth').value = parsed.userVerification || 'preferred';
            }
        }

        showStatus('advanced', 'JSON changes applied successfully!', 'success');
        cancelJsonEdit();
    } catch (error) {
        showStatus('advanced', `Invalid JSON: ${error.message}`, 'error');
    }
}

export function cancelJsonEdit() {
    setJsonEditorContent('');
    document.getElementById('apply-json').style.display = 'none';
    document.getElementById('cancel-json').style.display = 'none';
    state.currentJsonMode = null;
    state.currentJsonData = {};
}

export function updateJsonFromForm() {
    if (state.currentJsonMode) {
        if (state.currentJsonMode === 'create') {
            const options = getAdvancedCreateOptions();
            const sortedOptions = sortObjectKeys(options);
            setJsonEditorContent(JSON.stringify(sortedOptions, null, 2));
        } else if (state.currentJsonMode === 'assert') {
            const options = getAdvancedAssertOptions();
            const sortedOptions = sortObjectKeys(options);
            setJsonEditorContent(JSON.stringify(sortedOptions, null, 2));
        }
    }
}
