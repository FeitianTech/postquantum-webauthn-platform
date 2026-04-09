import { state } from '../../shared/state.js';
import {
    convertFormat,
    currentFormatToJsonFormat,
    getCurrentBinaryFormat,
} from '../../shared/binary-utils.js';
import {
    collectSelectedHints,
    deriveAllowedAttachmentsFromHints,
} from '../hints.js';
import {
    getCredentialIdHex,
    getStoredCredentialAttachment,
} from '../credential-utils.js';
import { getFakeAllowCredentials } from '../exclude-credentials.js';

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
            cred => (cred.credentialIdHex || getCredentialIdHex(cred)) === allowCreds,
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
                    publicKey.allowCredentials = [
                        {
                            type: 'public-key',
                            id: formattedId,
                        },
                    ];
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

            let idValue = { $hex: hexValue };
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
            publicKey.extensions.largeBlob = { read: true };
        } else if (largeBlobAuth === 'write') {
            const largeBlobWrite = document.getElementById('large-blob-write')?.value;
            if (largeBlobWrite) {
                publicKey.extensions.largeBlob = {
                    write: currentFormatToJsonFormat(largeBlobWrite),
                };
            }
        }
    }

    const prfFirst = document.getElementById('prf-eval-first-auth')?.value;
    const prfSecond = document.getElementById('prf-eval-second-auth')?.value;
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

    if (hints.length > 0) {
        publicKey.hints = hints;
    }

    return { publicKey };
}
