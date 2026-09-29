// What the hints and the authenticator attachment mean for a request, with no
// form: the hints' values in the form's order, the attachments they imply, the
// attachment given to the browser, and the allowCredentials the stored
// credentials' attachments allow. DOM-free.
import { HINT_ATTACHMENT_MAP } from '../constants.js';
import { state } from '../../shared/state.js';
import {
    convertFormat,
    currentFormatToJsonFormat,
    getCurrentBinaryFormat
} from '../../shared/utils/binary.js';
import {
    extractHexFromJsonFormat,
    getCredentialIdHex,
    getStoredCredentialAttachment,
    normalizeAttachmentValue
} from '../credentials/utils.js';

/** The hints the form offers, in its order. */
export const HINT_VALUES = ['client-device', 'hybrid', 'security-key'];

export function normalizeHintValue(value) {
    if (typeof value !== 'string') {
        return '';
    }
    return value.trim().toLowerCase();
}

export function deriveAllowedAttachmentsFromHints(hints) {
    const normalizedHints = Array.isArray(hints)
        ? hints.map(normalizeHintValue).filter(Boolean)
        : [];
    const attachments = [];
    const seen = new Set();
    normalizedHints.forEach(hint => {
        const mapped = HINT_ATTACHMENT_MAP[hint];
        if (mapped && !seen.has(mapped)) {
            attachments.push(mapped);
            seen.add(mapped);
        }
    });
    return attachments;
}

export function enforceAuthenticatorAttachmentWithHints(publicKey, options = {}) {
    const { storedCredentials } = options || {};
    return ensureAuthenticationHintsAllowed(publicKey, { storedCredentials });
}

export function applyAuthenticatorAttachmentPreference(targetOptions, allowedAttachments, ...fallbackSources) {
    if (!targetOptions || typeof targetOptions !== 'object') {
        return;
    }

    const publicKey = targetOptions.publicKey && typeof targetOptions.publicKey === 'object'
        ? targetOptions.publicKey
        : targetOptions;

    const normalizedResolved = Array.isArray(allowedAttachments)
        ? allowedAttachments.map(normalizeAttachmentValue).filter(Boolean)
        : [];

    const selectionSources = [publicKey, ...fallbackSources];

    let preferredAttachment = null;

    if (normalizedResolved.length === 1) {
        preferredAttachment = normalizedResolved[0];
    }

    if (!preferredAttachment) {
        for (const source of selectionSources) {
            if (!source || typeof source !== 'object') {
                continue;
            }
            const selection = source.authenticatorSelection;
            if (selection && typeof selection === 'object' && Object.prototype.hasOwnProperty.call(selection, 'authenticatorAttachment')) {
                const normalized = normalizeAttachmentValue(selection.authenticatorAttachment);
                if (normalized) {
                    preferredAttachment = normalized;
                    break;
                }
            }
        }
    }

    if (!preferredAttachment) {
        for (const source of selectionSources) {
            if (!source || typeof source !== 'object') {
                continue;
            }
            if (Array.isArray(source.hints)) {
                const derived = deriveAllowedAttachmentsFromHints(source.hints);
                if (derived.length === 1) {
                    preferredAttachment = derived[0];
                    break;
                }
            }
        }
    }

    if (!publicKey.authenticatorSelection || typeof publicKey.authenticatorSelection !== 'object') {
        publicKey.authenticatorSelection = {};
    }

    if (preferredAttachment) {
        publicKey.authenticatorSelection.authenticatorAttachment = preferredAttachment;
    } else if (Object.prototype.hasOwnProperty.call(publicKey.authenticatorSelection, 'authenticatorAttachment')) {
        delete publicKey.authenticatorSelection.authenticatorAttachment;
    }
}

// The stored credentials are the list's (state.storedCredentials) unless given.
export function ensureAuthenticationHintsAllowed(publicKey, options = {}) {
    const { storedCredentials = state.storedCredentials } = options || {};
    if (!publicKey || typeof publicKey !== 'object') {
        return [];
    }

    const hints = Array.isArray(publicKey.hints) ? publicKey.hints : [];
    const normalizedHints = hints.map(normalizeHintValue).filter(Boolean);

    const resolvedAttachments = [];
    const seen = new Set();

    const addAttachment = value => {
        const normalized = normalizeAttachmentValue(value);
        if (normalized && !seen.has(normalized)) {
            resolvedAttachments.push(normalized);
            seen.add(normalized);
        }
    };

    const derivedFromHints = deriveAllowedAttachmentsFromHints(normalizedHints);
    derivedFromHints.forEach(addAttachment);

    const selection = publicKey.authenticatorSelection && typeof publicKey.authenticatorSelection === 'object'
        ? publicKey.authenticatorSelection
        : null;

    if (!resolvedAttachments.length && selection && Object.prototype.hasOwnProperty.call(selection, 'authenticatorAttachment')) {
        addAttachment(selection.authenticatorAttachment);
    }

    if (Array.isArray(publicKey.allowCredentials) && resolvedAttachments.length > 0) {
        const invalidDescriptor = publicKey.allowCredentials.find(descriptor => {
            if (!descriptor || typeof descriptor !== 'object') {
                return false;
            }
            const descriptorId = descriptor.id;
            const hexId = extractHexFromJsonFormat(descriptorId);
            if (!hexId) {
                return false;
            }
            const matchingCredential = (storedCredentials || []).find(cred => {
                const credentialIdHex = cred.credentialIdHex || getCredentialIdHex(cred);
                if (!credentialIdHex) {
                    return false;
                }
                return credentialIdHex.toLowerCase() === hexId.toLowerCase();
            });
            if (!matchingCredential) {
                return false;
            }
            const attachment = getStoredCredentialAttachment(matchingCredential);
            return attachment && !resolvedAttachments.includes(attachment);
        });
        if (invalidDescriptor) {
            publicKey.allowCredentials = publicKey.allowCredentials.filter(descriptor => {
                if (!descriptor || typeof descriptor !== 'object') {
                    return false;
                }
                const descriptorId = descriptor.id;
                const hexId = extractHexFromJsonFormat(descriptorId);
                if (!hexId) {
                    return false;
                }
                const matchingCredential = storedCredentials.find(cred => {
                    const credentialIdHex = cred.credentialIdHex || getCredentialIdHex(cred);
                    if (!credentialIdHex) {
                        return false;
                    }
                    return credentialIdHex.toLowerCase() === hexId.toLowerCase();
                });
                if (!matchingCredential) {
                    return false;
                }
                const attachment = getStoredCredentialAttachment(matchingCredential);
                return attachment && resolvedAttachments.includes(attachment);
            });
            if (!publicKey.allowCredentials.length) {
                delete publicKey.allowCredentials;
            }
        } else if (publicKey.allowCredentials.length === 0 && Array.isArray(storedCredentials) && storedCredentials.length > 0) {
            if (resolvedAttachments.length === 1) {
                const allowedValue = resolvedAttachments[0];
                const fallbackCredential = storedCredentials.find(cred => {
                    const attachment = getStoredCredentialAttachment(cred);
                    return attachment && attachment === allowedValue;
                });
                if (fallbackCredential) {
                    const credentialIdHex = fallbackCredential.credentialIdHex || getCredentialIdHex(fallbackCredential);
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
                const fallbackSource = storedCredentials.filter(cred => {
                    const attachment = getStoredCredentialAttachment(cred);
                    return attachment && resolvedAttachments.includes(attachment);
                });
                const fallbackCredentials = fallbackSource
                    .map(cred => {
                        const credentialIdHex = cred.credentialIdHex || getCredentialIdHex(cred);
                        if (!credentialIdHex) {
                            return null;
                        }
                        const formatValue = convertFormat(credentialIdHex, 'hex', getCurrentBinaryFormat());
                        return {
                            type: 'public-key',
                            id: currentFormatToJsonFormat(formatValue),
                        };
                    })
                    .filter(Boolean);
                if (fallbackCredentials.length > 0) {
                    publicKey.allowCredentials = fallbackCredentials;
                } else {
                    delete publicKey.allowCredentials;
                }
            }
        }
    }

    return resolvedAttachments;
}
