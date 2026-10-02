// What the hints and the authenticator attachment mean for a request, with no
// form: the hints' values in the form's order, the attachments they imply, the
// attachment given to the browser, and the allowCredentials the stored
// credentials' attachments allow. DOM-free.
import { extractHexFromJsonFormat, jsonBytes } from './editor/byte-values.js';
import {
    getCredentialIdHex,
    getStoredCredentialAttachment,
    normalizeAttachmentValue,
} from '../credentials/record-fields.js';

const HINT_ATTACHMENT_MAP = {
    'security-key': 'cross-platform',
    'hybrid': 'cross-platform',
    'client-device': 'platform',
};

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

/**
 * A registration's request: no saved credential to offer.
 * @param {Record<string, any>} publicKey
 * @returns {string[]}
 */
export function enforceAuthenticatorAttachmentWithHints(publicKey) {
    return ensureAuthenticationHintsAllowed(publicKey);
}

/**
 * @param {Record<string, any> | null | undefined} targetOptions
 * @param {string[]} allowedAttachments
 * @param {...unknown} fallbackSources
 */
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
            if (selection && typeof selection === 'object' && Object.hasOwn(selection, 'authenticatorAttachment')) {
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
    } else if (Object.hasOwn(publicKey.authenticatorSelection, 'authenticatorAttachment')) {
        delete publicKey.authenticatorSelection.authenticatorAttachment;
    }
}

/**
 * The attachments the request's hints allow; may narrow allowCredentials, and
 * throws for hints the request cannot keep. storedCredentials: the saved
 * credentials Allow Credentials may name (none when not given).
 * @param {Record<string, any>} publicKey
 * @param {{ storedCredentials?: Array<Record<string, any>> }} [options]
 * @returns {string[]}
 */
export function ensureAuthenticationHintsAllowed(publicKey, options = {}) {
    const { storedCredentials } = options || {};
    const credentials = storedCredentials || [];
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

    if (!resolvedAttachments.length && selection && Object.hasOwn(selection, 'authenticatorAttachment')) {
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
            const matchingCredential = credentials.find(cred => {
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
                const matchingCredential = credentials.find(cred => {
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
                    const formattedId = jsonBytes(credentialIdHex);
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
                        return {
                            type: 'public-key',
                            id: jsonBytes(credentialIdHex),
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
