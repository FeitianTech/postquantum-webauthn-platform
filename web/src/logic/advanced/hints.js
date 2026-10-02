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

// The attachments the request allows: its hints', else its authenticatorSelection's.
function requestAttachments(publicKey) {
    const hints = Array.isArray(publicKey.hints) ? publicKey.hints : [];
    const normalizedHints = hints.map(normalizeHintValue).filter(Boolean);

    /** @type {string[]} */
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
    return resolvedAttachments;
}

// The saved credential an allowCredentials descriptor names by its ID, or none.
function storedCredentialFor(descriptor, credentials) {
    if (!descriptor || typeof descriptor !== 'object') {
        return null;
    }
    const hexId = extractHexFromJsonFormat(descriptor.id);
    if (!hexId) {
        return null;
    }
    return credentials.find(cred => {
        const credentialIdHex = cred.credentialIdHex || getCredentialIdHex(cred);
        if (!credentialIdHex) {
            return false;
        }
        return credentialIdHex.toLowerCase() === hexId.toLowerCase();
    }) || null;
}

// When allowCredentials names a saved credential of an attachment not allowed,
// only the saved credentials of an allowed one stay (none: no allowCredentials).
// Gives whether it named one.
function narrowAllowCredentials(publicKey, credentials, resolvedAttachments) {
    const invalidDescriptor = publicKey.allowCredentials.find(descriptor => {
        const matchingCredential = storedCredentialFor(descriptor, credentials);
        if (!matchingCredential) {
            return false;
        }
        const attachment = getStoredCredentialAttachment(matchingCredential);
        return attachment && !resolvedAttachments.includes(attachment);
    });
    if (!invalidDescriptor) {
        return false;
    }
    publicKey.allowCredentials = publicKey.allowCredentials.filter(descriptor => {
        const matchingCredential = storedCredentialFor(descriptor, credentials);
        if (!matchingCredential) {
            return false;
        }
        const attachment = getStoredCredentialAttachment(matchingCredential);
        return attachment && resolvedAttachments.includes(attachment);
    });
    if (!publicKey.allowCredentials.length) {
        delete publicKey.allowCredentials;
    }
    return true;
}

// An empty allowCredentials, given saved credentials: with one attachment
// allowed, the first saved credential of it (none: it stays empty); with more,
// every saved credential of them (none: no allowCredentials).
function fillEmptyAllowCredentials(publicKey, storedCredentials, resolvedAttachments) {
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
        return;
    }
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

    const resolvedAttachments = requestAttachments(publicKey);

    if (Array.isArray(publicKey.allowCredentials) && resolvedAttachments.length > 0) {
        const narrowed = narrowAllowCredentials(publicKey, credentials, resolvedAttachments);
        if (!narrowed && publicKey.allowCredentials.length === 0 && Array.isArray(storedCredentials) && storedCredentials.length > 0) {
            fillEmptyAllowCredentials(publicKey, storedCredentials, resolvedAttachments);
        }
    }

    return resolvedAttachments;
}
