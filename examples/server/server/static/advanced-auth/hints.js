import { HINT_ATTACHMENT_MAP } from './constants.js';
import { state } from './state.js';
import {
    convertFormat,
    currentFormatToJsonFormat,
    getCurrentBinaryFormat
} from './binary-utils.js';
import {
    extractHexFromJsonFormat,
    getCredentialIdHex,
    getStoredCredentialAttachment,
    normalizeAttachmentValue
} from './credential-utils.js';

let onRegistrationHintsChange = null;

export function registerHintsChangeCallback(callback) {
    onRegistrationHintsChange = typeof callback === 'function' ? callback : null;
}

export function normalizeHintValue(value) {
    if (typeof value !== 'string') {
        return '';
    }
    return value.trim().toLowerCase();
}

export function collectSelectedHints(scope) {
    const mappings = scope === 'authentication'
        ? [
            {id: 'hint-client-device-auth', value: 'client-device'},
            {id: 'hint-hybrid-auth', value: 'hybrid'},
            {id: 'hint-security-key-auth', value: 'security-key'},
        ]
        : [
            {id: 'hint-client-device', value: 'client-device'},
            {id: 'hint-hybrid', value: 'hybrid'},
            {id: 'hint-security-key', value: 'security-key'},
        ];
    const hints = [];
    mappings.forEach(({id, value}) => {
        const checkbox = document.getElementById(id);
        if (checkbox?.checked) {
            hints.push(value);
        }
    });
    return hints;
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

export function applyHintsToCheckboxes(hints, scope) {
    const normalized = new Set(
        Array.isArray(hints)
            ? hints.map(normalizeHintValue).filter(Boolean)
            : []
    );
    const mappings = scope === 'authentication'
        ? [
            {id: 'hint-client-device-auth', value: 'client-device'},
            {id: 'hint-hybrid-auth', value: 'hybrid'},
            {id: 'hint-security-key-auth', value: 'security-key'},
        ]
        : [
            {id: 'hint-client-device', value: 'client-device'},
            {id: 'hint-hybrid', value: 'hybrid'},
            {id: 'hint-security-key', value: 'security-key'},
        ];
    mappings.forEach(({id, value}) => {
        const checkbox = document.getElementById(id);
        if (checkbox) {
            checkbox.checked = normalized.has(value);
        }
    });
    if (scope !== 'authentication' && onRegistrationHintsChange) {
        onRegistrationHintsChange();
    }
}

export function enforceAuthenticatorAttachmentWithHints(publicKey, options = {}) {
    const { requireSelection = false } = options || {};
    if (!publicKey || typeof publicKey !== 'object') {
        if (requireSelection) {
            throw new Error('Please select at least one authenticator hint before continuing.');
        }
        return [];
    }

    const allowedAttachments = ensureAuthenticationHintsAllowed(publicKey, { requireSelection });
    const allowedList = Array.isArray(allowedAttachments) ? allowedAttachments : [];

    if (allowedList.length > 0) {
        publicKey.allowedAuthenticatorAttachments = allowedList.slice();
    } else if (Object.prototype.hasOwnProperty.call(publicKey, 'allowedAuthenticatorAttachments')) {
        delete publicKey.allowedAuthenticatorAttachments;
    }

    if (!publicKey.authenticatorSelection || typeof publicKey.authenticatorSelection !== 'object') {
        publicKey.authenticatorSelection = {};
    }

    const selection = publicKey.authenticatorSelection;
    if (selection && typeof selection === 'object' &&
        Object.prototype.hasOwnProperty.call(selection, 'authenticatorAttachment')) {
        delete selection.authenticatorAttachment;
    }

    return allowedList;
}

export function applyAuthenticatorAttachmentPreference(targetOptions, allowedAttachments, ...fallbackSources) {
    if (!targetOptions || typeof targetOptions !== 'object') {
        return;
    }

    const publicKey = targetOptions.publicKey && typeof targetOptions.publicKey === 'object'
        ? targetOptions.publicKey
        : targetOptions;

    if (!publicKey || typeof publicKey !== 'object') {
        return;
    }

    let resolved = Array.isArray(allowedAttachments)
        ? allowedAttachments.map(normalizeAttachmentValue).filter(Boolean)
        : [];

    if (!resolved.length && Array.isArray(publicKey.allowedAuthenticatorAttachments)) {
        resolved = publicKey.allowedAuthenticatorAttachments
            .map(normalizeAttachmentValue)
            .filter(Boolean);
    }

    if (!resolved.length) {
        fallbackSources.forEach(source => {
            if (resolved.length || !source || typeof source !== 'object') {
                return;
            }
            if (Array.isArray(source.allowedAuthenticatorAttachments)) {
                const normalized = source.allowedAuthenticatorAttachments
                    .map(normalizeAttachmentValue)
                    .filter(Boolean);
                if (normalized.length) {
                    resolved = normalized;
                    return;
                }
            }
            if (Array.isArray(source.hints)) {
                const derived = deriveAllowedAttachmentsFromHints(source.hints);
                if (derived.length) {
                    resolved = derived;
                }
            }
        });
    }

    if (resolved.length > 0) {
        publicKey.allowedAuthenticatorAttachments = resolved.slice();
    } else if (Object.prototype.hasOwnProperty.call(publicKey, 'allowedAuthenticatorAttachments')) {
        delete publicKey.allowedAuthenticatorAttachments;
    }

    if (resolved.length === 1) {
        if (!publicKey.authenticatorSelection || typeof publicKey.authenticatorSelection !== 'object') {
            publicKey.authenticatorSelection = {};
        }
        publicKey.authenticatorSelection.authenticatorAttachment = resolved[0];
    } else if (publicKey.authenticatorSelection && typeof publicKey.authenticatorSelection === 'object'
        && Object.prototype.hasOwnProperty.call(publicKey.authenticatorSelection, 'authenticatorAttachment')) {
        delete publicKey.authenticatorSelection.authenticatorAttachment;
    }
}

export function ensureAuthenticationHintsAllowed(publicKey, options = {}) {
    const { requireSelection = false } = options || {};
    if (!publicKey || typeof publicKey !== 'object') {
        if (requireSelection) {
            throw new Error('Please select at least one authenticator hint before continuing.');
        }
        return [];
    }

    const hints = Array.isArray(publicKey.hints) ? publicKey.hints : [];
    const normalizedHints = hints.map(normalizeHintValue).filter(Boolean);

    if (requireSelection && normalizedHints.length === 0) {
        throw new Error('Please select at least one authenticator hint before continuing.');
    }

    let allowedAttachments = deriveAllowedAttachmentsFromHints(normalizedHints);

    if (requireSelection && normalizedHints.length > 0 && allowedAttachments.length === 0) {
        throw new Error('Selected hints do not map to any authenticator attachments.');
    }

    const requestedAllowed = Array.isArray(publicKey.allowedAuthenticatorAttachments)
        ? Array.from(new Set(publicKey.allowedAuthenticatorAttachments
            .map(normalizeAttachmentValue)
            .filter(Boolean)))
        : [];

    if (requestedAllowed.length > 0) {
        if (allowedAttachments.length > 0) {
            allowedAttachments = allowedAttachments.filter(value => requestedAllowed.includes(value));
        } else {
            allowedAttachments = requestedAllowed.slice();
        }
    }

    allowedAttachments = Array.from(new Set(allowedAttachments));

    const resolvedAllowed = allowedAttachments.length > 0
        ? allowedAttachments
        : requestedAllowed;

    if (requireSelection && resolvedAllowed.length === 0) {
        throw new Error('Selected hints do not map to any authenticator attachments.');
    }

    if (Array.isArray(publicKey.allowCredentials) && resolvedAllowed.length > 0) {
        const invalidDescriptor = publicKey.allowCredentials.find(descriptor => {
            if (!descriptor || typeof descriptor !== 'object') {
                return false;
            }
            const descriptorId = descriptor.id;
            const hexId = extractHexFromJsonFormat(descriptorId);
            if (!hexId) {
                return false;
            }
            const matchingCredential = (state.storedCredentials || []).find(cred => {
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
            return attachment && !resolvedAllowed.includes(attachment);
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
                const matchingCredential = (state.storedCredentials || []).find(cred => {
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
                return attachment && resolvedAllowed.includes(attachment);
            });
            if (!publicKey.allowCredentials.length) {
                delete publicKey.allowCredentials;
            }
        } else if (publicKey.allowCredentials.length === 0 && Array.isArray(state.storedCredentials) && state.storedCredentials.length > 0) {
            if (resolvedAllowed.length === 1) {
                const allowedValue = resolvedAllowed[0];
                const fallbackCredential = (state.storedCredentials || []).find(cred => {
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
                const fallbackSource = (state.storedCredentials || []).filter(cred => {
                    const attachment = getStoredCredentialAttachment(cred);
                    return !resolvedAllowed.length || (attachment && resolvedAllowed.includes(attachment));
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
                if (fallbackCredentials.length > 0) {
                    publicKey.allowCredentials = fallbackCredentials;
                } else {
                    delete publicKey.allowCredentials;
                }
            }
        }
    }

    return resolvedAllowed;
}
