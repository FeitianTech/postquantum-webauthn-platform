import {
    HINT_VALUES,
    applyAuthenticatorAttachmentPreference,
    deriveAllowedAttachmentsFromHints,
    enforceAuthenticatorAttachmentWithHints,
    ensureAuthenticationHintsAllowed,
    normalizeHintValue,
} from './hint-rules.js';

export {
    applyAuthenticatorAttachmentPreference,
    deriveAllowedAttachmentsFromHints,
    enforceAuthenticatorAttachmentWithHints,
    ensureAuthenticationHintsAllowed,
    normalizeHintValue,
};

const registrationHintCallbacks = new Set();

export function registerHintsChangeCallback(callback) {
    if (typeof callback === 'function') {
        registrationHintCallbacks.add(callback);
    }
}

// The form's checkboxes: hint-<value>, and hint-<value>-auth on Authentication.
function hintCheckboxes(scope) {
    const suffix = scope === 'authentication' ? '-auth' : '';
    return HINT_VALUES.map(value => ({ id: `hint-${value}${suffix}`, value }));
}

export function collectSelectedHints(scope) {
    const mappings = hintCheckboxes(scope);
    const hints = [];
    mappings.forEach(({id, value}) => {
        const checkbox = document.getElementById(id);
        if (checkbox?.checked) {
            hints.push(value);
        }
    });
    return hints;
}

export function applyHintsToCheckboxes(hints, scope) {
    const normalized = new Set(
        Array.isArray(hints)
            ? hints.map(normalizeHintValue).filter(Boolean)
            : []
    );
    const mappings = hintCheckboxes(scope);
    mappings.forEach(({id, value}) => {
        const checkbox = document.getElementById(id);
        if (checkbox) {
            checkbox.checked = normalized.has(value);
        }
    });
    if (scope !== 'authentication' && registrationHintCallbacks.size > 0) {
        registrationHintCallbacks.forEach(callback => {
            try {
                callback();
            } catch (error) {
                console.error('Failed to run registration hints change callback.', error);
            }
        });
    }
}
