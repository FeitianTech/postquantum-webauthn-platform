// Whether the saved credentials can use the largeBlob and prf extensions in an
// authentication, with no page: what a credential's record says it supports,
// and whether the Advanced tab's authentication form may ask for each (a
// chosen credential judged alone, else any saved one), with the note it shows
// when it may not. DOM-free: the current form (./forms.js) and the new UI both
// use it.
import { getCredentialIdHex } from '../credentials/utils.js';

export const CAPABILITY_TEXT = {
    noLargeBlob: 'No largeBlob capable credentials available',
    selectedNoLargeBlob: 'Selected credential does not support largeBlob.',
    noPrf: 'No credentials with prf support available.',
    selectedNoPrf: 'Selected credential does not support the prf extension.',
};

export function credentialSupportsLargeBlob(cred) {
    if (!cred || typeof cred !== 'object') {
        return false;
    }
    if (cred.largeBlob === true || cred.largeBlobSupported === true) {
        return true;
    }
    const clientOutputs = cred.clientExtensionOutputs;
    if (clientOutputs && typeof clientOutputs === 'object') {
        const value = clientOutputs.largeBlob;
        if (value) {
            if (typeof value === 'object') {
                if (value.supported || value.written || value.blob || value.result) {
                    return true;
                }
            } else {
                return true;
            }
        }
    }
    const properties = cred.properties;
    if (properties && typeof properties === 'object') {
        if (properties.largeBlob === true || properties.largeBlobSupported === true) {
            return true;
        }
    }
    return false;
}

export function credentialSupportsPrf(cred) {
    if (!cred || typeof cred !== 'object') {
        return false;
    }
    const clientOutputs = cred.clientExtensionOutputs;
    if (clientOutputs && typeof clientOutputs === 'object') {
        const value = clientOutputs.prf;
        if (value) {
            if (typeof value === 'object') {
                if (value.results || value.eval || value.first || value.second) {
                    return true;
                }
                if (Object.keys(value).length > 0) {
                    return true;
                }
            } else {
                return true;
            }
        }
    }
    const properties = cred.properties;
    if (properties && typeof properties === 'object') {
        if (properties.prf) {
            return true;
        }
    }
    return false;
}

/** The saved credential whose ID is the hex given (in any case), or null. */
export function findSavedCredential(storedCredentials, hexValue) {
    if (typeof hexValue !== 'string' || !hexValue) {
        return null;
    }
    const normalised = hexValue.toLowerCase();
    return (storedCredentials || []).find(cred => {
        const storedHex = (cred.credentialIdHex || getCredentialIdHex(cred) || '').toLowerCase();
        return storedHex === normalised;
    }) || null;
}

function availability(storedCredentials, selectedCredential, supports, noneText, selectedText) {
    if (selectedCredential) {
        const available = supports(selectedCredential);
        return { available, message: available ? '' : selectedText };
    }
    const available = Boolean(storedCredentials && storedCredentials.some(supports));
    return { available, message: available ? '' : noneText };
}

/** Whether largeBlob may be asked for, and the note when not. */
export function largeBlobAvailability(storedCredentials, selectedCredential = null) {
    return availability(
        storedCredentials,
        selectedCredential,
        credentialSupportsLargeBlob,
        CAPABILITY_TEXT.noLargeBlob,
        CAPABILITY_TEXT.selectedNoLargeBlob,
    );
}

/** Whether prf may be asked for, and the note when not. */
export function prfAvailability(storedCredentials, selectedCredential = null) {
    return availability(
        storedCredentials,
        selectedCredential,
        credentialSupportsPrf,
        CAPABILITY_TEXT.noPrf,
        CAPABILITY_TEXT.selectedNoPrf,
    );
}

/**
 * Both, for an Allow Credentials choice: a saved credential's ID (hex) is
 * judged alone; All and Empty judge the saved credentials.
 */
export function authenticationAvailability(storedCredentials, selection) {
    const selected = selection && selection !== 'all' && selection !== 'empty'
        ? findSavedCredential(storedCredentials, selection)
        : null;
    return {
        largeBlob: largeBlobAvailability(storedCredentials, selected),
        prf: prfAvailability(storedCredentials, selected),
    };
}
