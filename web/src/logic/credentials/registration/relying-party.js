// The relying party's view of a registration as the registration view shows it:
// its own fields without the certificates and the checks' internals, the
// registration data it nests merged in, and the authenticator data as hex.
import {cloneJson} from '../../shared/json.js';
import {removeKeysCaseInsensitive, sanitiseRegistrationData, stripCertificateCollections} from './sanitize.js';

const RP_INFO_EXCLUDED_KEYS = [
    'attestationFmt',
    'attestationObject',
    'credentialIdBase64',
    'credentialIdBase64Url',
    'device',
    'root_valid',
    'rp_id_hash_valid',
    'signature_valid',
    'clientExtensionResults',
    'flags',
    'signatureCounter',
    'residentKey',
    'userHandle',
];

// The authenticator data as hex: the view's own, else the first spelling the
// relying party gives that is hex; the first it gives, as it is, when none is.
function authenticatorValuesOf(info, summaryHex) {
    const authenticatorCandidates = [];
    const recordCandidate = value => {
        if (typeof value !== 'string') {
            return;
        }
        const trimmed = value.trim();
        if (trimmed) {
            authenticatorCandidates.push(trimmed);
        }
    };

    if (info && typeof info === 'object') {
        recordCandidate(info.authenticatorData);

        const registrationData = info.registrationData;
        if (registrationData && typeof registrationData === 'object') {
            recordCandidate(registrationData.authenticatorData);
        }
    }

    let authenticatorHex = summaryHex;
    if (!authenticatorHex) {
        const hexCandidate = authenticatorCandidates.find(candidate => {
            const compact = candidate.replace(/\s+/g, '');
            return compact && compact.length % 2 === 0 && /^[0-9a-fA-F]+$/.test(compact);
        });
        if (hexCandidate) {
            authenticatorHex = hexCandidate.replace(/\s+/g, '').toLowerCase();
        }
    }

    let fallbackAuthenticatorValue = '';
    if (!authenticatorHex && authenticatorCandidates.length) {
        fallbackAuthenticatorValue = authenticatorCandidates[0];
    }
    return { authenticatorHex, fallbackAuthenticatorValue };
}

// The copy's registration data, sanitised (none when nothing is left), and its
// attestation summary when the copy has none of its own. Gives that data.
function mergeRegistrationData(cloned) {
    let registrationData = null;
    if (cloned.registrationData && typeof cloned.registrationData === 'object') {
        registrationData = sanitiseRegistrationData(cloned.registrationData);
    }

    if (registrationData) {
        cloned.registrationData = registrationData;
    } else if (Object.hasOwn(cloned, 'registrationData')) {
        delete cloned.registrationData;
    }

    if (
        !cloned.attestationSummary
        && registrationData
        && registrationData.attestationSummary
        && typeof registrationData.attestationSummary === 'object'
    ) {
        cloned.attestationSummary = cloneJson(registrationData.attestationSummary);
    }
    return registrationData;
}

// The copy's errors without those about the AAGUID (the details show it
// themselves); none left, no errors.
function withoutAaguidErrors(cloned) {
    if (Array.isArray(cloned.errors)) {
        cloned.errors = cloned.errors.filter(item => {
            if (typeof item === 'string') {
                return !item.toLowerCase().includes('aaguid');
            }
            return true;
        });
        if (cloned.errors.length === 0) {
            delete cloned.errors;
        }
    } else if (cloned.errors && typeof cloned.errors === 'object') {
        Object.keys(cloned.errors).forEach(key => {
            const value = cloned.errors[key];
            if (typeof value === 'string') {
                if (value.toLowerCase().includes('aaguid')) {
                    delete cloned.errors[key];
                }
                return;
            }
            if (Array.isArray(value)) {
                const filtered = value.filter(item => {
                    return !(typeof item === 'string' && item.toLowerCase().includes('aaguid'));
                });
                if (filtered.length) {
                    cloned.errors[key] = filtered;
                } else {
                    delete cloned.errors[key];
                }
            }
        });
        if (cloned.errors && typeof cloned.errors === 'object' && Object.keys(cloned.errors).length === 0) {
            delete cloned.errors;
        }
    }
}

// The authenticator data and its hash, on the copy and on its registration data.
function writeAuthenticatorData(cloned, registrationData, { authenticatorHex, fallbackAuthenticatorValue, summaryHash }) {
    if (authenticatorHex) {
        cloned.authenticatorData = authenticatorHex;
    } else if (fallbackAuthenticatorValue) {
        cloned.authenticatorData = fallbackAuthenticatorValue;
    }

    if (summaryHash) {
        cloned.authenticatorDataHash = summaryHash;
        if (
            registrationData
            && typeof registrationData === 'object'
            && !registrationData.authenticatorDataHash
        ) {
            registrationData.authenticatorDataHash = summaryHash;
        }
    }

    if (
        registrationData
        && typeof registrationData === 'object'
        && authenticatorHex
        && !registrationData.authenticatorData
    ) {
        registrationData.authenticatorData = authenticatorHex;
    }
}

/**
 * @param {any} info
 * @param {{ authenticatorDataHex: string, authenticatorDataHash: string } | null} [authenticatorSummary]
 */
export function sanitizeRelyingPartyInfo(info, authenticatorSummary = null) {
    const summary = authenticatorSummary && typeof authenticatorSummary === 'object'
        ? authenticatorSummary
        : {};

    const summaryHash = typeof summary.authenticatorDataHash === 'string'
        ? summary.authenticatorDataHash.trim()
        : '';
    const summaryHex = typeof summary.authenticatorDataHex === 'string'
        ? summary.authenticatorDataHex.trim()
        : '';

    const { authenticatorHex, fallbackAuthenticatorValue } = authenticatorValuesOf(info, summaryHex);

    // No relying party: the view's own hex and hash alone, when it has them.
    if (!info || typeof info !== 'object') {
        if (!authenticatorHex && !summaryHash) {
            return null;
        }
        const minimal = {};
        if (authenticatorHex) {
            minimal.authenticatorData = authenticatorHex;
        }
        if (summaryHash) {
            minimal.authenticatorDataHash = summaryHash;
        }
        return minimal;
    }
    const cloned = cloneJson(info);

    stripCertificateCollections(cloned);
    removeKeysCaseInsensitive(cloned, RP_INFO_EXCLUDED_KEYS);

    const registrationData = mergeRegistrationData(cloned);
    withoutAaguidErrors(cloned);
    writeAuthenticatorData(cloned, registrationData, { authenticatorHex, fallbackAuthenticatorValue, summaryHash });

    return cloned;
}
