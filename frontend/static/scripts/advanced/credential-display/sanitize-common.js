import {cloneJson} from './data-utils.js';

const CERTIFICATE_COLLECTION_KEYS = [
    'attestationCertificate',
    'attestationCertificates',
    'attestation_certificate',
    'attestation_certificates',
];

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
    'client_extension_results',
    'flags',
    'signatureCounter',
    'signature_counter',
    'residentKey',
    'resident_key',
    'userHandle',
    'user_handle',
];

export function stripCertificateCollections(target) {
    if (!target || typeof target !== 'object') {
        return;
    }

    CERTIFICATE_COLLECTION_KEYS.forEach(key => {
        if (Object.prototype.hasOwnProperty.call(target, key)) {
            delete target[key];
        }
    });

    Object.keys(target).forEach(key => {
        const value = target[key];
        if (value && typeof value === 'object') {
            stripCertificateCollections(value);
        }
    });
}

export function removeKeysFromObject(target, keys) {
    if (!target || typeof target !== 'object' || !Array.isArray(keys) || !keys.length) {
        return;
    }

    const process = value => {
        if (value && typeof value === 'object') {
            removeKeysFromObject(value, keys);
        }
    };

    if (Array.isArray(target)) {
        target.forEach(process);
        return;
    }

    keys.forEach(key => {
        if (Object.prototype.hasOwnProperty.call(target, key)) {
            delete target[key];
        }
    });

    Object.values(target).forEach(process);
}

export function removeKeysCaseInsensitive(target, keys) {
    if (!target || typeof target !== 'object' || !Array.isArray(keys) || !keys.length) {
        return;
    }

    const lowerKeys = keys.map(key => String(key).toLowerCase());

    const handleValue = value => {
        if (value && typeof value === 'object') {
            removeKeysCaseInsensitive(value, keys);
        }
    };

    if (Array.isArray(target)) {
        target.forEach(handleValue);
        return;
    }

    Object.keys(target).forEach(key => {
        const value = target[key];
        if (lowerKeys.includes(String(key).toLowerCase())) {
            delete target[key];
            return;
        }
        handleValue(value);
    });
}

export function sanitiseRegistrationData(raw) {
    if (!raw || typeof raw !== 'object') {
        return null;
    }

    const cloned = cloneJson(raw);
    if (!cloned || typeof cloned !== 'object') {
        return null;
    }

    const keysToRemove = [
        'attestationObject',
        'attestation_object',
        'attestationStatement',
        'attestation_statement',
        'attStmt',
        'rawAuthenticatorData',
        'raw_authenticator_data',
        'rawClientDataJSON',
        'raw_client_data_json',
    ];

    removeKeysCaseInsensitive(cloned, keysToRemove);
    stripCertificateCollections(cloned);
    stripSignatureFormatting(cloned);

    if (Object.prototype.hasOwnProperty.call(cloned, 'attestation_summary') && !cloned.attestationSummary) {
        const summary = cloned.attestation_summary;
        delete cloned.attestation_summary;
        if (summary && typeof summary === 'object') {
            cloned.attestationSummary = summary;
        }
    }

    if (Object.prototype.hasOwnProperty.call(cloned, 'attestation_checks') && !cloned.attestationChecks) {
        const checks = cloned.attestation_checks;
        delete cloned.attestation_checks;
        if (checks && typeof checks === 'object') {
            cloned.attestationChecks = checks;
        }
    }

    return cloned;
}

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
        recordCandidate(info.authenticator_data);

        const registrationData = info.registrationData || info.registration_data;
        if (registrationData && typeof registrationData === 'object') {
            recordCandidate(registrationData.authenticatorData);
            recordCandidate(registrationData.authenticator_data);
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

    const cloned = cloneJson(info);
    if (!cloned || typeof cloned !== 'object') {
        if (authenticatorHex || summaryHash || fallbackAuthenticatorValue) {
            const minimal = {};
            if (authenticatorHex) {
                minimal.authenticatorData = authenticatorHex;
            } else if (fallbackAuthenticatorValue) {
                minimal.authenticatorData = fallbackAuthenticatorValue;
            }
            if (summaryHash) {
                minimal.authenticatorDataHash = summaryHash;
            }
            return Object.keys(minimal).length ? minimal : null;
        }
        return null;
    }

    stripCertificateCollections(cloned);
    removeKeysCaseInsensitive(cloned, RP_INFO_EXCLUDED_KEYS);

    let registrationData = null;
    if (cloned.registrationData && typeof cloned.registrationData === 'object') {
        registrationData = sanitiseRegistrationData(cloned.registrationData);
    } else if (cloned.registration_data && typeof cloned.registration_data === 'object') {
        registrationData = sanitiseRegistrationData(cloned.registration_data);
        delete cloned.registration_data;
    }

    if (registrationData) {
        cloned.registrationData = registrationData;
    } else if (Object.prototype.hasOwnProperty.call(cloned, 'registrationData')) {
        delete cloned.registrationData;
    }

    if (Object.prototype.hasOwnProperty.call(cloned, 'attestation_summary') && !cloned.attestationSummary) {
        const summaryValue = cloned.attestation_summary;
        delete cloned.attestation_summary;
        if (summaryValue && typeof summaryValue === 'object') {
            cloned.attestationSummary = summaryValue;
        }
    }

    if (
        !cloned.attestationSummary
        && registrationData
        && registrationData.attestationSummary
        && typeof registrationData.attestationSummary === 'object'
    ) {
        cloned.attestationSummary = cloneJson(registrationData.attestationSummary);
    }

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

    if (!cloned.rpIdHash && typeof cloned.rp_id_hash === 'string') {
        cloned.rpIdHash = cloned.rp_id_hash;
    }
    if (!cloned.rpIdHashBase64 && typeof cloned.rp_id_hash_base64 === 'string') {
        cloned.rpIdHashBase64 = cloned.rp_id_hash_base64;
    }
    if (!cloned.rpIdHashExpected && typeof cloned.rp_id_hash_expected === 'string') {
        cloned.rpIdHashExpected = cloned.rp_id_hash_expected;
    }
    if (!cloned.rpIdHashExpectedBase64 && typeof cloned.rp_id_hash_expected_base64 === 'string') {
        cloned.rpIdHashExpectedBase64 = cloned.rp_id_hash_expected_base64;
    }

    return cloned;
}

export function sanitizeParsedCertificateDetails(parsed) {
    if (!parsed || typeof parsed !== 'object') {
        return null;
    }

    const parsedCopy = cloneJson(parsed);
    if (!parsedCopy || typeof parsedCopy !== 'object') {
        return null;
    }

    ['pem', 'der', 'derBase64', 'der_base64', 'raw', 'summary', 'error'].forEach(key => {
        if (Object.prototype.hasOwnProperty.call(parsedCopy, key)) {
            delete parsedCopy[key];
        }
    });

    if (Array.isArray(parsedCopy.extensions)) {
        parsedCopy.extensions = parsedCopy.extensions
            .map(ext => {
                if (!ext || typeof ext !== 'object') {
                    return null;
                }

                const extCopy = cloneJson(ext);
                if (!extCopy || typeof extCopy !== 'object') {
                    return null;
                }

                ['raw', 'hex', 'rawHex', 'der', 'derBase64', 'der_base64', 'valueHex'].forEach(key => {
                    if (Object.prototype.hasOwnProperty.call(extCopy, key)) {
                        delete extCopy[key];
                    }
                });

                return extCopy;
            })
            .filter(Boolean);
    }

    return parsedCopy;
}

export function stripSignatureFormatting(target) {
    if (!target || typeof target !== 'object') {
        return;
    }

    const process = value => {
        if (value && typeof value === 'object') {
            stripSignatureFormatting(value);
        }
    };

    if (Array.isArray(target)) {
        target.forEach(process);
        return;
    }

    Object.keys(target).forEach(key => {
        const value = target[key];
        if ((key === 'signature' || key === 'sig') && value && typeof value === 'object') {
            if (Object.prototype.hasOwnProperty.call(value, 'colon')) {
                delete value.colon;
            }
            if (Object.prototype.hasOwnProperty.call(value, 'lines')) {
                delete value.lines;
            }
        }
        process(value);
    });
}
