import { state } from './state.js';
import {
    base64ToBase64Url,
    base64ToHex,
    base64ToUint8Array,
    base64UrlToHex,
    base64UrlToJson,
    base64UrlToUint8Array,
    base64UrlToUtf8String,
    bytesToHex,
    convertFormat,
    currentFormatToJsonFormat,
    hexToBase64,
    hexToBase64Url,
    hexToGuid,
    hexToUint8Array
} from './binary-utils.js';
import {
    describeCoseAlgorithm,
    describeCoseKeyType,
    describeMldsaParameterSet,
    escapeHtml,
    formatBoolean,
    renderAttestationResultRow
} from './display-utils.js';
import {
    deriveAaguidDisplayValues,
    deriveAaguidFromCredentialData,
    extractHexFromJsonFormat,
    extractMinPinLengthValue,
    getCredentialIdHex,
    getCredentialUserHandleHex,
    getCoseMapValue,
    getStoredCredentialAttachment,
    normaliseAaguidValue
} from './credential-utils.js';
import { openModal, closeModal, updateGlobalScrollLock, resetModalScroll } from './ui.js';
import { showStatus, hideStatus, showProgress, hideProgress } from './status.js';
import { updateJsonEditor } from './json-editor.js';
import { checkLargeBlobCapability, updateAuthenticationExtensionAvailability } from './forms.js';
import { collectSelectedHints, deriveAllowedAttachmentsFromHints } from './hints.js';
import { ATTACHMENT_LABELS } from './constants.js';

function appendKeyValueLines(output, value, indentLevel = 0) {
    if (value === null || value === undefined) {
        return;
    }

    const indent = '    '.repeat(indentLevel);

    if (typeof value === 'string' || typeof value === 'number') {
        if (String(value).trim() !== '') {
            output.push(`${indent}${value}`);
        }
        return;
    }

    if (typeof value === 'boolean') {
        output.push(`${indent}${value}`);
        return;
    }

    if (Array.isArray(value)) {
        if (value.length === 0) {
            return;
        }

        const filtered = value.filter(item => item !== null && item !== undefined);
        if (filtered.length === 0) {
            return;
        }

        const allScalars = filtered.every(item => {
            return (
                typeof item === 'string' ||
                typeof item === 'number' ||
                typeof item === 'boolean'
            );
        });

        if (allScalars) {
            filtered.forEach(item => {
                output.push(`${indent}${item}`);
            });
        } else {
            filtered.forEach(item => {
                if (item === null || item === undefined) {
                    return;
                }

                if (typeof item === 'object') {
                    output.push(`${indent}-`);
                    appendKeyValueLines(output, item, indentLevel + 1);
                } else {
                    output.push(`${indent}- ${item}`);
                }
            });
        }
        return;
    }

    if (typeof value === 'object') {
        const entries = Object.entries(value).filter(([key, val]) => {
            if (val === null || val === undefined || val === '') {
                return false;
            }
            if (typeof key === 'string' && key.toLowerCase().includes('base64')) {
                return false;
            }
            return true;
        });

        if (entries.length === 0) {
            return;
        }

        entries.forEach(([key, val]) => {
            if (typeof val === 'object') {
                if (Array.isArray(val)) {
                    if (val.length === 0) {
                        return;
                    }
                    output.push(`${indent}${key}:`);
                    appendKeyValueLines(output, val, indentLevel + 1);
                } else {
                    const nestedEntries = Object.entries(val).filter(([, nestedVal]) => nestedVal !== null && nestedVal !== undefined && nestedVal !== '');
                    if (nestedEntries.length === 0) {
                        return;
                    }
                    output.push(`${indent}${key}:`);
                    appendKeyValueLines(output, val, indentLevel + 1);
                }
            } else {
                output.push(`${indent}${key}: ${val}`);
            }
        });
        return;
    }

    output.push(`${indent}${String(value)}`);
}

function hexToColonLines(hexString, bytesPerLine = 16) {
    if (typeof hexString !== 'string') {
        return [];
    }
    let clean = hexString.replace(/[^0-9a-fA-F]/g, '').toLowerCase();
    if (!clean) {
        return [];
    }
    if (clean.length % 2 !== 0) {
        clean = `0${clean}`;
    }
    const pairs = [];
    for (let i = 0; i < clean.length; i += 2) {
        pairs.push(clean.slice(i, i + 2));
    }
    const output = [];
    for (let i = 0; i < pairs.length; i += bytesPerLine) {
        output.push(pairs.slice(i, i + bytesPerLine).join(':'));
    }
    return output;
}

function normalizeClientDataString(value) {
    if (typeof value !== 'string') {
        return '';
    }

    const trimmed = value.trim();
    if (!trimmed) {
        return '';
    }

    if (trimmed.includes('-') || trimmed.includes('_')) {
        return trimmed;
    }

    const base64Pattern = /^[A-Za-z0-9+/=]+$/;
    if (base64Pattern.test(trimmed)) {
        try {
            return base64ToBase64Url(trimmed);
        } catch (error) {
            return trimmed;
        }
    }

    return trimmed;
}

function cloneJson(value) {
    if (!value || typeof value !== 'object') {
        return null;
    }

    try {
        return JSON.parse(JSON.stringify(value));
    } catch (error) {
        return null;
    }
}

const CERTIFICATE_COLLECTION_KEYS = [
    'attestationCertificate',
    'attestationCertificates',
    'attestation_certificate',
    'attestation_certificates',
];

function stripCertificateCollections(target) {
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

const RP_INFO_EXCLUDED_KEYS = [
    'attestationFmt',
    'attestationObject',
    'credentialIdBase64',
    'credentialIdBase64Url',
    'device',
    'registrationData',
    'registration_data',
    'root_valid',
    'rp_id_hash_valid',
    'signature_valid',
    'attestationSummary',
    'attestation_summary',
    'authenticatorData',
    'authenticator_data',
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

function removeKeysFromObject(target, keys) {
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

function removeKeysCaseInsensitive(target, keys) {
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

function sanitizeRelyingPartyInfo(info) {
    const cloned = cloneJson(info);
    if (!cloned || typeof cloned !== 'object') {
        return null;
    }

    stripCertificateCollections(cloned);
    removeKeysCaseInsensitive(cloned, RP_INFO_EXCLUDED_KEYS);

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

    return cloned;
}

function sanitizeParsedCertificateDetails(parsed) {
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

function stripSignatureFormatting(target) {
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

function sanitiseAttestationObjectForDisplay(
    attestationObject,
    attestationFormatRaw = '',
    authenticatorDataHash = '',
    authenticatorDataHex = ''
) {
    const cloned = cloneJson(attestationObject);
    if (!cloned || typeof cloned !== 'object') {
        const minimal = {};
        const formatValue = typeof attestationFormatRaw === 'string' ? attestationFormatRaw.trim() : '';
        const hashValue = typeof authenticatorDataHash === 'string' ? authenticatorDataHash.trim() : '';
        const hexValue = typeof authenticatorDataHex === 'string' ? authenticatorDataHex.trim() : '';
        if (formatValue) minimal.fmt = formatValue;
        if (hashValue) minimal.authenticatorDataHash = hashValue;
        if (hexValue) minimal.authenticatorDataHex = hexValue;
        return Object.keys(minimal).length ? minimal : null;
    }

    const certificatesAll = Array.isArray(registrationDetailState.attestationCertificates)
        ? registrationDetailState.attestationCertificates
        : [];
    const { valid: certificateInfos, failures: parseFailureInfos } = partitionCertificateEntries(certificatesAll);
    const certificates = certificateInfos.length
        ? certificateInfos
        : parseFailureInfos;

    if (cloned.attStmt && typeof cloned.attStmt === 'object') {
        const attStmtClone = { ...cloned.attStmt };
        const sourceArray = Array.isArray(attStmtClone.x5c) ? attStmtClone.x5c : [];
        const maxLength = Math.max(sourceArray.length, certificates.length);

        if (maxLength > 0) {
            const sanitizedChain = [];

            for (let index = 0; index < maxLength; index += 1) {
                const info = certificates[index];
                const certificateEntry = info && typeof info === 'object' && info.entry ? info.entry : info;
                const sourceEntry = sourceArray[index];

                let parsedDetails = certificateEntry && typeof certificateEntry === 'object'
                    ? certificateEntry.parsedX5c
                    : null;

                if ((!parsedDetails || typeof parsedDetails !== 'object') && sourceEntry) {
                    const normalised = normaliseCertificateEntryForModal(sourceEntry);
                    if (normalised && typeof normalised.parsedX5c === 'object') {
                        parsedDetails = normalised.parsedX5c;
                    }
                }

                if (!parsedDetails || typeof parsedDetails !== 'object') {
                    continue;
                }

                const sanitizedDetails = sanitizeParsedCertificateDetails(parsedDetails);
                const summaryText = typeof parsedDetails.summary === 'string'
                    ? parsedDetails.summary.trim()
                    : '';
                const errorText = typeof parsedDetails.error === 'string'
                    ? parsedDetails.error.trim()
                    : '';

                const hasDetails = sanitizedDetails && Object.keys(sanitizedDetails).length > 0;
                if (!hasDetails && !summaryText && !errorText) {
                    continue;
                }

                const entry = {
                    certificateIndex: index + 1,
                };

                if (hasDetails) {
                    entry.details = sanitizedDetails;
                }

                if (summaryText) {
                    entry.summary = summaryText;
                }

                if (errorText) {
                    entry.error = errorText;
                }

                sanitizedChain.push(entry);
            }

            if (sanitizedChain.length) {
                attStmtClone.x5c = sanitizedChain;
            } else {
                delete attStmtClone.x5c;
            }
        } else {
            delete attStmtClone.x5c;
        }

        delete attStmtClone.x5cParseErrors;

        stripCertificateCollections(attStmtClone);
        removeKeysCaseInsensitive(attStmtClone, ['publicKeyHex', 'publicKeyHexLines', 'publicKeyBase64']);
        stripSignatureFormatting(attStmtClone);
        cloned.attStmt = attStmtClone;
    }

    stripCertificateCollections(cloned);
    removeKeysFromObject(cloned, ['summary', 'raw']);
    removeKeysCaseInsensitive(cloned, ['publicKeyHex', 'publicKeyHexLines', 'publicKeyBase64']);
    stripSignatureFormatting(cloned);

    let formatValue = typeof attestationFormatRaw === 'string' ? attestationFormatRaw.trim() : '';
    if (!formatValue && typeof cloned.fmt === 'string') {
        formatValue = cloned.fmt;
    }
    if (Object.prototype.hasOwnProperty.call(cloned, 'fmt')) {
        delete cloned.fmt;
    }

    const ordered = {};
    if (formatValue) {
        ordered.fmt = formatValue;
    }

    Object.keys(cloned).forEach(key => {
        ordered[key] = cloned[key];
    });

    const hashValue = typeof authenticatorDataHash === 'string' ? authenticatorDataHash.trim() : '';
    if (hashValue) {
        ordered.authenticatorDataHash = hashValue;
    }

    const hexValue = typeof authenticatorDataHex === 'string' ? authenticatorDataHex.trim() : '';
    if (hexValue) {
        ordered.authenticatorDataHex = hexValue;
    }

    return ordered;
}

const registrationDetailState = {
    attestationObject: null,
    attestationCertificates: [],
    visibleAttestationCertificateIndices: [],
    authenticatorData: null,
    authenticatorDataHash: '',
    authenticatorDataHex: '',
};

function resetRegistrationDetailState() {
    registrationDetailState.attestationObject = null;
    registrationDetailState.attestationCertificates = [];
    registrationDetailState.visibleAttestationCertificateIndices = [];
    registrationDetailState.authenticatorData = null;
    registrationDetailState.authenticatorDataHash = '';
    registrationDetailState.authenticatorDataHex = '';
}

function normaliseHexFingerprint(value) {
    if (typeof value !== 'string') {
        return '';
    }
    const trimmed = value.replace(/[^0-9a-fA-F]/g, '');
    return trimmed ? trimmed.toLowerCase() : '';
}

function normalisePemString(value) {
    if (typeof value !== 'string') {
        return '';
    }
    const stripped = value
        .replace(/-----BEGIN CERTIFICATE-----/g, '')
        .replace(/-----END CERTIFICATE-----/g, '')
        .replace(/\s+/g, '');
    return stripped.trim();
}

function deriveCertificateIdentity(entry) {
    if (!entry || typeof entry !== 'object') {
        return '';
    }

    const pickHexValue = candidate => {
        if (typeof candidate !== 'string') {
            return '';
        }
        const trimmed = candidate.replace(/\s+/g, '').toLowerCase();
        return trimmed ? trimmed : '';
    };

    const pickBase64Value = candidate => {
        if (typeof candidate !== 'string') {
            return '';
        }
        const stripped = candidate.replace(/[^A-Za-z0-9+/=]/g, '');
        return stripped.trim();
    };

    const directRaw = pickHexValue(entry.raw);
    if (directRaw) {
        return `raw:${directRaw}`;
    }

    const directPem = normalisePemString(entry.pem);
    if (directPem) {
        return `pem:${directPem}`;
    }

    const parsed = entry.parsedX5c && typeof entry.parsedX5c === 'object'
        ? entry.parsedX5c
        : entry.parsed && typeof entry.parsed === 'object'
            ? entry.parsed
            : null;

    if (parsed) {
        const parsedRaw = pickHexValue(parsed.raw);
        if (parsedRaw) {
            return `raw:${parsedRaw}`;
        }

        const parsedDer = pickBase64Value(parsed.derBase64 || parsed.der_base64);
        if (parsedDer) {
            return `der:${parsedDer}`;
        }

        const parsedPem = normalisePemString(parsed.pem);
        if (parsedPem) {
            return `pem:${parsedPem}`;
        }

        const fingerprints = parsed.fingerprints && typeof parsed.fingerprints === 'object'
            ? parsed.fingerprints
            : null;
        if (fingerprints) {
            const fingerprintOrder = ['sha256', 'sha1', 'md5'];
            for (const key of fingerprintOrder) {
                const value = normaliseHexFingerprint(fingerprints[key]);
                if (value) {
                    return `${key}:${value}`;
                }
            }
        }
    }

    return '';
}

function addCertificateEntryToState(entry) {
    const normalised = normaliseCertificateEntryForModal(entry);
    if (!normalised) {
        return;
    }

    const identity = deriveCertificateIdentity(normalised);
    const existing = registrationDetailState.attestationCertificates;

    if (identity) {
        const existingIndex = existing.findIndex(item => deriveCertificateIdentity(item) === identity);
        if (existingIndex !== -1) {
            const currentEntry = existing[existingIndex];
            const currentParsed = currentEntry && typeof currentEntry === 'object' && currentEntry.parsedX5c
                && typeof currentEntry.parsedX5c === 'object'
                ? currentEntry.parsedX5c
                : null;
            const newParsed = normalised.parsedX5c && typeof normalised.parsedX5c === 'object'
                ? normalised.parsedX5c
                : null;
            const currentHasError = Boolean(currentParsed && currentParsed.parseError);
            const newHasError = Boolean(newParsed && newParsed.parseError);

            if (currentHasError && !newHasError) {
                existing[existingIndex] = normalised;
            }
            return;
        }
    } else {
        const duplicate = existing.some(item => {
            if (item === normalised) {
                return true;
            }
            if (item.pem && normalised.pem && item.pem === normalised.pem) {
                return true;
            }
            if (item.raw && normalised.raw && item.raw === normalised.raw) {
                return true;
            }
            return false;
        });

        if (duplicate) {
            return;
        }
    }

    existing.push(normalised);
}

function addCertificatesToRegistrationState(entries) {
    if (!entries) {
        return;
    }
    if (Array.isArray(entries)) {
        entries.forEach(entry => addCertificateEntryToState(entry));
    } else {
        addCertificateEntryToState(entries);
    }
}

function normaliseCertificateEntryForModal(entry) {
    if (!entry || typeof entry !== 'object') {
        return null;
    }

    const normalised = {
        parsedX5c: {},
    };

    if (entry.parsedX5c && typeof entry.parsedX5c === 'object') {
        normalised.parsedX5c = entry.parsedX5c;
    } else if (entry.parsed && typeof entry.parsed === 'object') {
        normalised.parsedX5c = entry.parsed;
    } else if (typeof entry === 'object') {
        normalised.parsedX5c = entry;
    }

    const pemValue = entry.pem || entry.parsedX5c?.pem || entry.parsed?.pem;
    if (typeof pemValue === 'string' && pemValue.trim() !== '') {
        normalised.pem = pemValue.trim();
    }

    let rawHex = typeof entry.raw === 'string' && entry.raw.trim() !== '' ? entry.raw.trim() : null;
    if (!rawHex) {
        const derBase64 = entry.derBase64
            || entry.der_base64
            || entry.parsedX5c?.derBase64
            || entry.parsed?.derBase64;
        if (typeof derBase64 === 'string' && derBase64.trim() !== '') {
            try {
                rawHex = base64ToHex(derBase64.trim());
            } catch (error) {
                rawHex = null;
            }
        }
    }
    if (rawHex) {
        normalised.raw = rawHex;
    }

    return normalised;
}

function partitionCertificateEntries(entries) {
    const result = {
        valid: [],
        failures: [],
    };

    if (!Array.isArray(entries) || !entries.length) {
        return result;
    }

    entries.forEach((entry, index) => {
        if (!entry || typeof entry !== 'object') {
            return;
        }

        const parsed = entry.parsedX5c && typeof entry.parsedX5c === 'object'
            ? entry.parsedX5c
            : null;

        if (parsed && parsed.parseError) {
            result.failures.push({ entry, index, parsed });
        } else {
            result.valid.push({ entry, index, parsed });
        }
    });

    if (result.failures.length && result.valid.length) {
        const validIdentities = new Set(
            result.valid
                .map(info => deriveCertificateIdentity(info.entry))
                .filter(identity => identity)
        );

        if (validIdentities.size) {
            result.failures = result.failures.filter(info => {
                const identity = deriveCertificateIdentity(info.entry);
                if (!identity) {
                    return true;
                }
                return !validIdentities.has(identity);
            });
        }
    }

    return result;
}

function getVisibleAttestationCertificates() {
    const indices = Array.isArray(registrationDetailState.visibleAttestationCertificateIndices)
        ? registrationDetailState.visibleAttestationCertificateIndices
        : [];

    return indices
        .map(idx => registrationDetailState.attestationCertificates[idx])
        .filter(entry => entry && typeof entry === 'object');
}

async function computeAuthenticatorDataHash() {
    registrationDetailState.authenticatorDataHash = '';
    registrationDetailState.authenticatorDataHex = '';

    const data = registrationDetailState.authenticatorData;
    if (!data) {
        return '';
    }

    const hexCandidates = new Set();
    const base64UrlCandidates = new Set();
    const base64Candidates = new Set();

    const addCandidate = (collection, value) => {
        if (typeof value !== 'string') {
            return;
        }
        const trimmed = value.trim();
        if (trimmed) {
            collection.add(trimmed);
        }
    };

    if (typeof data === 'string') {
        addCandidate(hexCandidates, data);
        addCandidate(base64UrlCandidates, data);
        addCandidate(base64Candidates, data);
    } else if (typeof data === 'object') {
        ['raw', 'hex', 'rawHex', 'raw_hex', 'hexValue', 'value'].forEach(key => {
            addCandidate(hexCandidates, data[key]);
        });
        ['base64url', 'base64Url'].forEach(key => {
            addCandidate(base64UrlCandidates, data[key]);
        });
        addCandidate(base64Candidates, data.base64);
    }

    let bytes = null;

    const recordHexCandidate = value => {
        if (registrationDetailState.authenticatorDataHex) {
            return;
        }
        if (typeof value !== 'string') {
            return;
        }
        const trimmed = value.trim();
        if (!trimmed) {
            return;
        }
        registrationDetailState.authenticatorDataHex = trimmed.toLowerCase();
    };

    for (const candidate of hexCandidates) {
        const normalized = candidate.replace(/[^0-9a-f]/gi, '').toLowerCase();
        if (!normalized || normalized.length % 2 !== 0) {
            continue;
        }
        const converted = hexToUint8Array(normalized);
        if (converted && converted.length) {
            recordHexCandidate(normalized);
            bytes = converted;
            break;
        }
    }

    if (!bytes) {
        for (const candidate of base64UrlCandidates) {
            const converted = base64UrlToUint8Array(candidate);
            if (converted && converted.length) {
                recordHexCandidate(bytesToHex(converted));
                bytes = converted;
                break;
            }
        }
    }

    if (!bytes) {
        for (const candidate of base64Candidates) {
            const converted = base64ToUint8Array(candidate);
            if (converted && converted.length) {
                recordHexCandidate(bytesToHex(converted));
                bytes = converted;
                break;
            }
        }
    }

    if (!bytes || !bytes.length) {
        return '';
    }

    if (!registrationDetailState.authenticatorDataHex) {
        registrationDetailState.authenticatorDataHex = bytesToHex(bytes);
    }

    if (!window.crypto || !window.crypto.subtle || typeof window.crypto.subtle.digest !== 'function') {
        return '';
    }

    try {
        const digestBuffer = await window.crypto.subtle.digest('SHA-256', bytes);
        const hashHex = bytesToHex(new Uint8Array(digestBuffer));
        registrationDetailState.authenticatorDataHash = hashHex;
        return hashHex;
    } catch (error) {
        registrationDetailState.authenticatorDataHash = '';
        return '';
    }
}

async function prepareRegistrationDetailState(options = {}) {
    const {
        attestationObjectValue = '',
        attestationObjectDecoded = null,
        authenticatorDataValue = '',
        fallbackCertificates = [],
        relyingPartyInfo = null,
    } = options || {};

    resetRegistrationDetailState();

    const attestationValue = typeof attestationObjectValue === 'string'
        ? attestationObjectValue.trim()
        : '';
    const authenticatorValue = typeof authenticatorDataValue === 'string'
        ? authenticatorDataValue.trim()
        : '';

    let attestationDecodeError = '';
    let authenticatorDecodeError = '';

    if (attestationValue) {
        try {
            const decoded = await decodePayloadThroughApi(attestationValue);
            const attestationData = decoded?.data?.attestationObject || decoded?.data || null;
            if (attestationData && typeof attestationData === 'object') {
                registrationDetailState.attestationObject = attestationData;
                if (attestationData.attStmt && typeof attestationData.attStmt === 'object') {
                    addCertificatesToRegistrationState(attestationData.attStmt.x5c);
                }
            }
            if (decoded?.data?.authenticatorData) {
                registrationDetailState.authenticatorData = decoded.data.authenticatorData;
            }
        } catch (error) {
            attestationDecodeError = error?.message || 'Failed to decode attestationObject.';
        }
    }

    const decodedObject = attestationObjectDecoded && typeof attestationObjectDecoded === 'object'
        ? attestationObjectDecoded
        : null;
    if (!registrationDetailState.attestationObject && decodedObject) {
        registrationDetailState.attestationObject = decodedObject;
        const attStmt = decodedObject.attStmt || decodedObject.att_statement || null;
        if (attStmt && typeof attStmt === 'object') {
            addCertificatesToRegistrationState(attStmt.x5c || attStmt.X5C || []);
        }
    }

    if (fallbackCertificates) {
        addCertificatesToRegistrationState(fallbackCertificates);
    }

    if (!registrationDetailState.attestationCertificates.length && relyingPartyInfo?.attestationCertificate) {
        addCertificatesToRegistrationState(relyingPartyInfo.attestationCertificate);
    }
    if (!registrationDetailState.attestationCertificates.length && Array.isArray(relyingPartyInfo?.attestationCertificates)) {
        addCertificatesToRegistrationState(relyingPartyInfo.attestationCertificates);
    }

    if (!registrationDetailState.authenticatorData && authenticatorValue) {
        try {
            const decodedAuth = await decodePayloadThroughApi(authenticatorValue);
            if (decodedAuth?.data) {
                registrationDetailState.authenticatorData = decodedAuth.data;
            }
        } catch (error) {
            authenticatorDecodeError = error?.message || 'Failed to decode authenticatorData.';
        }
    }

    if (!registrationDetailState.authenticatorData && authenticatorValue) {
        const fallback = { base64url: authenticatorValue };
        try {
            fallback.raw = base64UrlToHex(authenticatorValue);
        } catch (error) {
            fallback.raw = authenticatorValue;
        }
        registrationDetailState.authenticatorData = fallback;
    }

    await computeAuthenticatorDataHash();

    return {
        attestationObjectValue: attestationValue,
        attestationDecodeError,
        authenticatorDataValue: authenticatorValue,
        authenticatorDecodeError,
    };
}

function buildAttestationSection({
    attestationObjectValue = '',
    attestationDecodeError = '',
    attestationFormatRaw = '',
    attestationStatement = null,
    authenticatorDataValue = '',
    authenticatorDecodeError = '',
} = {}) {
    const attestationObject = registrationDetailState.attestationObject;
    const attestationFormatNormalized = typeof attestationFormatRaw === 'string'
        ? attestationFormatRaw.trim().toLowerCase()
        : '';
    const attestationStatementObject = attestationStatement && typeof attestationStatement === 'object'
        ? attestationStatement
        : attestationObject && typeof attestationObject.attStmt === 'object'
            ? attestationObject.attStmt
            : null;
    const attestationStatementHasContent = attestationStatementObject && Object.keys(attestationStatementObject).length > 0;

    const certificatesAll = Array.isArray(registrationDetailState.attestationCertificates)
        ? registrationDetailState.attestationCertificates
        : [];
    const { valid: certificateInfos } = partitionCertificateEntries(certificatesAll);
    const attestationHasCertificates = certificateInfos.length > 0;

    registrationDetailState.visibleAttestationCertificateIndices = certificateInfos.map(info => info.index);

    const hasAttestationObject = Boolean(attestationObject);
    const hasAttestationValue = typeof attestationObjectValue === 'string'
        ? attestationObjectValue.trim() !== ''
        : false;

    const shouldShowAttestationSection = hasAttestationObject
        || hasAttestationValue
        || (attestationFormatNormalized && attestationFormatNormalized !== 'none')
        || attestationStatementHasContent
        || attestationHasCertificates;

    const hasAuthenticatorData = Boolean(registrationDetailState.authenticatorData);
    const authenticatorButtonMarkup = hasAuthenticatorData
        ? '<button type="button" class="btn btn-small btn-secondary registration-authenticator-data-button">Authenticator Data</button>'
        : '';
    const shouldShowAuthenticatorError = !hasAuthenticatorData && authenticatorDataValue && authenticatorDecodeError;

    let attestationSectionHtml = '';

    if (shouldShowAttestationSection) {
        let attestationContent = '';
        const attestationHeading = '<h4 style="font-weight: 600; color: #0f2740; margin-bottom: 0.5rem;">Attestation Object</h4>';
        if (attestationObject) {
            let attestationJson = '';
            const attestationDisplay = sanitiseAttestationObjectForDisplay(
                attestationObject,
                attestationFormatRaw,
                typeof registrationDetailState.authenticatorDataHash === 'string'
                    ? registrationDetailState.authenticatorDataHash
                    : '',
                typeof registrationDetailState.authenticatorDataHex === 'string'
                    ? registrationDetailState.authenticatorDataHex
                    : ''
            ) || attestationObject;
            try {
                attestationJson = JSON.stringify(attestationDisplay, null, 2);
            } catch (error) {
                attestationJson = '';
            }

            if (!attestationJson && attestationObject) {
                try {
                    attestationJson = JSON.stringify(attestationObject, null, 2);
                } catch (jsonError) {
                    attestationJson = '';
                }
            }

            const attestationBody = attestationJson
                ? `<textarea class="certificate-textarea" readonly spellcheck="false" wrap="soft">${escapeHtml(attestationJson)}</textarea>`
                : '<div style="font-style: italic; color: #6c757d;">Unable to prepare decoded attestationObject.</div>';

            attestationContent = `
                <div style="margin-bottom: 0.75rem;">
                    ${attestationHeading}
                    ${attestationBody}
                </div>
            `;
        } else if (attestationObjectValue) {
            const message = attestationDecodeError || 'Unable to decode attestationObject.';
            attestationContent = `
                <div style="margin-bottom: 0.75rem;">
                    ${attestationHeading}
                    <div style="color: #dc3545; font-size: 0.9rem;">${escapeHtml(message)}</div>
                </div>
            `;
        } else {
            attestationContent = `
                <div style="margin-bottom: 0.75rem;">
                    ${attestationHeading}
                    <div style="font-style: italic; color: #6c757d;">No attestationObject was provided.</div>
                </div>
            `;
        }

        const buttonRowSegments = [];
        let certificateMessageHtml = '';

        if (attestationHasCertificates) {
            certificateInfos.forEach((info, displayIndex) => {
                buttonRowSegments.push(`<button type="button" class="btn btn-small registration-attestation-cert-button" data-cert-index="${displayIndex}">Attestation Certificate ${displayIndex + 1}</button>`);
            });
        } else if ((attestationFormatNormalized && attestationFormatNormalized !== 'none') || attestationStatementHasContent) {
            certificateMessageHtml = '<div style="font-style: italic; color: #6c757d; margin-top: 0.75rem;">No attestation certificates available.</div>';
        }

        if (authenticatorButtonMarkup) {
            buttonRowSegments.push(authenticatorButtonMarkup);
        }

        const buttonRowHtml = buttonRowSegments.length
            ? `<div class="registration-detail-button-row">${buttonRowSegments.join('')}</div>`
            : '';

        const authenticatorMessageHtml = shouldShowAuthenticatorError
            ? `<div style="color: #dc3545; font-size: 0.9rem; margin-top: 0.75rem;">${escapeHtml(authenticatorDecodeError)}</div>`
            : '';

        attestationSectionHtml = `
            <section style="margin-bottom: 1.5rem;">
                <h3 style="color: #0072CE; margin-bottom: 0.75rem;">Attestation and Authenticator Data</h3>
                ${attestationContent}
                ${buttonRowHtml}
                ${certificateMessageHtml}
                ${authenticatorMessageHtml}
            </section>
        `;
    } else if (authenticatorButtonMarkup || shouldShowAuthenticatorError) {
        const buttonRowHtml = authenticatorButtonMarkup
            ? `<div class="registration-detail-button-row registration-detail-button-row--solo">${authenticatorButtonMarkup}</div>`
            : '';
        const authenticatorMessageHtml = shouldShowAuthenticatorError
            ? `<div style="color: #dc3545; font-size: 0.9rem; ${authenticatorButtonMarkup ? 'margin-top: 0.75rem;' : ''}">${escapeHtml(authenticatorDecodeError)}</div>`
            : '';

        attestationSectionHtml = `
            <section style="margin-bottom: 1.5rem;">
                ${buttonRowHtml}
                ${authenticatorMessageHtml}
            </section>
        `;
    }

    return attestationSectionHtml;
}

async function composeRegistrationDetailHtml({
    credentialJson = null,
    relyingPartyInfo = null,
    attestationObjectValue = '',
    attestationObjectDecoded = null,
    authenticatorDataValue = '',
    authenticatorDataHex = '',
    fallbackCertificates = [],
    fallbackClientData = null,
    fallbackParsedClientData = null,
    includeAttestationSection = true,
} = {}) {
    resetRegistrationDetailState();

    const credentialDisplay = credentialJson && typeof credentialJson === 'object'
        ? JSON.stringify(credentialJson, null, 2)
        : '';

    const fallbackClientDataString = typeof fallbackClientData === 'string'
        ? fallbackClientData.trim()
        : '';
    const normalizedFallbackClientData = fallbackClientDataString
        ? normalizeClientDataString(fallbackClientDataString)
        : '';

    let clientDataBase64 = credentialJson?.response?.clientDataJSON;
    if (!clientDataBase64 && normalizedFallbackClientData) {
        clientDataBase64 = normalizedFallbackClientData;
    }

    let parsedClientData = null;
    if (clientDataBase64) {
        parsedClientData = base64UrlToJson(clientDataBase64);
    }

    if (!parsedClientData && fallbackParsedClientData && typeof fallbackParsedClientData === 'object') {
        parsedClientData = fallbackParsedClientData;
    }

    let clientDataDisplay = '';
    if (parsedClientData) {
        clientDataDisplay = JSON.stringify(parsedClientData, null, 2);
    } else if (clientDataBase64) {
        clientDataDisplay = base64UrlToUtf8String(clientDataBase64) || clientDataBase64;
    } else if (fallbackClientDataString) {
        clientDataDisplay = fallbackClientDataString;
    } else if (fallbackParsedClientData && typeof fallbackParsedClientData === 'object') {
        clientDataDisplay = JSON.stringify(fallbackParsedClientData, null, 2);
    }

    const relyingPartyCopy = sanitizeRelyingPartyInfo(relyingPartyInfo);

    const relyingPartyDisplay = relyingPartyCopy
        ? JSON.stringify(relyingPartyCopy, null, 2)
        : '';

    const credentialSection = credentialDisplay
        ? `<pre class="modal-pre">${escapeHtml(credentialDisplay)}</pre>`
        : '<div style="font-style: italic; color: #6c757d;">No credential response captured.</div>';

    const clientDataSection = clientDataDisplay
        ? `<pre class="modal-pre">${escapeHtml(clientDataDisplay)}</pre>`
        : '<div style="font-style: italic; color: #6c757d;">No clientDataJSON available.</div>';

    const relyingPartySection = relyingPartyDisplay
        ? `<pre class="modal-pre">${escapeHtml(relyingPartyDisplay)}</pre>`
        : '<div style="font-style: italic; color: #6c757d;">No relying party data returned.</div>';

    let html = `
        <section style="margin-bottom: 1.5rem;">
            <h3 style="color: #0072CE; margin-bottom: 0.75rem;">Authenticator Response</h3>
            <ol style="padding-left: 1.25rem; margin: 0;">
                <li style="margin-bottom: 1rem;">
                    <div style="font-weight: 600; margin-bottom: 0.5rem;">Result of navigator.credentials.create()</div>
                    ${credentialSection}
                </li>
                <li>
                    <div style="font-weight: 600; margin-bottom: 0.5rem;">Parsed clientDataJSON response</div>
                    ${clientDataSection}
                </li>
            </ol>
        </section>
        <section style="margin-bottom: 1.5rem;">
            <h3 style="color: #0072CE; margin-bottom: 0.75rem;">Relying Party extracted information</h3>
            ${relyingPartySection}
        </section>
    `;

    const detailPreparation = await prepareRegistrationDetailState({
        attestationObjectValue,
        attestationObjectDecoded,
        authenticatorDataValue,
        fallbackCertificates,
        relyingPartyInfo,
    });

    const authDataState = registrationDetailState.authenticatorData;
    if (authDataState) {
        if (detailPreparation.authenticatorDataValue && typeof authDataState.base64url !== 'string') {
            authDataState.base64url = detailPreparation.authenticatorDataValue;
        }
        if (authenticatorDataHex && typeof authDataState.raw !== 'string') {
            authDataState.raw = authenticatorDataHex;
        }
    } else if (detailPreparation.authenticatorDataValue || authenticatorDataHex) {
        registrationDetailState.authenticatorData = {};
        if (detailPreparation.authenticatorDataValue) {
            registrationDetailState.authenticatorData.base64url = detailPreparation.authenticatorDataValue;
        }
        if (authenticatorDataHex) {
            registrationDetailState.authenticatorData.raw = authenticatorDataHex;
        }
    }

    const attestationObject = registrationDetailState.attestationObject;
    const attestationFormatFromRp = typeof relyingPartyInfo?.attestationFmt === 'string'
        ? relyingPartyInfo.attestationFmt
        : '';
    const attestationFormatFromObject = attestationObject && typeof attestationObject.fmt === 'string'
        ? attestationObject.fmt
        : attestationObjectDecoded && typeof attestationObjectDecoded === 'object' && typeof attestationObjectDecoded.fmt === 'string'
            ? attestationObjectDecoded.fmt
            : '';
    const attestationFormatRaw = attestationFormatFromRp || attestationFormatFromObject || '';
    const attestationStatement = attestationObject && typeof attestationObject.attStmt === 'object'
        ? attestationObject.attStmt
        : attestationObjectDecoded && typeof attestationObjectDecoded === 'object' && typeof attestationObjectDecoded.attStmt === 'object'
            ? attestationObjectDecoded.attStmt
            : null;

    const attestationSectionHtml = buildAttestationSection({
        attestationObjectValue: detailPreparation.attestationObjectValue,
        attestationDecodeError: detailPreparation.attestationDecodeError,
        attestationFormatRaw,
        attestationStatement,
        authenticatorDataValue: detailPreparation.authenticatorDataValue,
        authenticatorDecodeError: detailPreparation.authenticatorDecodeError,
    });

    if (includeAttestationSection && attestationSectionHtml) {
        html += attestationSectionHtml;
    }

    return {
        html,
        attestationSectionHtml,
    };
}

function bindRegistrationDetailButtons(scope) {
    if (!scope) {
        return;
    }

    const certificateButtons = scope.querySelectorAll('.registration-attestation-cert-button');
    certificateButtons.forEach(button => {
        button.addEventListener('click', event => {
            event.preventDefault();
            const indexValue = Number(button.getAttribute('data-cert-index'));
            if (!Number.isNaN(indexValue)) {
                openAttestationCertificateDetail(indexValue);
            }
        });
    });

    const authenticatorButtonEl = scope.querySelector('.registration-authenticator-data-button');
    if (authenticatorButtonEl) {
        authenticatorButtonEl.addEventListener('click', event => {
            event.preventDefault();
            openAuthenticatorDataDetail();
        });
    }
}

export function formatCertificateDetails(details) {
    if (!details || typeof details !== 'object') {
        return '';
    }

    if (typeof details.summary === 'string' && details.summary.trim() !== '') {
        return details.summary.trim();
    }

    const lines = [];
    const addLine = line => lines.push(line);
    const addBlankLine = () => {
        if (lines.length && lines[lines.length - 1] !== '') {
            lines.push('');
        }
    };

    const { version } = details;
    if (version) {
        if (typeof version === 'object') {
            const parts = [];
            if (typeof version.display === 'string' && version.display.trim() !== '') {
                parts.push(version.display.trim());
            }
            if (typeof version.hex === 'string' && version.hex.trim() !== '') {
                if (!parts.length || parts[parts.length - 1] !== version.hex.trim()) {
                    parts.push(version.hex.trim());
                }
            }
            if (parts.length > 0) {
                addLine(`Version: ${parts.join(' ')}`);
            }
        } else if (String(version).trim() !== '') {
            addLine(`Version: ${version}`);
        }
    }

    const serialNumber = details.serialNumber;
    if (serialNumber) {
        if (typeof serialNumber === 'object') {
            const parts = [];
            if (typeof serialNumber.decimal === 'string' && serialNumber.decimal.trim() !== '') {
                parts.push(serialNumber.decimal.trim());
            }
            if (typeof serialNumber.hex === 'string' && serialNumber.hex.trim() !== '') {
                parts.push(serialNumber.hex.trim());
            }
            if (parts.length > 0) {
                addLine(`Certificate Serial Number: ${parts.join(' / ')}`);
            }
        } else if (String(serialNumber).trim() !== '') {
            addLine(`Certificate Serial Number: ${serialNumber}`);
        }
    }

    if (typeof details.signatureAlgorithm === 'string' && details.signatureAlgorithm.trim() !== '') {
        addLine(`Signature Algorithm: ${details.signatureAlgorithm.trim()}`);
    }

    if (typeof details.issuer === 'string' && details.issuer.trim() !== '') {
        addLine(`Issuer: ${details.issuer.trim()}`);
    }

    const validity = details.validity;
    if (validity && (validity.notBefore || validity.notAfter)) {
        addBlankLine();
        addLine('Validity:');
        if (validity.notBefore) {
            addLine(`    Not Before: ${validity.notBefore}`);
        }
        if (validity.notAfter) {
            addLine(`    Not After: ${validity.notAfter}`);
        }
    }

    if (typeof details.subject === 'string' && details.subject.trim() !== '') {
        addBlankLine();
        addLine(`Subject: ${details.subject.trim()}`);
    }

    if (details.publicKeyInfo && typeof details.publicKeyInfo === 'object') {
        addBlankLine();
        addLine('Subject Public Key Info:');
        appendKeyValueLines(lines, details.publicKeyInfo, 1);
    }

    if (Array.isArray(details.extensions) && details.extensions.length) {
        addBlankLine();
        addLine('X509v3 extensions:');
        details.extensions.forEach(ext => {
            if (!ext || typeof ext !== 'object') {
                return;
            }

            const includeOid = ext.includeOidInHeader === undefined
                ? true
                : Boolean(ext.includeOidInHeader);
            const headerOverride = typeof ext.displayHeader === 'string'
                ? ext.displayHeader.trim()
                : '';
            const oid = typeof ext.oid === 'string' ? ext.oid.trim() : '';
            const friendlyName = typeof ext.friendlyName === 'string'
                ? ext.friendlyName.trim()
                : '';
            const extName = typeof ext.name === 'string' ? ext.name.trim() : '';

            let header = headerOverride;
            if (!header) {
                const headerParts = [];
                if (includeOid && oid) {
                    headerParts.push(oid);
                }

                let displayName = friendlyName;
                if (!displayName && extName && extName !== oid) {
                    displayName = extName;
                }

                if (displayName) {
                    if (includeOid && headerParts.length) {
                        headerParts.push(`(${displayName})`);
                    } else {
                        headerParts.push(displayName);
                    }
                }

                if (!headerParts.length) {
                    if (extName) {
                        headerParts.push(extName);
                    } else if (oid) {
                        headerParts.push(oid);
                    } else {
                        headerParts.push('Extension');
                    }
                }

                header = headerParts.join(' ');
            }

            if (ext.critical) {
                header = `${header} [critical]`;
            }

            addLine(`    ${header}:`);
            if ('value' in ext) {
                appendKeyValueLines(lines, ext.value, 2);
            }
        });
    }

    if (details.signature && typeof details.signature === 'object') {
        const algorithm = typeof details.signature.algorithm === 'string'
            ? details.signature.algorithm.trim()
            : '';
        const signatureLines = Array.isArray(details.signature.lines)
            ? details.signature.lines.filter(line => typeof line === 'string' && line.trim() !== '')
            : [];
        const signatureColon = typeof details.signature.colon === 'string'
            ? details.signature.colon.trim()
            : '';

        if (algorithm || signatureLines.length || signatureColon) {
            addBlankLine();
            const algorithmLabel = algorithm || (typeof details.signatureAlgorithm === 'string' ? details.signatureAlgorithm.trim() : 'Signature');
            addLine(`Signature Algorithm: ${algorithmLabel}`);
            if (signatureLines.length) {
                signatureLines.forEach(line => addLine(`    ${line}`));
            } else if (signatureColon) {
                addLine(`    ${signatureColon}`);
            }
        }
    }

    if (details.fingerprints && typeof details.fingerprints === 'object') {
        const fingerprintEntries = Object.entries(details.fingerprints)
            .filter(([, value]) => typeof value === 'string' && value.trim() !== '');

        if (fingerprintEntries.length) {
            addBlankLine();
            addLine('Fingerprint:');
            fingerprintEntries.forEach(([algorithm, value]) => {
                const label = typeof algorithm === 'string' && algorithm.trim() !== ''
                    ? algorithm.trim().toUpperCase()
                    : 'VALUE';
                const colonLines = hexToColonLines(value);
                addLine(`    ${label}:`);
                if (colonLines.length) {
                    colonLines.forEach(line => addLine(`        ${line}`));
                } else {
                    addLine(`        ${value}`);
                }
            });
        }
    }

    const formatted = lines.join('\n').trim();
    return formatted;
}

export function autoResizeCertificateTextareas(context) {
    const scope = context && typeof context.querySelectorAll === 'function'
        ? context
        : document;
    const textareas = scope.querySelectorAll('.certificate-textarea');
    textareas.forEach(textarea => {
        if (!(textarea instanceof HTMLTextAreaElement)) {
            return;
        }

        const resizeOnce = () => {
            textarea.style.height = 'auto';
            textarea.style.overflowY = 'hidden';
            textarea.style.overflowX = 'hidden';
            const measuredHeight = textarea.scrollHeight;
            if (Number.isFinite(measuredHeight) && measuredHeight > 0) {
                textarea.style.height = `${measuredHeight}px`;
            } else {
                textarea.style.height = '';
            }
        };

        resizeOnce();

        if (typeof requestAnimationFrame === 'function') {
            requestAnimationFrame(resizeOnce);
        }

        setTimeout(resizeOnce, 150);
    });
}

function openRegistrationDetailModal(title, bodyHtml) {
    const modal = document.getElementById('registrationDetailModal');
    const titleEl = document.getElementById('registrationDetailModalTitle');
    const bodyEl = document.getElementById('registrationDetailModalBody');
    if (!modal || !titleEl || !bodyEl) {
        return;
    }

    titleEl.textContent = title;
    bodyEl.innerHTML = bodyHtml;
    openModal('registrationDetailModal');

    const resize = () => autoResizeCertificateTextareas(bodyEl);
    if (typeof requestAnimationFrame === 'function') {
        requestAnimationFrame(resize);
    } else {
        setTimeout(resize, 0);
    }
}

function openAttestationCertificateDetail(index) {
    const visibleCertificates = getVisibleAttestationCertificates();
    const certificate = visibleCertificates[index];
    const normalised = normaliseCertificateEntryForModal(certificate);
    if (!normalised) {
        return;
    }

    const parsed = normalised.parsedX5c && typeof normalised.parsedX5c === 'object'
        ? normalised.parsedX5c
        : {};
    const sections = [];
    const errorMessage = typeof parsed.error === 'string' && parsed.error.trim() !== ''
        ? parsed.error.trim()
        : '';
    const summary = formatCertificateDetails(parsed);

    if (summary && summary.trim() !== '') {
        sections.push(`<textarea class="certificate-textarea" readonly spellcheck="false" wrap="soft">${escapeHtml(summary)}</textarea>`);
    } else if (errorMessage) {
        sections.push(`<div style="color: #dc3545; font-size: 0.9rem;">${escapeHtml(errorMessage)}</div>`);
    } else {
        sections.push('<div style="font-style: italic; color: #6c757d;">No decoded certificate details available.</div>');
    }

    openRegistrationDetailModal(`Attestation Certificate ${index + 1}`, sections.join(''));
}

function openAuthenticatorDataDetail() {
    const data = registrationDetailState.authenticatorData;
    if (!data) {
        return;
    }

    const sections = [];
    const rawHex = typeof data.raw === 'string' && data.raw.trim() !== '' ? data.raw.trim() : null;
    if (rawHex) {
        sections.push('<h4 style="margin-bottom: 0.5rem;">Raw authenticatorData (hex)</h4>');
        sections.push(`<pre class="modal-pre">${escapeHtml(rawHex)}</pre>`);
    }

    sections.push('<h4 style="margin-top: 1rem; margin-bottom: 0.5rem;">Decoded authenticatorData</h4>');
    const jsonString = escapeHtml(JSON.stringify(data, null, 2));
    sections.push(`<textarea class="certificate-textarea" readonly spellcheck="false" wrap="soft">${jsonString}</textarea>`);

    openRegistrationDetailModal('Authenticator Data', sections.join(''));
}

export function closeRegistrationDetailModal() {
    closeModal('registrationDetailModal');
}

export function updateAllowCredentialsDropdown() {
    const allowCredentialsSelect = document.getElementById('allow-credentials');
    if (!allowCredentialsSelect) return;

    const currentValue = allowCredentialsSelect.value;

    allowCredentialsSelect.innerHTML = `
        <option value="all">All credentials</option>
        <option value="empty">Empty (resident key only)</option>
    `;

    const selectedHints = collectSelectedHints ? collectSelectedHints('registration') : [];
    let attachmentFilters = deriveAllowedAttachmentsFromHints(selectedHints);
    if (!attachmentFilters.length) {
        const attachmentSelect = document.getElementById('authenticator-attachment');
        const attachmentPreference = attachmentSelect ? attachmentSelect.value : '';
        if (attachmentPreference === 'platform' || attachmentPreference === 'cross-platform') {
            attachmentFilters = [attachmentPreference];
        }
    }

    const matchesAttachmentPreference = attachmentValue => {
        if (!attachmentFilters.length) {
            return true;
        }
        if (typeof attachmentValue !== 'string' || !attachmentValue.trim()) {
            return false;
        }
        return attachmentFilters.includes(attachmentValue.trim().toLowerCase());
    };

    if (state.storedCredentials && state.storedCredentials.length > 0) {
        state.storedCredentials.forEach((cred, index) => {
            const credentialIdHex = cred.credentialIdHex || getCredentialIdHex(cred);
            if (!credentialIdHex) {
                return;
            }

            const attachmentValue = getStoredCredentialAttachment(cred);
            if (!matchesAttachmentPreference(attachmentValue)) {
                return;
            }

            const credName = cred.userName || cred.email || `Credential ${index + 1}`;
            const algorithmValue = cred.publicKeyAlgorithm ?? cred.algorithm;
            const algorithmLabel = describeCoseAlgorithm(algorithmValue) || 'Unknown';
            const attachmentLabel = attachmentValue
                ? (ATTACHMENT_LABELS[attachmentValue] || attachmentValue)
                : '';
            const labelSuffix = attachmentLabel ? ` • ${attachmentLabel}` : '';

            const option = document.createElement('option');
            option.value = credentialIdHex;
            option.textContent = `${credName} (${algorithmLabel})${labelSuffix}`;
            option.dataset.attachment = attachmentValue || '';
            allowCredentialsSelect.appendChild(option);
        });
    }

    const availableValues = new Set(Array.from(allowCredentialsSelect.options).map(opt => opt.value));
    const desiredValue = availableValues.has(currentValue) ? currentValue : 'all';
    if (allowCredentialsSelect.value !== desiredValue) {
        allowCredentialsSelect.value = desiredValue;
        try {
            allowCredentialsSelect.dispatchEvent(new Event('change', { bubbles: true }));
        } catch (error) {
            const changeEvent = document.createEvent('Event');
            changeEvent.initEvent('change', true, true);
            allowCredentialsSelect.dispatchEvent(changeEvent);
        }
    }
}

export async function loadSavedCredentials() {
    try {
        const response = await fetch('/api/credentials', {
            method: 'GET',
            headers: {'Content-Type': 'application/json'}
        });

        if (response.ok) {
            const credentials = await response.json();
            const normalizedCredentials = Array.isArray(credentials)
                ? credentials.map(cred => ({
                    ...cred,
                    credentialIdHex: getCredentialIdHex(cred),
                    userHandleHex: getCredentialUserHandleHex(cred),
                }))
                : [];
            state.storedCredentials = normalizedCredentials;
            updateCredentialsDisplay();
            updateJsonEditor();
        }
    } catch (error) {
        // Silently fail
    }
}

export function updateCredentialsDisplay() {
    const clearButton = document.getElementById('clear-credentials');
    if (clearButton) {
        clearButton.disabled = state.storedCredentials.length === 0;
    }

    const credentialsList = document.getElementById('credentials-list');

    if (!credentialsList) {
        return;
    }

    if (!state.storedCredentials.length) {
        credentialsList.innerHTML = '<p style="color: #6c757d; font-style: normal;">No credentials registered yet.</p>';
        checkLargeBlobCapability();
        updateAllowCredentialsDropdown();
        updateAuthenticationExtensionAvailability();
        return;
    }

    credentialsList.innerHTML = state.storedCredentials.map((cred, index) => {
        const features = [];
        if (cred.residentKey === true || cred.discoverable === true) {
            features.push('Discoverable');
        }
        if (cred.largeBlob === true || cred.largeBlobSupported === true) {
            features.push('largeBlob');
        }
        const algorithmValue = cred.publicKeyAlgorithm ?? cred.algorithm;
        if (describeMldsaParameterSet(algorithmValue)) {
            features.push('PQC');
        }

        const featureText = features.length > 0 ? features.join(' • ') : '';

        return `
        <div class="credential-item" role="button" tabindex="0" onclick="showCredentialDetails(${index})" onkeydown="if(event.key==='Enter'||event.key===' '){event.preventDefault();showCredentialDetails(${index});}">
            <div style="flex: 1; min-width: 0;">
                <div style="font-weight: 600; color: #0f2740; font-size: 0.95rem; margin-bottom: 0.25rem;">${cred.email || cred.username || 'Unknown User'}</div>
                ${featureText ? `<div style="font-size: 0.75rem; color: #5c6c7a;">${featureText}</div>` : ''}
            </div>
            <button class="btn btn-small btn-danger" onclick="event.stopPropagation();deleteCredential('${cred.email || cred.username}', ${index})">Delete</button>
        </div>
        `;
    }).join('');

    checkLargeBlobCapability();
    updateAllowCredentialsDropdown();
    updateAuthenticationExtensionAvailability();
}

function setAaguidStatus(statusEl, message, { showSpinner = false } = {}) {
    if (!(statusEl instanceof HTMLElement)) {
        return;
    }

    statusEl.dataset.active = 'true';
    const spinner = statusEl.querySelector('.credential-aaguid-spinner');
    const textEl = statusEl.querySelector('.credential-aaguid-status-text');

    if (spinner instanceof HTMLElement) {
        if (showSpinner) {
            spinner.hidden = false;
            spinner.setAttribute('aria-hidden', 'true');
        } else {
            spinner.hidden = true;
            spinner.setAttribute('aria-hidden', 'true');
        }
    }

    if (textEl instanceof HTMLElement) {
        textEl.textContent = typeof message === 'string' ? message : '';
    }
}

function clearAaguidStatus(statusEl) {
    if (!(statusEl instanceof HTMLElement)) {
        return;
    }
    delete statusEl.dataset.active;
    const spinner = statusEl.querySelector('.credential-aaguid-spinner');
    const textEl = statusEl.querySelector('.credential-aaguid-status-text');
    if (spinner instanceof HTMLElement) {
        spinner.hidden = true;
        spinner.setAttribute('aria-hidden', 'true');
    }
    if (textEl instanceof HTMLElement) {
        textEl.textContent = '';
    }
}

export function navigateToMdsAuthenticator(aaguid) {
    if (!aaguid) {
        return;
    }

    const switchToMdsTab = typeof window.switchTab === 'function'
        ? window.switchTab
        : null;
    if (switchToMdsTab) {
        switchToMdsTab('mds');
    }

    const highlightRow = typeof window.highlightMdsAuthenticatorRow === 'function'
        ? window.highlightMdsAuthenticatorRow
        : null;

    if (!highlightRow) {
        console.warn('Unable to highlight authenticator row: integration unavailable.');
        return;
    }

    const modalBody = document.getElementById('modalBody');
    const statusEl = modalBody ? modalBody.querySelector('.credential-aaguid-status') : null;
    const getLoadState = typeof window.getMdsLoadState === 'function'
        ? window.getMdsLoadState
        : null;
    const waitForLoad = typeof window.waitForMdsLoad === 'function'
        ? window.waitForMdsLoad
        : null;
    const initialState = getLoadState ? getLoadState() : null;
    const requiresLoad = !initialState || initialState.isLoading || !initialState.hasLoaded;

    let clearTimer = null;
    const scheduleClear = () => {
        if (typeof window !== 'undefined' && clearTimer) {
            window.clearTimeout(clearTimer);
        }
        if (typeof window !== 'undefined') {
            clearTimer = window.setTimeout(() => {
                clearAaguidStatus(statusEl);
                clearTimer = null;
            }, 4000);
        }
    };

    const showSpinnerStatus = message => {
        if (!statusEl) {
            return;
        }
        if (typeof window !== 'undefined' && clearTimer) {
            window.clearTimeout(clearTimer);
            clearTimer = null;
        }
        setAaguidStatus(statusEl, message, { showSpinner: true });
    };

    const run = async () => {
        try {
            if (statusEl) {
                const message = requiresLoad
                    ? 'Loading authenticator metadata…'
                    : 'Locating authenticator entry…';
                showSpinnerStatus(message);
            }

            if (waitForLoad && requiresLoad) {
                try {
                    await waitForLoad();
                } catch (error) {
                    console.warn('Failed to wait for authenticator metadata to load:', error);
                }
                showSpinnerStatus('Locating authenticator entry…');
            }

            const highlightResult = await Promise.resolve(highlightRow(aaguid));

            let highlighted = false;
            let resolvedEntry = null;

            if (highlightResult && typeof highlightResult === 'object' && 'highlighted' in highlightResult) {
                highlighted = Boolean(highlightResult.highlighted);
                resolvedEntry = highlightResult.entry || null;
            } else {
                highlighted = Boolean(highlightResult);
            }

            if (highlighted) {
                clearAaguidStatus(statusEl);
                closeCredentialModal();
                return;
            }

            if (statusEl) {
                const message = resolvedEntry
                    ? 'Unable to locate authenticator entry.'
                    : 'Authenticator metadata not found.';
                setAaguidStatus(statusEl, message, { showSpinner: false });
                scheduleClear();
            }
        } catch (error) {
            console.error('Failed to highlight authenticator row.', error);
            if (statusEl) {
                setAaguidStatus(statusEl, 'Unable to open authenticator metadata.', { showSpinner: false });
                scheduleClear();
            }
        }
    };

    run();
}

export function closeCredentialModal() {
    closeModal('credentialModal');
}

export function closeRegistrationResultModal() {
    closeModal('registrationResultModal');
}

export async function showCredentialDetails(index) {
    const cred = state.storedCredentials[index];
    if (!cred) {
        return;
    }

    const modalBody = document.getElementById('modalBody');
    if (!modalBody) {
        return;
    }

    resetRegistrationDetailState();

    const pickFirstString = (...candidates) => {
        for (const candidate of candidates) {
            if (typeof candidate !== 'string') {
                continue;
            }
            const trimmed = candidate.trim();
            if (trimmed) {
                return trimmed;
            }
        }
        return '';
    };

    const pickFirstObject = (...candidates) => {
        for (const candidate of candidates) {
            if (candidate && typeof candidate === 'object') {
                return candidate;
            }
        }
        return null;
    };

    const collectCertificates = (...sources) => {
        const result = [];
        sources.forEach(source => {
            if (!source) {
                return;
            }
            if (Array.isArray(source)) {
                source.forEach(item => {
                    if (item) {
                        result.push(item);
                    }
                });
            } else {
                result.push(source);
            }
        });
        return result;
    };

    let attestationObjectValue = pickFirstString(
        cred.attestationObjectRaw,
        cred.attestationObject,
        cred.attestation_object_raw,
        cred.attestation_object,
        cred.attestationObjectBase64,
        cred.attestation_object_base64,
    );

    let attestationObjectDecoded = pickFirstObject(
        cred.attestationObjectDecoded,
        cred.attestation_object_decoded,
        typeof cred.attestationObject === 'object' ? cred.attestationObject : null,
        typeof cred.attestation_object === 'object' ? cred.attestation_object : null,
    );

    let authenticatorDataBase64 = pickFirstString(
        cred.authenticatorDataRaw,
        cred.authenticatorData,
        cred.authenticator_data_raw,
        cred.authenticator_data,
        cred.authenticatorDataBase64,
        cred.authenticatorDataBase64Url,
    );

    let authenticatorDataHex = pickFirstString(
        cred.authenticatorDataHex,
        cred.authenticator_data_hex,
    );

    const fallbackCertificates = collectCertificates(
        cred.attestationCertificate,
        cred.attestationCertificates,
        cred.attestation_certificate,
        cred.attestation_certificates,
        cred.properties?.attestationCertificate,
        cred.properties?.attestationCertificates,
        cred.relyingParty?.attestationCertificate,
        cred.relyingParty?.attestationCertificates,
    );

    const relyingPartyInfo = pickFirstObject(
        cred.relyingParty,
        cred.registrationRelyingParty,
        cred.registration_relying_party,
        cred.properties?.relyingParty,
    );

    const fallbackClientDataString = pickFirstString(
        cred.clientDataJSON,
        cred.clientDataJson,
        cred.clientData,
        typeof cred.client_data_json === 'string' ? cred.client_data_json : '',
    );

    const fallbackClientDataObject = pickFirstObject(
        typeof cred.client_data_json === 'object' ? cred.client_data_json : null,
        cred.clientDataParsed,
        cred.clientDataObject,
    );

    const registrationResponseStored = pickFirstObject(
        cred.registrationResponse,
        cred.registration_response,
        cred.registrationResult,
        cred.registration_result,
    );

    let registrationCredential = cloneJson(registrationResponseStored);
    if (!registrationCredential || typeof registrationCredential !== 'object') {
        registrationCredential = {};
    }

    if (!registrationCredential.response || typeof registrationCredential.response !== 'object') {
        registrationCredential.response = {};
    }
    const registrationResponse = registrationCredential.response;

    const credentialIdBase64 = pickFirstString(
        cred.credentialId,
        cred.credential_id,
        cred.credentialIdBase64,
    );
    let credentialIdBase64Url = '';
    if (credentialIdBase64) {
        try {
            credentialIdBase64Url = base64ToBase64Url(credentialIdBase64);
        } catch (error) {
            credentialIdBase64Url = credentialIdBase64;
        }
    }

    if (credentialIdBase64Url) {
        if (!registrationCredential.id) {
            registrationCredential.id = credentialIdBase64Url;
        }
        if (!registrationCredential.rawId) {
            registrationCredential.rawId = credentialIdBase64Url;
        }
    }

    if (!registrationCredential.type) {
        registrationCredential.type = 'public-key';
    }

    const storedRegistrationResponse = (() => {
        if (registrationResponseStored && typeof registrationResponseStored === 'object') {
            const nestedResponse = registrationResponseStored.response;
            if (nestedResponse && typeof nestedResponse === 'object') {
                return nestedResponse;
            }
            return registrationResponseStored;
        }
        return null;
    })();

    if (!attestationObjectValue) {
        attestationObjectValue = pickFirstString(
            storedRegistrationResponse?.attestationObject,
            storedRegistrationResponse?.attestation_object,
            storedRegistrationResponse?.attestationObjectRaw,
            storedRegistrationResponse?.attestation_object_raw,
            registrationCredential?.attestationObject,
            registrationCredential?.attestation_object,
            registrationCredential?.attestationObjectRaw,
            registrationCredential?.attestation_object_raw,
        );
    }

    if (!attestationObjectDecoded) {
        attestationObjectDecoded = pickFirstObject(
            storedRegistrationResponse?.attestationObjectDecoded,
            storedRegistrationResponse?.attestation_object_decoded,
            typeof storedRegistrationResponse?.attestationObject === 'object'
                ? storedRegistrationResponse.attestationObject
                : null,
            typeof storedRegistrationResponse?.attestation_object === 'object'
                ? storedRegistrationResponse.attestation_object
                : null,
            typeof registrationCredential?.attestationObject === 'object'
                ? registrationCredential.attestationObject
                : null,
            typeof registrationCredential?.attestation_object === 'object'
                ? registrationCredential.attestation_object
                : null,
        );
    }

    if (!authenticatorDataBase64) {
        authenticatorDataBase64 = pickFirstString(
            storedRegistrationResponse?.authenticatorData,
            storedRegistrationResponse?.authenticator_data,
            storedRegistrationResponse?.authenticatorDataRaw,
            storedRegistrationResponse?.authenticator_data_raw,
            registrationCredential?.authenticatorData,
            registrationCredential?.authenticator_data,
            registrationCredential?.authenticatorDataRaw,
            registrationCredential?.authenticator_data_raw,
        );
    }

    if (!authenticatorDataHex) {
        authenticatorDataHex = pickFirstString(
            storedRegistrationResponse?.authenticatorDataHex,
            storedRegistrationResponse?.authenticator_data_hex,
            registrationCredential?.authenticatorDataHex,
            registrationCredential?.authenticator_data_hex,
        );
    }

    if (attestationObjectValue && !registrationResponse.attestationObject) {
        registrationResponse.attestationObject = attestationObjectValue;
    }

    if (attestationObjectDecoded && !registrationResponse.attestationObjectDecoded) {
        registrationResponse.attestationObjectDecoded = attestationObjectDecoded;
    }

    const normalizedClientDataForResponse = normalizeClientDataString(
        registrationResponse.clientDataJSON || fallbackClientDataString,
    );
    if (normalizedClientDataForResponse && !registrationResponse.clientDataJSON) {
        registrationResponse.clientDataJSON = normalizedClientDataForResponse;
    }

    if (authenticatorDataBase64 && !registrationResponse.authenticatorData) {
        registrationResponse.authenticatorData = authenticatorDataBase64;
    }

    const extensionResults = pickFirstObject(
        registrationCredential.clientExtensionResults,
        cred.clientExtensionOutputs,
        cred.client_extension_outputs,
    );
    if (extensionResults && typeof extensionResults === 'object') {
        registrationCredential.clientExtensionResults = cloneJson(extensionResults) || extensionResults;
    }

    if (cred.authenticatorAttachment && !registrationCredential.authenticatorAttachment) {
        registrationCredential.authenticatorAttachment = cred.authenticatorAttachment;
    }

    const authenticatorDataForDetail = authenticatorDataBase64 || authenticatorDataHex || '';

    const registrationDetailResult = await composeRegistrationDetailHtml({
        credentialJson: Object.keys(registrationCredential).length ? registrationCredential : null,
        relyingPartyInfo,
        attestationObjectValue,
        attestationObjectDecoded,
        authenticatorDataValue: authenticatorDataForDetail,
        authenticatorDataHex,
        fallbackCertificates,
        fallbackClientData: fallbackClientDataString,
        fallbackParsedClientData: fallbackClientDataObject,
        includeAttestationSection: false,
    });
    const registrationDetailHtml = registrationDetailResult.html;
    const attestationSectionHtml = registrationDetailResult.attestationSectionHtml;

    const attestationFormatCandidates = [
        cred.attestationFormat,
        cred.attestation_format,
        cred.attestationFmt,
        relyingPartyInfo?.attestationFmt,
        attestationObjectDecoded && typeof attestationObjectDecoded.fmt === 'string' ? attestationObjectDecoded.fmt : '',
    ];
    const attestationFormatRaw = pickFirstString(...attestationFormatCandidates);

    let detailsHtml = '';

    detailsHtml += `
    <div style="margin-bottom: 1.5rem;">
        <h4 style="color: #0072CE; margin-bottom: 0.5rem;">User info at creation</h4>
        <div style="font-size: 0.9rem; line-height: 1.4;">
            <div><strong>Name:</strong> ${cred.userName || cred.email || 'N/A'}</div>
            <div style="margin-bottom: 0.5rem;"><strong>Display name:</strong> ${cred.displayName || cred.userName || cred.email || 'N/A'}</div>
        </div>`;

    if (cred.userHandle) {
        const userHandleB64 = cred.userHandle;
        const userHandleB64u = base64ToBase64Url(userHandleB64);
        const userHandleHex = base64UrlToHex(userHandleB64u);

        detailsHtml += `
        <div style="margin-top: 0.5rem;">
            <div><strong>User handle (User ID):</strong></div>
            <div style="font-family: 'Courier New', monospace; font-size: 0.9rem; margin-left: 1rem; word-break: break-word; overflow-wrap: anywhere;">
                <div><strong>b64</strong></div>
                <div class="credential-code-block">${userHandleB64}</div>
                <div><strong>b64u</strong></div>
                <div class="credential-code-block">${userHandleB64u}</div>
                <div><strong>hex</strong></div>
                <div class="credential-code-block">${userHandleHex}</div>
            </div>
        </div>`;
    }

    if (cred.credentialId) {
        const credentialIdB64 = cred.credentialId;
        const credentialIdB64u = base64ToBase64Url(credentialIdB64);
        const credentialIdHex = base64UrlToHex(credentialIdB64u);

        detailsHtml += `
        <div style="margin-top: 0.5rem;">
            <div><strong>Credential ID:</strong></div>
            <div style="font-family: 'Courier New', monospace; font-size: 0.9rem; margin-left: 1rem; word-break: break-word; overflow-wrap: anywhere;">
                <div><strong>b64</strong></div>
                <div class="credential-code-block">${credentialIdB64}</div>
                <div><strong>b64u</strong></div>
                <div class="credential-code-block">${credentialIdB64u}</div>
                <div><strong>hex</strong></div>
                <div class="credential-code-block">${credentialIdHex}</div>
            </div>
        </div>`;
    }

    let aaguidHex = normaliseAaguidValue(cred.aaguid);

    const discoverableValue = cred.residentKey ?? cred.discoverable ?? false;
    const largeBlobSupported = cred.largeBlob ?? cred.largeBlobSupported ?? false;
    const minPinLengthValue = extractMinPinLengthValue(cred);
    const propertiesData = (cred.properties && typeof cred.properties === 'object' && cred.properties !== null)
        ? cred.properties
        : {};
    const attestationSummaryData = (() => {
        if (cred && typeof cred.attestationSummary === 'object' && cred.attestationSummary !== null) {
            return cred.attestationSummary;
        }
        if (typeof propertiesData.attestationSummary === 'object' && propertiesData.attestationSummary !== null) {
            return propertiesData.attestationSummary;
        }
        return null;
    })();
    const attestationChecksData = (() => {
        if (cred && typeof cred.attestationChecks === 'object' && cred.attestationChecks !== null) {
            return cred.attestationChecks;
        }
        if (typeof propertiesData.attestationChecks === 'object' && propertiesData.attestationChecks !== null) {
            return propertiesData.attestationChecks;
        }
        if (
            attestationSummaryData
            && typeof attestationSummaryData.metadata === 'object'
            && attestationSummaryData.metadata !== null
        ) {
            return { metadata: attestationSummaryData.metadata };
        }
        return null;
    })();
    const resolveAttestationValue = (summaryKey, propertyKey) => {
        if (attestationSummaryData && Object.prototype.hasOwnProperty.call(attestationSummaryData, summaryKey)) {
            return attestationSummaryData[summaryKey];
        }
        if (Object.prototype.hasOwnProperty.call(propertiesData, propertyKey)) {
            return propertiesData[propertyKey];
        }
        if (Object.prototype.hasOwnProperty.call(cred, propertyKey)) {
            return cred[propertyKey];
        }
        return null;
    };
    const normaliseAttestationResultValue = (value) => {
        if (typeof value === 'boolean' || value === null || value === undefined) {
            return value;
        }
        if (typeof value === 'number') {
            if (Number.isNaN(value)) {
                return null;
            }
            if (value === 1) {
                return true;
            }
            if (value === 0) {
                return false;
            }
        }
        if (typeof value === 'string') {
            const trimmed = value.trim();
            if (!trimmed) {
                return null;
            }
            const normalised = trimmed.toLowerCase();
            if (['true', 'yes', 'valid', 'pass', 'passed', 'success', 'ok'].includes(normalised)) {
                return true;
            }
            if (['false', 'no', 'invalid', 'fail', 'failed', 'error', 'ko'].includes(normalised)) {
                return false;
            }
            if (normalised === '1') {
                return true;
            }
            if (normalised === '0') {
                return false;
            }
        }
        return value;
    };

    const attestationSignatureValue = normaliseAttestationResultValue(resolveAttestationValue('signatureValid', 'attestationSignatureValid'));
    const attestationRootValue = normaliseAttestationResultValue(resolveAttestationValue('rootValid', 'attestationRootValid'));
    const attestationRpIdHashValue = normaliseAttestationResultValue(resolveAttestationValue('rpIdHashValid', 'attestationRpIdHashValid'));
    const attestationAaguidMatchValue = normaliseAttestationResultValue(resolveAttestationValue('aaguidMatch', 'attestationAaguidMatch'));
    const attestationRowsHtml = [
        renderAttestationResultRow('Signature Valid', attestationSignatureValue),
        renderAttestationResultRow('Root Valid', attestationRootValue),
        renderAttestationResultRow('RPID Hash Valid', attestationRpIdHashValue),
        renderAttestationResultRow('AAGUID Match', attestationAaguidMatchValue),
    ].join('');

    const fallbackAaguidCandidates = [
        cred.aaguidHex,
        cred.aaguidGuid,
        cred.aaguidRaw,
        propertiesData?.aaguid,
        propertiesData?.aaguidHex,
        propertiesData?.aaguidGuid,
        propertiesData?.aaguidRaw,
        attestationSummaryData?.aaguid,
        attestationSummaryData?.aaguidHex,
        attestationSummaryData?.aaguidGuid,
        attestationChecksData?.metadata?.aaguid,
        attestationChecksData?.metadata?.hex,
        attestationChecksData?.metadata?.raw,
        attestationChecksData?.metadata?.guid,
        propertiesData?.metadata?.aaguid,
        propertiesData?.metadata?.hex,
        propertiesData?.metadata?.raw,
        propertiesData?.metadata?.guid,
        cred?.metadata?.aaguid,
        cred?.metadata?.hex,
        cred?.metadata?.raw,
        cred?.metadata?.guid,
    ];
    const relyingPartyAaguid = cred?.relyingParty?.aaguid;
    if (relyingPartyAaguid && typeof relyingPartyAaguid === 'object') {
        fallbackAaguidCandidates.push(
            relyingPartyAaguid.raw,
            relyingPartyAaguid.hex,
            relyingPartyAaguid.guid,
        );
    } else if (relyingPartyAaguid) {
        fallbackAaguidCandidates.push(relyingPartyAaguid);
    }

    if (!aaguidHex) {
        for (const candidate of fallbackAaguidCandidates) {
            const normalised = normaliseAaguidValue(candidate);
            if (normalised) {
                aaguidHex = normalised;
                break;
            }
        }
    }

    if (!aaguidHex) {
        aaguidHex = deriveAaguidFromCredentialData(cred);
    }

    const rootVerified = attestationRootValue === true ||
        (typeof attestationRootValue === 'string' && attestationRootValue.trim().toLowerCase() === 'true');

    const { aaguidHex: normalizedAaguidHex, aaguidB64, aaguidB64u } = deriveAaguidDisplayValues(aaguidHex);
    let aaguidGuid = '';
    if (normalizedAaguidHex && normalizedAaguidHex.length === 32) {
        try {
            aaguidGuid = hexToGuid(normalizedAaguidHex);
        } catch (error) {
            aaguidGuid = '';
        }
    }

    const hasAaguid = Boolean(normalizedAaguidHex);
    const infoButton = rootVerified && aaguidGuid
        ? `<button type="button" class="credential-info-button credential-aaguid-button" data-aaguid="${escapeHtml(aaguidGuid.toLowerCase())}" aria-label="View authenticator metadata">Info</button>`
        : '';

    const renderAaguidValue = (label, value) => `
            <div class="credential-aaguid-value">
                <span class="credential-aaguid-value-label">${label}</span>
                <div class="credential-code-block">${escapeHtml(value || 'N/A')}</div>
            </div>`;

    const sections = [
        renderAaguidValue('b64', hasAaguid && aaguidB64 ? aaguidB64 : 'N/A'),
        renderAaguidValue('b64u', hasAaguid && aaguidB64u ? aaguidB64u : 'N/A'),
        renderAaguidValue('hex', hasAaguid ? normalizedAaguidHex : 'N/A'),
        renderAaguidValue('guid', aaguidGuid || 'N/A'),
    ];

    detailsHtml += `
        <div class="credential-aaguid-row">
            <span class="credential-aaguid-label">AAGUID</span>
            ${infoButton}
        </div>
        <div class="credential-aaguid-status" role="status" aria-live="polite">
            <span class="credential-aaguid-spinner" aria-hidden="true" hidden></span>
            <span class="credential-aaguid-status-text"></span>
        </div>
        <div class="credential-aaguid-values">
            ${sections.join('')}
        </div>`;

    detailsHtml += `</div>`;

    detailsHtml += `
    <div style="margin-bottom: 1.5rem;">
        <h4 style="color: #0072CE; margin-bottom: 0.5rem;">Properties</h4>
        <div style="font-size: 0.9rem; line-height: 1.4;">
            <div><strong>Discoverable (resident key):</strong> ${formatBoolean(discoverableValue)}</div>
            <div><strong>Supports largeBlob:</strong> ${formatBoolean(largeBlobSupported)}</div>
            ${minPinLengthValue !== null ? `<div><strong>Authenticator minPinLength:</strong> ${escapeHtml(String(minPinLengthValue))}</div>` : ''}
            <div style="margin-top: 0.5rem; padding-top: 0.5rem; border-top: 1px solid rgba(0, 114, 206, 0.15);">
                ${attestationRowsHtml}
            </div>
        </div>
    </div>`;

    const attestationFormatFallback = pickFirstString(cred.attestationFormat, cred.attestation_format);
    const attestationFormatDisplay = attestationFormatRaw || attestationFormatFallback || 'none';

    detailsHtml += `
    <div style="margin-bottom: 1.5rem;">
        <h4 style="color: #0072CE; margin-bottom: 0.5rem;">Attestation Format</h4>
        <div style="font-size: 0.9rem;">${attestationFormatDisplay}</div>
    </div>`;

    if (cred.flags) {
        detailsHtml += `
        <div style="margin-bottom: 1.5rem;">
            <h4 style="color: #0072CE; margin-bottom: 0.5rem;">Authenticator Data (registration)</h4>
            <div style="font-size: 0.9rem; line-height: 1.4;">
                <div><strong>AT:</strong> ${cred.flags.at}, <strong>BE:</strong> ${cred.flags.be}, <strong>BS:</strong> ${cred.flags.bs}, <strong>ED:</strong> ${cred.flags.ed}, <strong>UP:</strong> ${cred.flags.up}, <strong>UV:</strong> ${cred.flags.uv}</div>
                <div><strong>Signature Counter:</strong> ${cred.signCount || 0}</div>
            </div>
        </div>`;
    }

    if (cred.clientExtensionOutputs && Object.keys(cred.clientExtensionOutputs).length > 0) {
        detailsHtml += `
        <div style="margin-bottom: 1.5rem;">
            <h4 style="color: #0072CE; margin-bottom: 0.5rem;">Client extension outputs (registration)</h4>
            <div class="credential-code-block" style="font-size: 0.9rem; border-radius: 16px;">${JSON.stringify(cred.clientExtensionOutputs, null, 2)}</div>
        </div>`;
    }

    if (cred.publicKeyAlgorithm !== undefined || cred.algorithm !== undefined || (cred.publicKeyCose && Object.keys(cred.publicKeyCose).length > 0)) {
        const coseMap = cred.publicKeyCose || {};
        let algo = cred.publicKeyAlgorithm;
        if (algo === undefined || algo === null) {
            algo = cred.algorithm;
        }
        if (typeof algo === 'string' && algo.trim().toLowerCase() === 'unknown') {
            const coseValue = getCoseMapValue(coseMap, 3);
            if (coseValue !== undefined) {
                algo = coseValue;
            }
        }
        if (algo === undefined || algo === null) {
            algo = getCoseMapValue(coseMap, 3);
        }
        const algorithmName = describeCoseAlgorithm(algo);
        const coseKeyTypeValue = cred.publicKeyType ?? getCoseMapValue(coseMap, 1);
        const coseKeyTypeLine = coseKeyTypeValue !== undefined && coseKeyTypeValue !== null
            ? `<div><strong>COSE key type:</strong> ${describeCoseKeyType(coseKeyTypeValue)}</div>`
            : '';
        const parameterSet = describeMldsaParameterSet(algo);

        const parameterSetLine = parameterSet
            ? `<div><strong>ML-DSA parameter set:</strong> ${parameterSet}</div>`
            : '';

        detailsHtml += `
        <div style="margin-bottom: 1.5rem;">
            <h4 style="color: #0072CE; margin-bottom: 0.5rem;">Public Key</h4>
            <div style="font-size: 0.9rem;">
                <div><strong>Algorithm:</strong> ${algorithmName}</div>
                ${coseKeyTypeLine}
                ${parameterSetLine}
            </div>
        </div>`;
    }

    const combinedRegistrationHtml = [registrationDetailHtml, attestationSectionHtml].filter(Boolean).join('');
    if (combinedRegistrationHtml) {
        detailsHtml += `
        <div class="credential-registration-copy">
            ${combinedRegistrationHtml}
        </div>`;
    } else {
        detailsHtml += `
        <div class="credential-registration-copy">
            <div style="font-style: italic; color: #6c757d;">Registration detail data is not available for this credential.</div>
        </div>`;
    }

    modalBody.innerHTML = detailsHtml;
    bindRegistrationDetailButtons(modalBody);

    const statusEl = modalBody.querySelector('.credential-aaguid-status');
    if (statusEl) {
        clearAaguidStatus(statusEl);
    }
    const aaguidButton = modalBody.querySelector('.credential-aaguid-button');
    if (aaguidButton) {
        aaguidButton.addEventListener('click', () => {
            const target = aaguidButton.getAttribute('data-aaguid');
            if (target) {
                navigateToMdsAuthenticator(target);
            }
        });
    }
    modalBody.scrollTop = 0;
    if (typeof modalBody.scrollTo === 'function') {
        modalBody.scrollTo(0, 0);
    }
    openModal('credentialModal');
    const scheduleResize = () => autoResizeCertificateTextareas(modalBody);
    if (typeof requestAnimationFrame === 'function') {
        requestAnimationFrame(scheduleResize);
    } else {
        setTimeout(scheduleResize, 0);
    }
}

async function decodePayloadThroughApi(payload) {
    const trimmed = typeof payload === 'string' ? payload.trim() : '';
    if (!trimmed) {
        throw new Error('Decoder payload must be a non-empty string.');
    }

    const response = await fetch('/api/decode', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ payload: trimmed })
    });

    if (!response.ok) {
        const errorText = await response.text();
        throw new Error(errorText || 'Unable to decode payload.');
    }

    const json = await response.json();
    if (json && typeof json === 'object') {
        if (json.error) {
            throw new Error(json.error);
        }
        if (json.data !== undefined) {
            return json;
        }
    }

    throw new Error('Decoder response did not include data.');
}

export async function showRegistrationResultModal(credentialJson, relyingPartyInfo) {
    const modalBody = document.getElementById('registrationResultBody');
    if (!modalBody) {
        return;
    }

    const attestationObjectValue = credentialJson?.response?.attestationObject || '';
    const authenticatorDataValue = credentialJson?.response?.authenticatorData || '';

    const collectCertificates = (...sources) => {
        const result = [];
        sources.forEach(source => {
            if (!source) {
                return;
            }
            if (Array.isArray(source)) {
                source.forEach(item => {
                    if (item) {
                        result.push(item);
                    }
                });
            } else {
                result.push(source);
            }
        });
        return result;
    };

    const fallbackCertificates = collectCertificates(
        relyingPartyInfo?.attestationCertificate,
        relyingPartyInfo?.attestationCertificates,
        relyingPartyInfo?.attestation_certificate,
        relyingPartyInfo?.attestation_certificates,
        relyingPartyInfo?.registrationData?.attestationCertificate,
        relyingPartyInfo?.registrationData?.attestationCertificates,
        relyingPartyInfo?.registrationData?.attestation_certificate,
        relyingPartyInfo?.registrationData?.attestation_certificates,
    );

    const registrationDetail = await composeRegistrationDetailHtml({
        credentialJson,
        relyingPartyInfo,
        attestationObjectValue,
        authenticatorDataValue,
        fallbackCertificates,
    });

    modalBody.innerHTML = registrationDetail.html;
    bindRegistrationDetailButtons(modalBody);

    modalBody.scrollTop = 0;
    if (typeof modalBody.scrollTo === 'function') {
        modalBody.scrollTo(0, 0);
    }
    openModal('registrationResultModal');
    const scheduleResize = () => autoResizeCertificateTextareas(modalBody);
    if (typeof requestAnimationFrame === 'function') {
        requestAnimationFrame(scheduleResize);
    } else {
        setTimeout(scheduleResize, 0);
    }
}

export async function deleteCredential(username, index) {
    if (!confirm(`Are you sure you want to delete the credential for ${username}? This action cannot be undone.`)) {
        return;
    }

    try {
        const response = await fetch('/api/deletepub', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({"email": username})
        });

        if (response.ok) {
            state.storedCredentials.splice(index, 1);
            updateCredentialsDisplay();
            showStatus('advanced',
                'Credential deleted from server successfully! ',
                'success'
            );
        } else {
            throw new Error('Failed to delete credential from server');
        }
    } catch (error) {
        showStatus('advanced', `Failed to delete credential: ${error.message}`, 'error');
    }
}

export async function clearAllCredentials() {
    if (!state.storedCredentials.length) {
        showStatus('advanced', 'No saved credentials to clear.', 'info');
        return;
    }

    if (!confirm('Are you sure you want to delete all saved credentials? This action cannot be undone.')) {
        return;
    }

    try {
        const response = await fetch('/api/credentials', {
            method: 'DELETE',
            headers: {'Content-Type': 'application/json'}
        });

        if (!response.ok) {
            const errorText = await response.text();
            throw new Error(errorText || 'Failed to clear credentials.');
        }

        state.storedCredentials = [];
        updateCredentialsDisplay();
        showStatus('advanced', 'All saved credentials removed successfully!', 'success');
    } catch (error) {
        const message = error && typeof error === 'object' && typeof error.message === 'string'
            ? error.message
            : 'Unknown error';
        showStatus('advanced', `Failed to clear credentials: ${message}`, 'error');
    }
}

export function addCredentialToList(credential) {
    const normalizedCredential = {
        ...credential,
        credentialIdHex: getCredentialIdHex(credential),
        userHandleHex: getCredentialUserHandleHex(credential),
    };
    state.storedCredentials.push(normalizedCredential);
    updateCredentialsList();
}

export function updateCredentialsList() {
    const list = document.getElementById('credentials-list');

    if (!list) {
        return;
    }

    if (state.storedCredentials.length === 0) {
        list.innerHTML = '<p style="color: #6c757d; font-style: normal">No credentials registered yet.</p>';
        return;
    }

    list.innerHTML = '';
    state.storedCredentials.forEach((cred, index) => {
        const credItem = document.createElement('div');
        credItem.className = 'credential-item';
        credItem.onclick = () => toggleCredentialDetails(index);

        let summary = '';
        if (cred.type === 'simple') {
            summary = cred.email || cred.username;
        } else {
            summary = `${cred.userName || cred.userId}`;
            if (cred.displayName) summary += `\n${cred.displayName}`;
        }

        credItem.innerHTML = `
            <div class="credential-summary">${summary}</div>
            <div class="credential-details">
                ${generateCredentialDetails(cred)}
                <button class="credential-delete" onclick="deleteCredential(${index}); event.stopPropagation();">Delete</button>
            </div>
        `;

        list.appendChild(credItem);
    });
}

export function generateCredentialDetails(cred) {
    const algorithmDisplay = describeCoseAlgorithm(cred.algorithm);
    if (cred.type === 'simple') {
        return `
            <strong>Type:</strong> Simple Authentication<br>
            <strong>User:</strong> ${cred.email || cred.username}<br>
            <strong>Credential ID:</strong> ${cred.credentialId}<br>
            <strong>Algorithm:</strong> ${algorithmDisplay}
        `;
    } else {
        return `
            <strong>Type:</strong> Advanced Authentication<br>
            <strong>User ID:</strong> ${cred.userId}<br>
            <strong>User Name:</strong> ${cred.userName}<br>
            <strong>Display Name:</strong> ${cred.displayName || 'N/A'}<br>
            <strong>Credential ID:</strong> ${cred.credentialId}<br>
            <strong>Algorithm:</strong> ${algorithmDisplay}
        `;
    }
}

export function toggleCredentialDetails(index) {
    const credItems = document.querySelectorAll('.credential-item');
    const item = credItems[index];

    if (item.classList.contains('expanded')) {
        item.classList.remove('expanded');
    } else {
        credItems.forEach(item => item.classList.remove('expanded'));
        item.classList.add('expanded');
    }
}
