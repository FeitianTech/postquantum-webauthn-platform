const SIMPLE_STORAGE_KEY = 'postquantum-webauthn.simpleCredentials';
const ADVANCED_STORAGE_KEY = 'postquantum-webauthn.advancedCredentials';
const CERTIFICATE_COLLECTION_KEYS = [
    'attestationCertificate',
    'attestationCertificates',
    'attestation_certificate',
    'attestation_certificates',
];
const HEAVY_DUPLICATE_KEYS = [
    'attestationObject',
    'attestation_object',
    'authenticatorData',
    'authenticator_data',
];
const AGGRESSIVE_DROP_KEYS = [
    'attestationObject',
    'attestation_object',
    'attestationStatement',
    'attestation_statement',
    'registrationResponse',
    'registration_response',
];
const MAX_SNAPSHOT_HTML_LENGTH = 120000;
const MAX_DETAIL_STRING_LENGTH = 48000;
const MAX_AUTH_DATA_HEX_LENGTH = 8192;
const MAX_AUTH_DATA_HASH_LENGTH = 1024;
const SNAPSHOT_CERT_STRIP_KEYS = [
    'der',
    'derBase64',
    'der_base64',
    'certificatePem',
    'certificate_pem',
    'certificateDer',
    'certificate_der',
    'certificate',
    'certificate_raw',
    'certificateRaw',
    'rawBinary',
    'raw_buffer',
    'rawBuffer',
    'rawBytes',
    'raw_bytes',
];
const SNAPSHOT_EXTENSION_STRIP_KEYS = [
    'raw',
    'rawHex',
    'raw_hex',
    'hex',
    'valueHex',
    'value_hex',
    'der',
    'derBase64',
    'der_base64',
];
const SNAPSHOT_ATTESTATION_STRIP_KEYS = [
    'attestationCertificate',
    'attestationCertificates',
    'attestation_certificate',
    'attestation_certificates',
];
const SNAPSHOT_AUTH_DATA_STRIP_KEYS = [
    'rawBinary',
    'raw_buffer',
    'rawBuffer',
    'rawBytes',
    'raw_bytes',
];

function cloneJsonValue(value) {
    if (!value || typeof value !== 'object') {
        return null;
    }
    try {
        return JSON.parse(JSON.stringify(value));
    } catch (error) {
        return { ...value };
    }
}

function truncateString(value, maxLength) {
    if (typeof value !== 'string') {
        return '';
    }
    if (!Number.isFinite(maxLength) || maxLength <= 0) {
        return value;
    }
    return value.length > maxLength ? value.slice(0, maxLength) : value;
}

function sanitiseParsedCertificateForSnapshot(parsed) {
    const parsedClone = cloneJsonValue(parsed);
    if (!parsedClone) {
        return null;
    }

    stripKeysRecursively(parsedClone, SNAPSHOT_CERT_STRIP_KEYS, false);

    if (Array.isArray(parsedClone.extensions)) {
        parsedClone.extensions = parsedClone.extensions
            .map(ext => {
                const extClone = cloneJsonValue(ext);
                if (!extClone) {
                    return null;
                }
                stripKeysRecursively(extClone, SNAPSHOT_EXTENSION_STRIP_KEYS, false);
                return extClone;
            })
            .filter(Boolean);
    }

    return parsedClone;
}

function sanitiseCertificateEntryForSnapshot(entry) {
    const clone = cloneJsonValue(entry);
    if (!clone) {
        return null;
    }

    stripKeysRecursively(clone, SNAPSHOT_CERT_STRIP_KEYS, false);

    if (clone.parsedX5c && typeof clone.parsedX5c === 'object') {
        const sanitisedParsed = sanitiseParsedCertificateForSnapshot(clone.parsedX5c);
        if (sanitisedParsed) {
            clone.parsedX5c = sanitisedParsed;
        } else {
            delete clone.parsedX5c;
        }
    } else if (clone.parsed && typeof clone.parsed === 'object') {
        const sanitisedParsed = sanitiseParsedCertificateForSnapshot(clone.parsed);
        if (sanitisedParsed) {
            clone.parsedX5c = sanitisedParsed;
        }
        delete clone.parsed;
    }

    return Object.keys(clone).length ? clone : null;
}

function sanitiseDetailPreparationSnapshot(preparation) {
    if (!preparation || typeof preparation !== 'object') {
        return null;
    }

    return {
        attestationObjectValue: truncateString(preparation.attestationObjectValue || '', MAX_DETAIL_STRING_LENGTH),
        attestationDecodeError: truncateString(preparation.attestationDecodeError || '', MAX_DETAIL_STRING_LENGTH),
        authenticatorDataValue: truncateString(preparation.authenticatorDataValue || '', MAX_DETAIL_STRING_LENGTH),
        authenticatorDecodeError: truncateString(preparation.authenticatorDecodeError || '', MAX_DETAIL_STRING_LENGTH),
    };
}

function sanitiseAttestationObjectForSnapshot(attestationObject) {
    const clone = cloneJsonValue(attestationObject);
    if (!clone) {
        return null;
    }

    if (clone.attStmt && typeof clone.attStmt === 'object') {
        const attStmtClone = { ...clone.attStmt };
        if (Array.isArray(attStmtClone.x5c)) {
            attStmtClone.x5c = new Array(attStmtClone.x5c.length).fill(null);
        }
        stripKeysRecursively(attStmtClone, SNAPSHOT_ATTESTATION_STRIP_KEYS, false);
        clone.attStmt = attStmtClone;
    }

    return clone;
}

function sanitiseAuthenticatorDataForSnapshot(authData) {
    const clone = cloneJsonValue(authData);
    if (!clone) {
        return null;
    }

    stripKeysRecursively(clone, SNAPSHOT_AUTH_DATA_STRIP_KEYS, false);
    return clone;
}

function sanitiseRegistrationDetailStateSnapshot(state) {
    if (!state || typeof state !== 'object') {
        return null;
    }

    const sanitised = {};

    if (state.detailPreparation && typeof state.detailPreparation === 'object') {
        const detailClone = sanitiseDetailPreparationSnapshot(state.detailPreparation);
        if (detailClone) {
            sanitised.detailPreparation = detailClone;
        }
    }

    if (state.attestationObject && typeof state.attestationObject === 'object') {
        const attestationClone = sanitiseAttestationObjectForSnapshot(state.attestationObject);
        if (attestationClone) {
            sanitised.attestationObject = attestationClone;
        }
    }

    if (Array.isArray(state.attestationCertificates)) {
        const certificates = state.attestationCertificates
            .map(sanitiseCertificateEntryForSnapshot)
            .filter(Boolean);
        if (certificates.length) {
            sanitised.attestationCertificates = certificates;
        }
    }

    if (Array.isArray(state.visibleAttestationCertificateIndices)) {
        const indices = state.visibleAttestationCertificateIndices
            .map(index => Number.parseInt(index, 10))
            .filter(Number.isFinite);
        if (indices.length) {
            sanitised.visibleAttestationCertificateIndices = indices;
        }
    }

    if (state.authenticatorData && typeof state.authenticatorData === 'object') {
        const authClone = sanitiseAuthenticatorDataForSnapshot(state.authenticatorData);
        if (authClone) {
            sanitised.authenticatorData = authClone;
        }
    }

    if (typeof state.authenticatorDataHex === 'string' && state.authenticatorDataHex.trim()) {
        sanitised.authenticatorDataHex = truncateString(state.authenticatorDataHex.trim(), MAX_AUTH_DATA_HEX_LENGTH);
    }

    if (typeof state.authenticatorDataHash === 'string' && state.authenticatorDataHash.trim()) {
        sanitised.authenticatorDataHash = truncateString(state.authenticatorDataHash.trim(), MAX_AUTH_DATA_HASH_LENGTH);
    }

    return Object.keys(sanitised).length ? sanitised : null;
}

function sanitiseRegistrationDetailSnapshot(snapshot) {
    if (!snapshot || typeof snapshot !== 'object') {
        return null;
    }

    const sanitised = {};

    if (typeof snapshot.schemaVersion === 'number') {
        sanitised.schemaVersion = snapshot.schemaVersion;
    }

    if (typeof snapshot.capturedAt === 'string' && snapshot.capturedAt.trim()) {
        sanitised.capturedAt = snapshot.capturedAt.trim();
    }

    if (typeof snapshot.html === 'string' && snapshot.html.trim()) {
        sanitised.html = truncateString(snapshot.html.trim(), MAX_SNAPSHOT_HTML_LENGTH);
    }

    if (typeof snapshot.attestationSectionHtml === 'string' && snapshot.attestationSectionHtml.trim()) {
        sanitised.attestationSectionHtml = truncateString(snapshot.attestationSectionHtml.trim(), MAX_SNAPSHOT_HTML_LENGTH);
    }

    if (!sanitised.html && typeof snapshot.combinedHtml === 'string' && snapshot.combinedHtml.trim()) {
        sanitised.html = truncateString(snapshot.combinedHtml.trim(), MAX_SNAPSHOT_HTML_LENGTH);
    } else if (typeof snapshot.combinedHtml === 'string' && snapshot.combinedHtml.trim()) {
        sanitised.combinedHtml = truncateString(snapshot.combinedHtml.trim(), MAX_SNAPSHOT_HTML_LENGTH);
    }

    const stateClone = sanitiseRegistrationDetailStateSnapshot(snapshot.state || snapshot.stateSnapshot || {});
    if (stateClone) {
        sanitised.state = stateClone;
    }

    return Object.keys(sanitised).length ? sanitised : null;
}

function isNonEmptyString(value) {
    return typeof value === 'string' && value.trim() !== '';
}

function safeParse(json) {
    if (typeof json !== 'string') {
        return [];
    }
    try {
        const parsed = JSON.parse(json);
        if (Array.isArray(parsed)) {
            return parsed.filter(item => item && typeof item === 'object');
        }
    } catch (error) {
        // Ignore parse errors and fall back to empty list.
    }
    return [];
}

function readStoredCredentials(storageKey) {
    if (typeof window === 'undefined' || !window.localStorage) {
        return [];
    }
    try {
        return safeParse(window.localStorage.getItem(storageKey));
    } catch (error) {
        return [];
    }
}

function persistStoredCredentials(storageKey, records) {
    if (typeof window === 'undefined' || !window.localStorage) {
        return false;
    }
    try {
        window.localStorage.setItem(storageKey, JSON.stringify(records));
        return true;
    } catch (error) {
        return false;
    }
}

function normaliseCredentialId(record) {
    if (!record) {
        return '';
    }
    if (typeof record.credentialIdBase64Url === 'string' && record.credentialIdBase64Url) {
        return record.credentialIdBase64Url;
    }
    if (typeof record.credentialId === 'string' && record.credentialId) {
        return record.credentialId;
    }
    if (typeof record.id === 'string' && record.id) {
        return record.id;
    }
    return '';
}

function cloneCredential(record) {
    if (!record || typeof record !== 'object') {
        return null;
    }
    return { ...record };
}

export function getAllSimpleCredentials() {
    return readStoredCredentials(SIMPLE_STORAGE_KEY).map(cloneCredential).filter(Boolean);
}

export function getSimpleCredentialsForEmail(email) {
    if (!email) {
        return [];
    }
    const normalised = String(email).toLowerCase();
    return getAllSimpleCredentials().filter(cred => {
        const storedEmail = cred.email || cred.userName || cred.username;
        return storedEmail && String(storedEmail).toLowerCase() === normalised;
    });
}

export function saveSimpleCredential(rawCredential) {
    if (!rawCredential || typeof rawCredential !== 'object') {
        return null;
    }

    const credential = {
        type: 'simple',
        ...rawCredential,
    };

    if (!credential.email) {
        credential.email = credential.userName || credential.username || '';
    }

    const credentialId = normaliseCredentialId(credential);
    if (!credentialId) {
        return null;
    }

    credential.credentialIdBase64Url = credentialId;
    if (typeof credential.signCount !== 'number' || !Number.isFinite(credential.signCount)) {
        credential.signCount = 0;
    }

    const stored = readStoredCredentials(SIMPLE_STORAGE_KEY);
    const filtered = stored.filter(item => normaliseCredentialId(item) !== credentialId);
    filtered.push(credential);
    persistStoredCredentials(SIMPLE_STORAGE_KEY, filtered);
    return credential;
}

export function removeSimpleCredential(credentialId, email) {
    const id = credentialId ? String(credentialId) : '';
    if (!id) {
        return false;
    }
    const stored = readStoredCredentials(SIMPLE_STORAGE_KEY);
    const normalisedEmail = email ? String(email).toLowerCase() : null;
    const filtered = stored.filter(record => {
        const recordId = normaliseCredentialId(record);
        if (recordId !== id) {
            return true;
        }
        if (normalisedEmail) {
            const recordEmail = record.email || record.userName || record.username;
            return String(recordEmail || '').toLowerCase() !== normalisedEmail;
        }
        return false;
    });
    const changed = filtered.length !== stored.length;
    if (changed) {
        persistStoredCredentials(SIMPLE_STORAGE_KEY, filtered);
    }
    return changed;
}

export function clearSimpleCredentials() {
    persistStoredCredentials(SIMPLE_STORAGE_KEY, []);
}

export function updateSimpleCredentialSignCount(email, credentialId, signCount) {
    const id = credentialId ? String(credentialId) : '';
    if (!id) {
        return false;
    }
    const stored = readStoredCredentials(SIMPLE_STORAGE_KEY);
    const normalisedEmail = email ? String(email).toLowerCase() : null;
    let updated = false;
    const updatedRecords = stored.map(record => {
        const recordId = normaliseCredentialId(record);
        if (recordId !== id) {
            return record;
        }
        if (normalisedEmail) {
            const recordEmail = record.email || record.userName || record.username;
            if (String(recordEmail || '').toLowerCase() !== normalisedEmail) {
                return record;
            }
        }
        const clone = { ...record };
        if (typeof signCount === 'number' && Number.isFinite(signCount)) {
            clone.signCount = signCount;
        } else if (typeof clone.signCount === 'number' && Number.isFinite(clone.signCount)) {
            clone.signCount += 1;
        } else {
            clone.signCount = 1;
        }
        updated = true;
        return clone;
    });
    if (updated) {
        persistStoredCredentials(SIMPLE_STORAGE_KEY, updatedRecords);
    }
    return updated;
}

export function prepareCredentialsForServer(credentials) {
    if (!Array.isArray(credentials) || !credentials.length) {
        return [];
    }
    return credentials
        .filter(item => item && typeof item === 'object')
        .map(item => {
            const credentialId = normaliseCredentialId(item);
            const aaguid = item.aaguid || item.aaguidHex || null;
            const publicKey = item.publicKeyBase64Url || item.publicKey || null;
            const algorithm = typeof item.publicKeyAlgorithm === 'number'
                ? item.publicKeyAlgorithm
                : (typeof item.algorithm === 'number' ? item.algorithm : undefined);
            return {
                credentialId,
                aaguid,
                publicKey,
                signCount: Number.isFinite(item.signCount) ? item.signCount : 0,
                algorithm,
            };
        })
        .filter(item => item.credentialId && item.publicKey);
}

function normaliseAdvancedCredentialId(record) {
    if (!record) {
        return '';
    }
    const candidates = [
        record.credentialIdBase64Url,
        record.credentialIdBase64URL,
        record.credentialIdBase64,
        record.credentialId,
        record.id,
    ];
    for (const candidate of candidates) {
        if (typeof candidate === 'string' && candidate.trim()) {
            return candidate.trim();
        }
    }
    return '';
}

function generateRandomIdSegment() {
    if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
        return crypto.randomUUID();
    }
    const random = Math.random().toString(36).slice(2, 11);
    const randomB = Math.random().toString(36).slice(2, 11);
    return `${random}${randomB}`;
}

function ensureAdvancedCredentialStorageId(record, { forceNew = false } = {}) {
    if (!record || typeof record !== 'object') {
        return '';
    }

    if (!forceNew) {
        const existing = isNonEmptyString(record.storageId) ? record.storageId.trim() : '';
        if (existing) {
            record.storageId = existing;
            return existing;
        }
    }

    const baseId = normaliseAdvancedCredentialId(record);
    const timestampSource = record.createdAt || record.registrationTime || record.registration_time;
    const timestampValue = isNonEmptyString(timestampSource) ? timestampSource.trim() : '';
    const randomSegment = generateRandomIdSegment();
    const parts = [];
    if (baseId) {
        parts.push(baseId);
    }
    if (timestampValue) {
        parts.push(timestampValue);
    } else {
        parts.push(Date.now().toString(36));
    }
    parts.push(randomSegment);
    const storageId = parts.join('::');
    record.storageId = storageId;
    return storageId;
}

function cloneAdvancedStoredRecord(record) {
    if (!record || typeof record !== 'object') {
        return null;
    }
    const clone = { ...record };
    clone.type = clone.type || 'advanced';
    ensureAdvancedCredentialStorageId(clone);
    return clone;
}

function stripKeysRecursively(target, keys, skipRoot = false) {
    if (!target || typeof target !== 'object' || !Array.isArray(keys) || !keys.length) {
        return;
    }

    if (Array.isArray(target)) {
        target.forEach(item => {
            if (item && typeof item === 'object') {
                stripKeysRecursively(item, keys, false);
            }
        });
        return;
    }

    if (!skipRoot) {
        keys.forEach(key => {
            if (Object.prototype.hasOwnProperty.call(target, key)) {
                delete target[key];
            }
        });
    }

    Object.keys(target).forEach(key => {
        const value = target[key];
        if (value && typeof value === 'object') {
            stripKeysRecursively(value, keys, false);
        }
    });
}

function pruneAdvancedCredentialPayload(record, { aggressive = false } = {}) {
    if (!record || typeof record !== 'object') {
        return;
    }

    let registrationSnapshot = null;
    if (record.registrationDetailSnapshot && typeof record.registrationDetailSnapshot === 'object') {
        try {
            registrationSnapshot = JSON.parse(JSON.stringify(record.registrationDetailSnapshot));
        } catch (error) {
            registrationSnapshot = { ...record.registrationDetailSnapshot };
        }
        delete record.registrationDetailSnapshot;
    }

    stripKeysRecursively(record, CERTIFICATE_COLLECTION_KEYS, true);
    stripKeysRecursively(record, HEAVY_DUPLICATE_KEYS, true);

    if (aggressive) {
        // Keep attestation certificate collections even in aggressively trimmed payloads so
        // credential detail views can reuse the parsed attestation data without re-decoding.
        AGGRESSIVE_DROP_KEYS.forEach(key => {
            if (Object.prototype.hasOwnProperty.call(record, key)) {
                delete record[key];
            }
        });
    }

    if (registrationSnapshot) {
        const sanitisedSnapshot = sanitiseRegistrationDetailSnapshot(registrationSnapshot);
        if (sanitisedSnapshot) {
            record.registrationDetailSnapshot = sanitisedSnapshot;
        }
    }
}

function prepareAdvancedCredentialForStorage(record, options = {}) {
    const clone = cloneAdvancedCredential(record);
    if (!clone) {
        return null;
    }
    pruneAdvancedCredentialPayload(clone, options);
    return clone;
}

function readAdvancedCredentials() {
    const stored = readStoredCredentials(ADVANCED_STORAGE_KEY);
    let needsPersist = false;

    const clonedRecords = stored
        .map(record => {
            const clone = cloneAdvancedStoredRecord(record);
            if (!clone) {
                return null;
            }
            if (clone.storageId && clone.storageId !== record.storageId) {
                needsPersist = true;
            }
            return clone;
        })
        .filter(Boolean);

    if (needsPersist) {
        persistAdvancedCredentials(clonedRecords);
    }

    return clonedRecords;
}

function persistAdvancedCredentials(records) {
    return persistStoredCredentials(ADVANCED_STORAGE_KEY, records);
}

function ensureBase64Url(value) {
    if (typeof value !== 'string' || !value.trim()) {
        return '';
    }
    const trimmed = value.trim();
    if (/^[A-Za-z0-9_-]+$/.test(trimmed)) {
        return trimmed;
    }
    try {
        const decoded = atob(trimmed);
        return btoa(decoded).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
    } catch (error) {
        try {
            const bytes = new Uint8Array(trimmed.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
            let binary = '';
            bytes.forEach(byte => {
                binary += String.fromCharCode(byte);
            });
            return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
        } catch (innerError) {
            return trimmed;
        }
    }
}

function cloneAdvancedCredential(record) {
    if (!record || typeof record !== 'object') {
        return null;
    }
    const credential = { type: 'advanced', ...record };
    if (!credential.credentialIdBase64Url) {
        credential.credentialIdBase64Url = ensureBase64Url(normaliseAdvancedCredentialId(credential));
    }
    ensureAdvancedCredentialStorageId(credential);
    return credential;
}

export function getAllAdvancedCredentials() {
    return readAdvancedCredentials().map(cloneAdvancedCredential).filter(Boolean);
}

export function saveAdvancedCredential(rawCredential) {
    if (!rawCredential || typeof rawCredential !== 'object') {
        return null;
    }

    const credential = cloneAdvancedCredential(rawCredential);
    if (!credential) {
        return null;
    }

    credential.type = 'advanced';

    const credentialId = normaliseAdvancedCredentialId(credential);
    if (!credentialId) {
        return null;
    }

    credential.credentialIdBase64Url = ensureBase64Url(credentialId);
    let storageId = ensureAdvancedCredentialStorageId(credential, { forceNew: !isNonEmptyString(credential.storageId) });

    const stored = readAdvancedCredentials();
    if (storageId && stored.some(item => item && typeof item === 'object' && item.storageId === storageId)) {
        storageId = ensureAdvancedCredentialStorageId(credential, { forceNew: true });
    }

    const sanitisedStored = stored
        .map(item => prepareAdvancedCredentialForStorage(item))
        .filter(Boolean);
    const sanitisedCredential = prepareAdvancedCredentialForStorage(credential);
    if (!sanitisedCredential) {
        return null;
    }

    const updated = sanitisedStored.concat(sanitisedCredential);
    if (persistAdvancedCredentials(updated)) {
        return sanitisedCredential;
    }

    const aggressivelyTrimmedStored = stored
        .map(item => prepareAdvancedCredentialForStorage(item, { aggressive: true }))
        .filter(Boolean);
    const aggressivelyTrimmedCredential = prepareAdvancedCredentialForStorage(credential, { aggressive: true });
    if (!aggressivelyTrimmedCredential) {
        return null;
    }

    const aggressiveSet = aggressivelyTrimmedStored.concat(aggressivelyTrimmedCredential);
    if (persistAdvancedCredentials(aggressiveSet)) {
        return aggressivelyTrimmedCredential;
    }

    return null;
}

export function removeAdvancedCredential(credentialId, storageId = null) {
    const id = credentialId ? String(credentialId) : '';
    const storageKey = isNonEmptyString(storageId) ? storageId.trim() : '';
    const stored = readAdvancedCredentials();
    const filtered = stored.filter(record => {
        if (!record || typeof record !== 'object') {
            return false;
        }
        if (storageKey) {
            return record.storageId !== storageKey;
        }
        if (!id) {
            return true;
        }
        return normaliseAdvancedCredentialId(record) !== id;
    });
    const changed = filtered.length !== stored.length;
    if (changed) {
        persistAdvancedCredentials(filtered);
    }
    return changed;
}

export function clearAdvancedCredentials() {
    persistAdvancedCredentials([]);
}

export function updateAdvancedCredentialSignCount(credentialId, signCount, storageId = null) {
    const id = credentialId ? String(credentialId) : '';
    const storageKey = isNonEmptyString(storageId) ? storageId.trim() : '';
    if (!id && !storageKey) {
        return false;
    }

    const stored = readAdvancedCredentials();
    let updated = false;
    const updatedRecords = stored.map(record => {
        if (!record || typeof record !== 'object') {
            return record;
        }
        if (storageKey) {
            if (record.storageId !== storageKey) {
                return record;
            }
        } else if (normaliseAdvancedCredentialId(record) !== id) {
            return record;
        }
        const clone = { ...record };
        if (typeof signCount === 'number' && Number.isFinite(signCount)) {
            clone.signCount = signCount;
        } else if (typeof clone.signCount === 'number' && Number.isFinite(clone.signCount)) {
            clone.signCount += 1;
        } else {
            clone.signCount = 1;
        }
        updated = true;
        return clone;
    });

    if (updated) {
        persistAdvancedCredentials(updatedRecords);
    }

    return updated;
}

export function updateAdvancedCredentialRegistrationSnapshot(storageId, snapshot) {
    const storageKey = isNonEmptyString(storageId) ? storageId.trim() : '';
    if (!storageKey || !snapshot || typeof snapshot !== 'object') {
        return false;
    }

    const sanitisedSnapshot = sanitiseRegistrationDetailSnapshot(snapshot);
    if (!sanitisedSnapshot) {
        return false;
    }

    const stored = readAdvancedCredentials();
    let updated = false;
    const updatedRecords = stored.map(record => {
        if (!record || typeof record !== 'object') {
            return record;
        }
        if (record.storageId !== storageKey) {
            return record;
        }
        const clone = { ...record };
        clone.registrationDetailSnapshot = sanitisedSnapshot;
        updated = true;
        return clone;
    });

    if (!updated) {
        return false;
    }

    const sanitised = updatedRecords
        .map(item => prepareAdvancedCredentialForStorage(item))
        .filter(Boolean);

    if (!sanitised.length) {
        return false;
    }

    return persistAdvancedCredentials(sanitised);
}

function extractAlgorithm(record) {
    const candidates = [
        record.algorithm,
        record.publicKeyAlgorithm,
        record.coseAlgorithm,
        record.publicKeyCose && record.publicKeyCose[3],
    ];
    for (const candidate of candidates) {
        if (typeof candidate === 'number' && Number.isFinite(candidate)) {
            return candidate;
        }
    }
    return undefined;
}

function extractPublicKey(record) {
    if (!record || typeof record !== 'object') {
        return '';
    }

    const preferredCandidates = [
        record.publicKey,
        record.publicKeyBase64,
        record.publicKeyBase64Url,
        record.publicKeyCbor,
    ];
    for (const candidate of preferredCandidates) {
        if (typeof candidate === 'string' && candidate.trim()) {
            return ensureBase64Url(candidate);
        }
    }

    const secondaryCandidates = [
        record.publicKeyBytes,
    ];
    for (const candidate of secondaryCandidates) {
        if (typeof candidate === 'string' && candidate.trim()) {
            return ensureBase64Url(candidate);
        }
    }

    if (record.publicKeyCose && typeof record.publicKeyCose === 'object') {
        try {
            const json = JSON.stringify(record.publicKeyCose);
            return ensureBase64Url(btoa(json));
        } catch (error) {
            return '';
        }
    }
    return '';
}

export function prepareAdvancedCredentialsForServer(credentials = null) {
    const source = Array.isArray(credentials) ? credentials : getAllAdvancedCredentials();
    if (!source.length) {
        return [];
    }

    const uniqueById = new Map();

    source
        .filter(item => item && typeof item === 'object')
        .forEach(item => {
            const credentialId = ensureBase64Url(normaliseAdvancedCredentialId(item));
            if (!credentialId) {
                return;
            }
            const publicKey = extractPublicKey(item);
            if (!publicKey) {
                return;
            }
            const aaguidCandidate = item.aaguidBase64Url || item.aaguid || item.aaguidHex;
            const aaguid = aaguidCandidate ? ensureBase64Url(String(aaguidCandidate)) : null;
            const signCount = Number.isFinite(item.signCount) ? Number(item.signCount) : 0;
            const algorithm = extractAlgorithm(item);
            const attachment = item.authenticatorAttachment || item.attachment || item.properties?.authenticatorAttachment;
            const residentSource = (
                item.resident ?? item.residentKey ?? item.discoverable ?? item.properties?.residentKey ??
                item.relyingParty?.residentKey
            );
            const resident = typeof residentSource === 'boolean' ? residentSource : Boolean(item.residentKey);

            const prepared = {
                credentialId,
                publicKey,
                aaguid,
                signCount,
                algorithm,
                authenticatorAttachment: attachment || null,
                resident,
            };

            if (!uniqueById.has(credentialId)) {
                uniqueById.set(credentialId, prepared);
            } else {
                const existing = uniqueById.get(credentialId);
                if (prepared.signCount > existing.signCount) {
                    uniqueById.set(credentialId, prepared);
                }
            }
        });

    return Array.from(uniqueById.values());
}

export default {
    getAllSimpleCredentials,
    getSimpleCredentialsForEmail,
    saveSimpleCredential,
    removeSimpleCredential,
    clearSimpleCredentials,
    updateSimpleCredentialSignCount,
    prepareCredentialsForServer,
    getAllAdvancedCredentials,
    saveAdvancedCredential,
    removeAdvancedCredential,
    clearAdvancedCredentials,
    updateAdvancedCredentialSignCount,
    updateAdvancedCredentialRegistrationSnapshot,
    prepareAdvancedCredentialsForServer,
};
