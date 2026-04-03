import {
    fetchCredentialArtifactsBulk,
    uploadCredentialArtifact,
    updateCredentialSnapshot as uploadSnapshotToServer,
} from './credential-artifacts-client.js';

const SHARED_STORAGE_KEY = 'postquantum-webauthn.credentials';
const LEGACY_SIMPLE_STORAGE_KEY = 'postquantum-webauthn.simpleCredentials';
const LEGACY_ADVANCED_STORAGE_KEY = 'postquantum-webauthn.advancedCredentials';
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
const SERVER_ARTIFACT_VERSION = 1;
const LOCAL_HEAVY_ROOT_KEYS = [
    'attestationObject',
    'attestation_object',
    'attestationObjectRaw',
    'attestation_object_raw',
    'attestationObjectDecoded',
    'attestation_object_decoded',
    'attestationStatement',
    'attestation_statement',
    'attestationCertificate',
    'attestation_certificate',
    'attestationCertificates',
    'attestation_certificates',
    'attestationCertificatesDetails',
    'attestation_certificates_details',
    'registrationResponse',
    'registration_response',
    'registrationCredential',
    'registration_credential',
    'registrationResult',
    'registration_result',
    'registrationDetailHtml',
    'registration_detail_html',
    'registrationDetailCombinedHtml',
    'registration_detail_combined_html',
    'registrationDetailCopy',
    'registration_detail_copy',
    'registrationData',
    'registration_data',
    'clientDataJSON',
    'clientData',
    'clientDataParsed',
    'clientDataObject',
    'client_data_json',
    'authenticatorData',
    'authenticator_data',
    'authenticatorDataHex',
    'authenticator_data_hex',
    'authenticatorDataHash',
    'authenticator_data_hash',
];
const LOCAL_HEAVY_PROPERTY_KEYS = [
    'attestationCertificate',
    'attestationCertificates',
    'attestation_certificate',
    'attestation_certificates',
    'attestationChecks',
    'attestation_checks',
    'registrationData',
    'registration_data',
];
const LOCAL_HEAVY_RELYING_PARTY_KEYS = [
    'registrationData',
    'registration_data',
    'attestationCertificate',
    'attestationCertificates',
    'attestation_certificate',
    'attestation_certificates',
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
let bootUnifiedCredentialRecords = (
    typeof window !== 'undefined'
    && Array.isArray(window.__INITIAL_CREDENTIAL_RECORDS__)
)
    ? window.__INITIAL_CREDENTIAL_RECORDS__.filter(item => item && typeof item === 'object')
    : null;

function setBootUnifiedCredentialRecords(records) {
    bootUnifiedCredentialRecords = Array.isArray(records)
        ? records.filter(item => item && typeof item === 'object')
        : null;

    if (typeof window !== 'undefined') {
        window.__INITIAL_CREDENTIAL_RECORDS__ = bootUnifiedCredentialRecords || [];
    }
}

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

function removeObjectKeys(target, keys) {
    if (!target || typeof target !== 'object' || !Array.isArray(keys)) {
        return;
    }
    keys.forEach(key => {
        if (Object.prototype.hasOwnProperty.call(target, key)) {
            delete target[key];
        }
    });
}

function summarisePropertiesForLocal(properties) {
    if (!properties || typeof properties !== 'object') {
        return null;
    }
    const clone = { ...properties };
    removeObjectKeys(clone, LOCAL_HEAVY_PROPERTY_KEYS);
    return Object.keys(clone).length ? clone : null;
}

function summariseRelyingPartyForLocal(relyingParty) {
    if (!relyingParty || typeof relyingParty !== 'object') {
        return null;
    }
    const clone = { ...relyingParty };
    removeObjectKeys(clone, LOCAL_HEAVY_RELYING_PARTY_KEYS);
    return Object.keys(clone).length ? clone : null;
}

function summariseAdvancedCredentialForLocal(record, storageId, options = {}) {
    if (!record || typeof record !== 'object') {
        return null;
    }
    const { hasArtifact = true } = options;
    const summary = { ...record, type: 'advanced' };
    removeObjectKeys(summary, LOCAL_HEAVY_ROOT_KEYS);

    const snapshot = sanitiseRegistrationDetailSnapshot(record.registrationDetailSnapshot);
    if (snapshot) {
        summary.registrationDetailSnapshot = snapshot;
    }

    if (summary.properties && typeof summary.properties === 'object') {
        const propertiesSummary = summarisePropertiesForLocal(summary.properties);
        if (propertiesSummary) {
            summary.properties = propertiesSummary;
        } else {
            delete summary.properties;
        }
    }

    if (summary.relyingParty && typeof summary.relyingParty === 'object') {
        const rpSummary = summariseRelyingPartyForLocal(summary.relyingParty);
        if (rpSummary) {
            summary.relyingParty = rpSummary;
        } else {
            delete summary.relyingParty;
        }
    }

    if (storageId && isNonEmptyString(storageId)) {
        summary.storageId = storageId.trim();
        summary.localStorageId = summary.storageId;
    }

    summary.hasServerArtifact = Boolean(hasArtifact);
    summary.artifactVersion = SERVER_ARTIFACT_VERSION;

    return summary;
}

function recordHasHeavyData(record) {
    if (!record || typeof record !== 'object') {
        return false;
    }
    const rootKeyPresent = LOCAL_HEAVY_ROOT_KEYS.some(key => record[key] !== undefined && record[key] !== null);
    if (rootKeyPresent) {
        return true;
    }
    const props = record.properties;
    if (props && typeof props === 'object') {
        if (LOCAL_HEAVY_PROPERTY_KEYS.some(key => props[key] !== undefined && props[key] !== null)) {
            return true;
        }
    }
    const rp = record.relyingParty;
    if (rp && typeof rp === 'object') {
        if (LOCAL_HEAVY_RELYING_PARTY_KEYS.some(key => rp[key] !== undefined && rp[key] !== null)) {
            return true;
        }
    }
    return false;
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

function getRecordIdentifier(record) {
    if (!record || typeof record !== 'object') {
        return '';
    }
    if (isNonEmptyString(record.storageId)) {
        return `storage:${record.storageId.trim()}`;
    }
    const advancedId = normaliseAdvancedCredentialId(record);
    if (advancedId) {
        return `id:${advancedId}`;
    }
    const simpleId = normaliseCredentialId(record);
    if (simpleId) {
        return `id:${simpleId}`;
    }
    return '';
}

function ensureRecordType(record, fallbackType = 'simple') {
    if (!record || typeof record !== 'object') {
        return null;
    }
    const clone = { ...record };
    const type = clone.type === 'advanced' ? 'advanced' : (clone.type === 'simple' ? 'simple' : fallbackType);
    clone.type = type === 'advanced' ? 'advanced' : 'simple';
    return clone;
}

function readUnifiedCredentialRecords() {
    const combined = [];
    const seen = new Set();

    const addRecords = (records, fallbackType = 'simple') => {
        if (!Array.isArray(records) || !records.length) {
            return;
        }
        records.forEach(record => {
            const clone = ensureRecordType(record, fallbackType);
            if (!clone) {
                return;
            }
            const identifier = getRecordIdentifier(clone);
            if (!identifier || seen.has(identifier)) {
                return;
            }
            seen.add(identifier);
            combined.push(clone);
        });
    };

    if (Array.isArray(bootUnifiedCredentialRecords)) {
        addRecords(bootUnifiedCredentialRecords, 'simple');
        return combined;
    }

    addRecords(readStoredCredentials(SHARED_STORAGE_KEY), 'simple');

    const legacyAdvanced = readStoredCredentials(LEGACY_ADVANCED_STORAGE_KEY);
    const legacySimple = readStoredCredentials(LEGACY_SIMPLE_STORAGE_KEY);

    let needsMigration = false;

    if (legacyAdvanced.length) {
        needsMigration = true;
        addRecords(legacyAdvanced, 'advanced');
    }

    if (legacySimple.length) {
        needsMigration = true;
        addRecords(legacySimple, 'simple');
    }

    if (needsMigration) {
        persistUnifiedCredentialRecords(combined);
    }

    setBootUnifiedCredentialRecords(combined);
    return combined;
}

function persistUnifiedCredentialRecords(records) {
    const payload = Array.isArray(records)
        ? records.filter(item => item && typeof item === 'object')
        : [];
    const success = persistStoredCredentials(SHARED_STORAGE_KEY, payload);
    if (success) {
        setBootUnifiedCredentialRecords(payload);
    }
    if (success && typeof window !== 'undefined' && window.localStorage) {
        try {
            window.localStorage.removeItem(LEGACY_SIMPLE_STORAGE_KEY);
        } catch (error) {
            // Ignore removal errors.
        }
        try {
            window.localStorage.removeItem(LEGACY_ADVANCED_STORAGE_KEY);
        } catch (error) {
            // Ignore removal errors.
        }
    }
    return success;
}

let advancedArtifactSyncPromise = null;
let advancedSnapshotSyncPromise = null;

async function synchroniseAdvancedCredentialArtifacts() {
    const records = readStoredCredentials(SHARED_STORAGE_KEY);
    if (!Array.isArray(records) || !records.length) {
        return false;
    }

    let changed = false;
    const updatedRecords = [];

    for (const record of records) {
        if (!record || typeof record !== 'object') {
            continue;
        }
        if ((record.type || 'simple') !== 'advanced') {
            updatedRecords.push(record);
            continue;
        }

        const working = { ...record, type: 'advanced' };
        ensureAdvancedCredentialStorageId(working);
        const storageId = isNonEmptyString(working.storageId) ? working.storageId.trim() : '';

        const needsUpload = (
            !working.hasServerArtifact
            || Number(working.artifactVersion) < SERVER_ARTIFACT_VERSION
        ) && recordHasHeavyData(record);

        let artifactAvailable = Boolean(working.hasServerArtifact);

        if (needsUpload && storageId) {
            const artifactRecord = cloneJsonValue(record) || record;
            const payload = {
                schemaVersion: SERVER_ARTIFACT_VERSION,
                storedCredential: artifactRecord,
            };
            const uploaded = await uploadCredentialArtifact(storageId, payload, { merge: true });
            if (uploaded) {
                artifactAvailable = true;
            }
        }

        let recordForStorage = record;
        if (artifactAvailable) {
            const summary = summariseAdvancedCredentialForLocal(working, storageId, { hasArtifact: artifactAvailable });
            if (summary) {
                recordForStorage = summary;
            }
            if (recordForStorage !== record) {
                changed = true;
            }
        }

        updatedRecords.push(recordForStorage);

        if (
            artifactAvailable
            && (
                !working.hasServerArtifact
                || Number(working.artifactVersion) < SERVER_ARTIFACT_VERSION
                || recordHasHeavyData(record)
            )
        ) {
            changed = true;
        }
    }

    if (changed) {
        persistUnifiedCredentialRecords(updatedRecords);
    }

    return changed;
}

export function ensureAdvancedCredentialArtifactsSynced() {
    if (!advancedArtifactSyncPromise) {
        advancedArtifactSyncPromise = synchroniseAdvancedCredentialArtifacts()
            .catch(error => {
                console.warn('Failed to synchronise advanced credential artifacts', error);
                return false;
            })
            .finally(() => {
                advancedArtifactSyncPromise = null;
            });
    }
    return advancedArtifactSyncPromise;
}

async function synchroniseAdvancedCredentialSnapshots() {
    const records = readUnifiedCredentialRecords();
    if (!Array.isArray(records) || !records.length) {
        return false;
    }

    const missingStorageIds = [];
    const seen = new Set();

    records.forEach(record => {
        if (!record || typeof record !== 'object' || (record.type || 'simple') !== 'advanced') {
            return;
        }

        if (record.registrationDetailSnapshot && typeof record.registrationDetailSnapshot === 'object') {
            return;
        }
        if (!record.hasServerArtifact) {
            return;
        }

        const storageId = isNonEmptyString(record.storageId)
            ? record.storageId.trim()
            : (isNonEmptyString(record.localStorageId) ? record.localStorageId.trim() : '');
        if (!storageId || seen.has(storageId)) {
            return;
        }

        seen.add(storageId);
        missingStorageIds.push(storageId);
    });

    if (!missingStorageIds.length) {
        return false;
    }

    const artifacts = await fetchCredentialArtifactsBulk(missingStorageIds);
    if (!artifacts || typeof artifacts !== 'object') {
        return false;
    }

    let changed = false;
    const updatedRecords = records.map(record => {
        if (!record || typeof record !== 'object' || (record.type || 'simple') !== 'advanced') {
            return record;
        }

        const storageId = isNonEmptyString(record.storageId)
            ? record.storageId.trim()
            : (isNonEmptyString(record.localStorageId) ? record.localStorageId.trim() : '');
        if (!storageId) {
            return record;
        }

        const artifact = artifacts[storageId];
        if (!artifact || typeof artifact !== 'object') {
            return record;
        }

        const snapshotCandidate = artifact.registrationDetailSnapshot
            || artifact.storedCredential?.registrationDetailSnapshot;
        const snapshot = sanitiseRegistrationDetailSnapshot(snapshotCandidate);
        if (!snapshot) {
            return record;
        }

        changed = true;
        return {
            ...record,
            registrationDetailSnapshot: snapshot,
            hasServerArtifact: true,
            artifactVersion: SERVER_ARTIFACT_VERSION,
        };
    });

    if (changed) {
        persistUnifiedCredentialRecords(updatedRecords);
    }

    return changed;
}

export function ensureAdvancedCredentialSnapshotsPrefetched() {
    if (!advancedSnapshotSyncPromise) {
        advancedSnapshotSyncPromise = synchroniseAdvancedCredentialSnapshots()
            .catch(error => {
                console.warn('Failed to prefetch advanced credential snapshots', error);
                return false;
            })
            .finally(() => {
                advancedSnapshotSyncPromise = null;
            });
    }
    return advancedSnapshotSyncPromise;
}

function partitionRecords(records) {
    const simple = [];
    const advanced = [];

    if (!Array.isArray(records)) {
        return { simple, advanced };
    }

    records.forEach(record => {
        const clone = ensureRecordType(record);
        if (!clone) {
            return;
        }
        if (clone.type === 'advanced') {
            advanced.push(clone);
        } else {
            simple.push(clone);
        }
    });

    return { simple, advanced };
}

function persistCredentialPartitions(simpleRecords, advancedRecords) {
    const preparedSimple = Array.isArray(simpleRecords)
        ? simpleRecords
            .filter(item => item && typeof item === 'object')
            .map(item => ({ ...item, type: 'simple' }))
        : [];

    const preparedAdvanced = Array.isArray(advancedRecords)
        ? advancedRecords
            .map(item => prepareAdvancedCredentialForStorage(item))
            .filter(Boolean)
        : [];

    const buildEntries = (records, fallbackType) => {
        return records.map(record => {
            const key = buildRecordKey(record, fallbackType);
            return key ? { key, record } : null;
        }).filter(Boolean);
    };

    const simpleEntries = buildEntries(preparedSimple, 'simple');
    const advancedEntries = buildEntries(preparedAdvanced, 'advanced');

    const entryMap = new Map();
    simpleEntries.forEach(entry => entryMap.set(entry.key, entry));
    advancedEntries.forEach(entry => entryMap.set(entry.key, entry));

    const current = readUnifiedCredentialRecords();
    const nextRecords = [];

    if (Array.isArray(current) && current.length) {
        current.forEach(record => {
            const key = buildRecordKey(record);
            if (!key) {
                return;
            }
            const entry = entryMap.get(key);
            if (entry) {
                nextRecords.push(entry.record);
                entryMap.delete(key);
            }
        });
    }

    const appendRemaining = entries => {
        entries.forEach(entry => {
            if (!entryMap.has(entry.key)) {
                return;
            }
            nextRecords.push(entry.record);
            entryMap.delete(entry.key);
        });
    };

    appendRemaining(simpleEntries);
    appendRemaining(advancedEntries);

    return persistUnifiedCredentialRecords(nextRecords);
}

function buildRecordKey(record, fallbackType = 'simple') {
    const typed = ensureRecordType(record, fallbackType);
    if (!typed) {
        return '';
    }
    const identifier = getRecordIdentifier(typed);
    if (identifier) {
        return `${typed.type}:${identifier}`;
    }
    return `${typed.type}:generated:${generateRandomIdSegment()}`;
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

export function getAllStoredCredentialsInOrder() {
    const orderedRecords = readUnifiedCredentialRecords();
    if (!Array.isArray(orderedRecords) || !orderedRecords.length) {
        return [];
    }

    return orderedRecords
        .map(record => {
            if (!record || typeof record !== 'object') {
                return null;
            }

            if ((record.type || 'simple') === 'advanced') {
                const clone = cloneAdvancedStoredRecord(record);
                return clone ? clone : null;
            }

            const clone = cloneCredential(record);
            if (!clone) {
                return null;
            }
            clone.type = clone.type === 'advanced' ? 'advanced' : 'simple';
            return clone;
        })
        .filter(Boolean);
}

export function getAllSimpleCredentials() {
    const { simple } = partitionRecords(readUnifiedCredentialRecords());
    return simple.map(cloneCredential).filter(Boolean);
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

    const { simple: simpleStored, advanced: advancedStored } = partitionRecords(readUnifiedCredentialRecords());

    const updatedAdvanced = advancedStored.map(record => {
        const recordId = normaliseAdvancedCredentialId(record) || normaliseCredentialId(record);
        if (recordId !== credentialId) {
            return record;
        }
        const clone = { ...record };
        clone.email = credential.email;
        clone.userName = credential.userName;
        clone.username = credential.username;
        clone.signCount = credential.signCount;
        return clone;
    });

    const advancedHasMatch = updatedAdvanced.some(record => {
        const recordId = normaliseAdvancedCredentialId(record) || normaliseCredentialId(record);
        return recordId === credentialId;
    });

    const filteredSimple = simpleStored.filter(item => normaliseCredentialId(item) !== credentialId);
    if (!advancedHasMatch) {
        filteredSimple.push(credential);
    }

    const success = persistCredentialPartitions(filteredSimple, updatedAdvanced);
    return success ? credential : null;
}

export function removeSimpleCredential(credentialId, email) {
    const id = credentialId ? String(credentialId) : '';
    if (!id) {
        return false;
    }

    const { simple: simpleStored, advanced: advancedStored } = partitionRecords(readUnifiedCredentialRecords());
    const normalisedEmail = email ? String(email).toLowerCase() : null;

    const filteredSimple = simpleStored.filter(record => {
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

    const changed = filteredSimple.length !== simpleStored.length;
    if (changed) {
        persistCredentialPartitions(filteredSimple, advancedStored);
    }
    return changed;
}

export function clearSimpleCredentials() {
    const { advanced } = partitionRecords(readUnifiedCredentialRecords());
    persistCredentialPartitions([], advanced);
}

export function updateSimpleCredentialSignCount(email, credentialId, signCount) {
    const id = credentialId ? String(credentialId) : '';
    if (!id) {
        return false;
    }

    const { simple: simpleStored, advanced: advancedStored } = partitionRecords(readUnifiedCredentialRecords());
    const normalisedEmail = email ? String(email).toLowerCase() : null;
    let updated = false;

    const updatedSimple = simpleStored.map(record => {
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

    const updatedAdvanced = advancedStored.map(record => {
        const recordId = normaliseAdvancedCredentialId(record) || normaliseCredentialId(record);
        if (recordId !== id) {
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
        persistCredentialPartitions(updatedSimple, updatedAdvanced);
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

function readAdvancedCredentialPartitions() {
    const { simple, advanced } = partitionRecords(readUnifiedCredentialRecords());
    let needsPersist = false;

    const advancedRecords = advanced
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
        persistCredentialPartitions(simple, advancedRecords);
    }

    return { simpleRecords: simple, advancedRecords };
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
    const { advancedRecords } = readAdvancedCredentialPartitions();
    return advancedRecords.map(cloneAdvancedCredential).filter(Boolean);
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

    const { simpleRecords, advancedRecords } = readAdvancedCredentialPartitions();

    let mergedEmail = credential.email || credential.userName || credential.username || '';
    let mergedSignCount = Number.isFinite(credential.signCount) ? Number(credential.signCount) : null;

    const filteredSimple = simpleRecords.filter(record => {
        const recordId = normaliseCredentialId(record);
        if (recordId !== credentialId) {
            return true;
        }
        if (!mergedEmail) {
            mergedEmail = record.email || record.userName || record.username || '';
        }
        if (!Number.isFinite(mergedSignCount) && Number.isFinite(record.signCount)) {
            mergedSignCount = Number(record.signCount);
        }
        return false;
    });

    const filteredAdvanced = [];
    advancedRecords.forEach(record => {
        if (!record || typeof record !== 'object') {
            return;
        }
        const recordStorageId = isNonEmptyString(record.storageId) ? record.storageId.trim() : '';
        const recordId = normaliseAdvancedCredentialId(record) || normaliseCredentialId(record);
        if ((recordStorageId && storageId && recordStorageId === storageId) || (recordId && recordId === credentialId)) {
            if (!mergedEmail) {
                mergedEmail = record.email || record.userName || record.username || '';
            }
            if (!Number.isFinite(mergedSignCount) && Number.isFinite(record.signCount)) {
                mergedSignCount = Number(record.signCount);
            }
            return;
        }
        filteredAdvanced.push(record);
    });

    credential.email = credential.email || mergedEmail || '';
    if (!credential.userName && mergedEmail) {
        credential.userName = mergedEmail;
    }
    if (!credential.username && mergedEmail) {
        credential.username = mergedEmail;
    }
    if (!Number.isFinite(credential.signCount)) {
        credential.signCount = Number.isFinite(mergedSignCount) ? Number(mergedSignCount) : 0;
    }

    if (storageId && filteredAdvanced.some(item => item && typeof item === 'object' && item.storageId === storageId)) {
        storageId = ensureAdvancedCredentialStorageId(credential, { forceNew: true });
    }

    const sanitisedStored = filteredAdvanced
        .map(item => prepareAdvancedCredentialForStorage(item))
        .filter(Boolean);
    const sanitisedCredential = prepareAdvancedCredentialForStorage(credential);
    if (!sanitisedCredential) {
        return null;
    }

    const updatedAdvanced = sanitisedStored.concat(sanitisedCredential);
    if (persistCredentialPartitions(filteredSimple, updatedAdvanced)) {
        return sanitisedCredential;
    }

    const aggressivelyTrimmedStored = filteredAdvanced
        .map(item => prepareAdvancedCredentialForStorage(item, { aggressive: true }))
        .filter(Boolean);
    const aggressivelyTrimmedCredential = prepareAdvancedCredentialForStorage(credential, { aggressive: true });
    if (!aggressivelyTrimmedCredential) {
        return null;
    }

    const aggressiveSet = aggressivelyTrimmedStored.concat(aggressivelyTrimmedCredential);
    if (persistCredentialPartitions(filteredSimple, aggressiveSet)) {
        return aggressivelyTrimmedCredential;
    }

    return null;
}

export function removeAdvancedCredential(credentialId, storageId = null) {
    const id = credentialId ? String(credentialId) : '';
    const storageKey = isNonEmptyString(storageId) ? storageId.trim() : '';
    const { simpleRecords, advancedRecords } = readAdvancedCredentialPartitions();
    const filteredAdvanced = advancedRecords.filter(record => {
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
    const changed = filteredAdvanced.length !== advancedRecords.length;
    if (changed) {
        persistCredentialPartitions(simpleRecords, filteredAdvanced);
    }
    return changed;
}

export function clearAdvancedCredentials() {
    const { simpleRecords } = readAdvancedCredentialPartitions();
    persistCredentialPartitions(simpleRecords, []);
}

export function updateAdvancedCredentialSignCount(credentialId, signCount, storageId = null) {
    const id = credentialId ? String(credentialId) : '';
    const storageKey = isNonEmptyString(storageId) ? storageId.trim() : '';
    if (!id && !storageKey) {
        return false;
    }

    const { simpleRecords, advancedRecords } = readAdvancedCredentialPartitions();
    let updated = false;
    const updatedAdvanced = advancedRecords.map(record => {
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

    const updatedSimple = simpleRecords.map(record => {
        if (!record || typeof record !== 'object') {
            return record;
        }
        const recordId = normaliseCredentialId(record);
        if (!recordId || recordId !== id) {
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
        persistCredentialPartitions(updatedSimple, updatedAdvanced);
    }

    return updated;
}

export async function updateAdvancedCredentialRegistrationSnapshot(storageId, snapshot) {
    const storageKey = isNonEmptyString(storageId) ? storageId.trim() : '';
    if (!storageKey || !snapshot || typeof snapshot !== 'object') {
        return false;
    }

    const sanitisedSnapshot = sanitiseRegistrationDetailSnapshot(snapshot);
    if (!sanitisedSnapshot) {
        return false;
    }

    const records = readUnifiedCredentialRecords();
    let changed = false;
    const updatedRecords = records.map(record => {
        if (!record || typeof record !== 'object' || (record.type || 'simple') !== 'advanced') {
            return record;
        }

        const recordStorageId = isNonEmptyString(record.storageId)
            ? record.storageId.trim()
            : (isNonEmptyString(record.localStorageId) ? record.localStorageId.trim() : '');
        if (recordStorageId !== storageKey) {
            return record;
        }

        changed = true;
        return {
            ...record,
            registrationDetailSnapshot: sanitisedSnapshot,
            hasServerArtifact: true,
            artifactVersion: SERVER_ARTIFACT_VERSION,
        };
    });

    if (changed) {
        persistUnifiedCredentialRecords(updatedRecords);
    }

    const uploaded = await uploadSnapshotToServer(storageKey, sanitisedSnapshot);
    return changed || uploaded;
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

};
