import {
    AGGRESSIVE_DROP_KEYS,
    CERTIFICATE_COLLECTION_KEYS,
    HEAVY_DUPLICATE_KEYS,
    LOCAL_HEAVY_PROPERTY_KEYS,
    LOCAL_HEAVY_RELYING_PARTY_KEYS,
    LOCAL_HEAVY_ROOT_KEYS,
    SERVER_ARTIFACT_VERSION,
} from './constants.js';
import {
    cloneJsonValue,
    isNonEmptyString,
    removeObjectKeys,
} from './common.js';
import {
    ensureAdvancedCredentialStorageId,
    ensureBase64Url,
    normaliseAdvancedCredentialId,
} from './id-utils.js';
import {
    partitionRecords,
    persistCredentialPartitions,
} from './partition-core.js';
import {
    sanitiseRegistrationDetailSnapshot,
    stripKeysRecursively,
} from './snapshot-sanitize.js';
import { readUnifiedCredentialRecords } from './storage-core.js';

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

export function summariseAdvancedCredentialForLocal(record, storageId, options = {}) {
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

export function recordHasHeavyData(record) {
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

export function cloneAdvancedCredential(record) {
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

export function cloneAdvancedStoredRecord(record) {
    if (!record || typeof record !== 'object') {
        return null;
    }
    const clone = { ...record };
    clone.type = clone.type || 'advanced';
    ensureAdvancedCredentialStorageId(clone);
    return clone;
}

export function pruneAdvancedCredentialPayload(record, { aggressive = false } = {}) {
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

export function prepareAdvancedCredentialForStorage(record, options = {}) {
    const clone = cloneAdvancedCredential(record);
    if (!clone) {
        return null;
    }
    pruneAdvancedCredentialPayload(clone, options);
    return clone;
}

export function readAdvancedCredentialPartitions() {
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
        persistCredentialPartitions(simple, advancedRecords, { prepareAdvancedCredentialForStorage });
    }

    return { simpleRecords: simple, advancedRecords };
}
