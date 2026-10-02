// The saved-credential list both interfaces show: which records, in what shape,
// and for each its name, its four checks, its tags, its identifiers and whether
// it links to FIDO MDS; the warm-up after the list is drawn. DOM-free. What it
// needs from the credential helpers and from storage is passed in.

import { normalizeToHex } from './record-fields.js';
import {
    ensureBase64Url,
    getRecordIdentifier,
    normaliseAdvancedCredentialId,
} from './storage/local/id-utils.js';

export const SAVED_LIST_TEXT = {
    empty: 'No credentials registered yet.',
    unknownUser: 'Unknown User',
    openMetadata: 'Open authenticator metadata',
};

// The checks a card shows, in its order: each true, false or unknown (null).
export const CREDENTIAL_CHECKS = [
    { key: 'signatureStatus', label: 'Signature' },
    { key: 'rootStatus', label: 'Root' },
    { key: 'rpidStatus', label: 'RPID' },
    { key: 'aaguidStatus', label: 'AAGUID' },
];

/**
 * The stored records as the list holds them: an advanced record with its storage
 * ids and normalised AAGUID, both kinds with their credential id and user handle
 * in hex. helpers: aaguidHex, getCredentialIdHex,
 * getCredentialUserHandleHex (credentials/record-fields.js).
 */
export function listSavedCredentials(records, helpers) {
    const { aaguidHex, getCredentialIdHex, getCredentialUserHandleHex } = helpers;
    return records.map(record => {
        if (record.type === 'advanced') {
            const relyingPartyInfo = record.relyingParty;
            const relyingPartyAaguid = relyingPartyInfo && typeof relyingPartyInfo === 'object'
                ? relyingPartyInfo.aaguid
                : null;
            const normalizedAaguidHex = aaguidHex(
                record.aaguidHex || record.aaguid || relyingPartyAaguid,
            );

            return {
                ...record,
                type: 'advanced',
                storageId: record.storageId || record.localStorageId || null,
                localStorageId: record.storageId || record.localStorageId || null,
                aaguidHex: normalizedAaguidHex || record.aaguidHex || null,
                credentialIdHex: getCredentialIdHex(record),
                userHandleHex: getCredentialUserHandleHex(record),
            };
        }

        return {
            ...record,
            type: 'simple',
            credentialIdHex: getCredentialIdHex(record),
            userHandleHex: getCredentialUserHandleHex(record),
        };
    });
}

/** A credential's key: its storage id, else its credential id (as storage de-duplicates them). */
export function credentialKey(credential) {
    return getRecordIdentifier(credential);
}

/**
 * What a card shows. inputs: indicators (deriveCredentialStatusIndicators:
 * each check, whether metadata is available, the dashed AAGUID), algorithmTag
 * (describeCredentialAlgorithmTag), credentialIdHex (getCredentialIdHex).
 * `mdsAaguid` is the AAGUID FIDO MDS opens, or '' when the card has no such
 * button (no AAGUID, or neither a valid root nor known metadata).
 */
export function describeCredentialCard(credential, { indicators, algorithmTag, credentialIdHex }) {
    const tags = [];
    if (algorithmTag) {
        tags.push(algorithmTag);
    }
    if (credential.residentKey === true) {
        tags.push('Discoverable');
    }
    if (credential.largeBlob === true) {
        tags.push('Large blob');
    }
    const { aaguidGuid, aaguidUnreadable, rootStatus, metadataAvailable } = indicators;
    return {
        name: credential.userName || credential.username || credential.email || SAVED_LIST_TEXT.unknownUser,
        checks: CREDENTIAL_CHECKS.map(check => ({ label: check.label, value: indicators[check.key] })),
        tags,
        mdsAaguid: aaguidGuid && (rootStatus === true || metadataAvailable) ? aaguidGuid.toLowerCase() : '',
        credentialIdHex: (credentialIdHex || '').toLowerCase(),
        credentialId: ensureBase64Url(normaliseAdvancedCredentialId(credential)),
        aaguid: aaguidGuid ? aaguidGuid.toLowerCase() : '',
        // A stored AAGUID no spelling reads, shown as it is stored.
        aaguidUnreadable: aaguidUnreadable || '',
    };
}

/** The key a flash after a ceremony matches a card by: the credential id in lower-case hex. */
export function credentialFlashKey(credentialId) {
    if (typeof credentialId !== 'string') {
        return '';
    }
    const normalized = normalizeToHex(credentialId.trim());
    return normalized ? normalized.toLowerCase() : '';
}

/**
 * After the list is drawn: heavy advanced records go to the server and missing
 * registration snapshots come from it; when anything changed the list is read
 * again. Gives whether anything changed; a failure is logged and changes nothing.
 * steps: syncArtifacts, prefetchSnapshots (storage), reload.
 */
export function warmSavedCredentials({ syncArtifacts, prefetchSnapshots, reload }) {
    return (async () => {
        const [artifactChanged, snapshotChanged] = await Promise.all([
            syncArtifacts(),
            prefetchSnapshots(),
        ]);
        const changed = Boolean(artifactChanged || snapshotChanged);
        if (changed) {
            await reload();
        }
        return changed;
    })()
        // A warm-up that fails changes nothing: the list shows what is stored.
        .catch(() => false);
}
