// Records saved by earlier versions, brought to today's format when they are read.
//
// Registration detail used to be stored as composed HTML: in the snapshot and
// under raw registrationDetailHtml-style keys. The detail view is now built from
// data and never reads markup, so the markup is dropped; the snapshot's
// structured state stays.
//
// Byte fields the server did not label used to arrive as standard base64; they
// are base64url now, like every byte field on the wire. The old spelling is
// re-spelled by decoding it strictly and encoding the same bytes as base64url, so
// nothing is lost. Only fields known to hold bytes are touched: fields named for
// base64 (publicKeyBase64, userHandleBase64, ...) keep their spelling, and so do
// extension outputs and properties, where text and bytes cannot be told apart.

import { base64ToBytes, bytesToBase64Url } from '../../utils/base64.js';

const ROOT_BYTE_FIELDS = ['credentialId', 'publicKey', 'publicKeyBytes', 'userHandle'];
// attStmt byte strings (WebAuthn L3 section 8); `ver` and `alg` are not bytes.
const ATTESTATION_BYTE_FIELDS = ['sig', 'certInfo', 'pubArea', 'response', 'ecdaaKeyId'];
const STANDARD_ONLY = /[+/=]/;

const RECORD_MARKUP_KEYS = [
    'registrationDetailHtml',
    'registration_detail_html',
    'registrationDetailCombinedHtml',
    'registration_detail_combined_html',
];

const SNAPSHOT_KEYS = [
    'registrationDetailSnapshot',
    'registration_detail_snapshot',
    'registrationDetailCopy',
    'registration_detail_copy',
];

const SNAPSHOT_MARKUP_KEYS = ['html', 'attestationSectionHtml', 'combinedHtml'];

function hasOwn(target, key) {
    return Object.prototype.hasOwnProperty.call(target, key);
}

// The same bytes in base64url when `value` is standard base64 that base64url
// could not be; anything else is returned as it is.
function respell(value) {
    if (typeof value !== 'string' || !STANDARD_ONLY.test(value)) {
        return value;
    }
    try {
        return bytesToBase64Url(base64ToBytes(value));
    } catch (error) {
        return value;
    }
}

function respellEntries(source, keys) {
    let changed = false;
    const result = Array.isArray(source) ? [...source] : { ...source };
    keys.forEach(key => {
        const respelled = respell(result[key]);
        if (respelled !== result[key]) {
            result[key] = respelled;
            changed = true;
        }
    });
    return changed ? result : source;
}

function respellByteFields(record, edit) {
    ROOT_BYTE_FIELDS.forEach(key => {
        const respelled = respell(record[key]);
        if (respelled !== record[key]) {
            edit()[key] = respelled;
        }
    });

    const cose = record.publicKeyCose;
    if (cose && typeof cose === 'object' && !Array.isArray(cose)) {
        const respelled = respellEntries(cose, Object.keys(cose));
        if (respelled !== cose) {
            edit().publicKeyCose = respelled;
        }
    }

    const statement = record.attestationStatement;
    if (statement && typeof statement === 'object' && !Array.isArray(statement)) {
        let respelled = respellEntries(statement, ATTESTATION_BYTE_FIELDS);
        if (Array.isArray(statement.x5c)) {
            const chain = respellEntries(statement.x5c, statement.x5c.map((_, index) => index));
            if (chain !== statement.x5c) {
                respelled = { ...respelled, x5c: chain };
            }
        }
        if (respelled !== statement) {
            edit().attestationStatement = respelled;
        }
    }
}

/** The record in today's format, and whether anything had to change. */
export function migrateStoredRecord(record) {
    if (!record || typeof record !== 'object') {
        return { record, changed: false };
    }

    let migrated = record;
    const edit = () => {
        if (migrated === record) {
            migrated = { ...record };
        }
        return migrated;
    };

    RECORD_MARKUP_KEYS.forEach(key => {
        if (hasOwn(migrated, key)) {
            delete edit()[key];
        }
    });

    SNAPSHOT_KEYS.forEach(key => {
        const snapshot = migrated[key];
        if (!snapshot || typeof snapshot !== 'object' || !SNAPSHOT_MARKUP_KEYS.some(name => hasOwn(snapshot, name))) {
            return;
        }
        const cleaned = { ...snapshot };
        SNAPSHOT_MARKUP_KEYS.forEach(name => {
            delete cleaned[name];
        });
        // A snapshot that held only markup holds nothing now; without it the
        // record is completed from its server artifact again.
        if (cleaned.state || cleaned.stateSnapshot || cleaned.response) {
            edit()[key] = cleaned;
        } else {
            delete edit()[key];
        }
    });

    respellByteFields(migrated, edit);

    return { record: migrated, changed: migrated !== record };
}
