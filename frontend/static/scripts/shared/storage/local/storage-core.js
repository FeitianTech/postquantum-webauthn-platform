import {
    LEGACY_ADVANCED_STORAGE_KEY,
    LEGACY_SIMPLE_STORAGE_KEY,
    SHARED_STORAGE_KEY,
} from './constants.js';
import { safeParse } from './common.js';
import { ensureRecordType, getRecordIdentifier } from './id-utils.js';
import { migrateStoredRecord } from './record-migration.js';
import { readPageData } from '../../utils/page-data.js';

function recordsOrNull(records) {
    return Array.isArray(records)
        ? records.filter(item => item && typeof item === 'object')
        : null;
}

// The records read so far. The page gives none (the server renders no
// "initial-credential-records" block), so the first read is the browser's
// storage; tests give their records in that block instead.
let bootUnifiedCredentialRecords = recordsOrNull(readPageData('initial-credential-records'));

function setBootUnifiedCredentialRecords(records) {
    bootUnifiedCredentialRecords = recordsOrNull(records);
}

export function readStoredCredentials(storageKey) {
    if (typeof window === 'undefined' || !window.localStorage) {
        return [];
    }
    try {
        return safeParse(window.localStorage.getItem(storageKey));
    } catch (error) {
        return [];
    }
}

export function persistStoredCredentials(storageKey, records) {
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

export function readUnifiedCredentialRecords() {
    const combined = [];
    const seen = new Set();
    let recordsMigrated = false;

    const addRecords = (records, fallbackType = 'simple') => {
        if (!Array.isArray(records) || !records.length) {
            return;
        }
        records.forEach(stored => {
            const { record, changed } = migrateStoredRecord(stored);
            recordsMigrated = recordsMigrated || changed;
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

    let needsMigration = recordsMigrated;

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

export function persistUnifiedCredentialRecords(records) {
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
