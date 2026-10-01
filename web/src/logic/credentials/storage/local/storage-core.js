import {
    LEGACY_ADVANCED_STORAGE_KEY,
    LEGACY_SIMPLE_STORAGE_KEY,
    SHARED_STORAGE_KEY,
} from './constants.js';
import { safeParse } from './common.js';
import { ensureRecordType, getRecordIdentifier } from './id-utils.js';
import { migrateStoredRecord } from './record-migration.js';

function recordsOrNull(records) {
    return Array.isArray(records)
        ? records.filter(item => item && typeof item === 'object')
        : null;
}

// The records read so far; until the first read, none, and the first read is
// the browser's storage. Tests seed them (seedUnifiedCredentialRecords); this
// module reads no page.
let bootUnifiedCredentialRecords = null;

/** Sets the records read so far (null: the next read is the browser's storage). */
export function seedUnifiedCredentialRecords(records) {
    bootUnifiedCredentialRecords = recordsOrNull(records);
}

const STORED_KEYS = [SHARED_STORAGE_KEY, LEGACY_SIMPLE_STORAGE_KEY, LEGACY_ADVANCED_STORAGE_KEY];

/**
 * Follows another tab's changes to the saved credentials. The browser tells a
 * page when another page of its origin changes localStorage (a `storage` event,
 * whose key is null when the storage was cleared); the records read so far are
 * then dropped, so the next read is the browser's storage and the next write
 * builds on what the other tab saved, and `onChange` is called. Gives the
 * function that stops following.
 */
export function followStoredCredentialChanges(onChange) {
    if (typeof window === 'undefined') {
        return () => {};
    }
    const listener = event => {
        if (event.key !== null && !STORED_KEYS.includes(event.key)) {
            return;
        }
        seedUnifiedCredentialRecords(null);
        onChange();
    };
    window.addEventListener('storage', listener);
    return () => window.removeEventListener('storage', listener);
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
            // Only objects are stored (safeParse and the seed drop the rest).
            const clone = ensureRecordType(record, fallbackType);
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

    seedUnifiedCredentialRecords(combined);
    return combined;
}

export function persistUnifiedCredentialRecords(records) {
    const payload = Array.isArray(records)
        ? records.filter(item => item && typeof item === 'object')
        : [];
    const success = persistStoredCredentials(SHARED_STORAGE_KEY, payload);
    if (success) {
        seedUnifiedCredentialRecords(payload);
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
