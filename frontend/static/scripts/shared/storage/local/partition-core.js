import { buildRecordKey, ensureRecordType } from './id-utils.js';
import {
    persistUnifiedCredentialRecords,
    readUnifiedCredentialRecords,
} from './storage-core.js';

export function partitionRecords(records) {
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

export function persistCredentialPartitions(simpleRecords, advancedRecords, options = {}) {
    const { prepareAdvancedCredentialForStorage } = options;

    const preparedSimple = Array.isArray(simpleRecords)
        ? simpleRecords
            .filter(item => item && typeof item === 'object')
            .map(item => ({ ...item, type: 'simple' }))
        : [];

    const preparedAdvanced = Array.isArray(advancedRecords)
        ? advancedRecords
            .map(item => {
                if (typeof prepareAdvancedCredentialForStorage === 'function') {
                    return prepareAdvancedCredentialForStorage(item);
                }
                return ensureRecordType(item, 'advanced');
            })
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
