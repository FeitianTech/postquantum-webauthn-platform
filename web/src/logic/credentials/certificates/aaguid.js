// The AAGUID an attestation certificate carries: in its fields, or in the FIDO
// AAGUID extension (1.3.6.1.4.1.45724.1.1.4) under whichever spelling the
// decoder gave its value. DOM-free.
import { aaguidHex } from '../../shared/aaguid.js';

const AAGUID_EXTENSION_OID = '1.3.6.1.4.1.45724.1.1.4';

export function extractAaguidFromExtensionValue(extValue) {
    if (!extValue) {
        return '';
    }

    if (typeof extValue === 'string') {
        return aaguidHex(extValue);
    }

    if (Array.isArray(extValue)) {
        for (const item of extValue) {
            const candidate = extractAaguidFromExtensionValue(item);
            if (candidate) {
                return candidate;
            }
        }
        return '';
    }

    if (typeof extValue === 'object') {
        const keys = Object.keys(extValue);

        for (const key of keys) {
            if (typeof key === 'string' && key.toLowerCase().includes('aaguid')) {
                const candidate = aaguidHex(extValue[key]);
                if (candidate) {
                    return candidate;
                }
            }
        }

        const fallbackKeys = [
            'value',
            'Value',
            'hex',
            'Hex',
            'hexValue',
            'Hex value',
            'raw',
            'rawHex',
        ];

        for (const key of fallbackKeys) {
            if (Object.hasOwn(extValue, key)) {
                const candidate = extractAaguidFromExtensionValue(extValue[key]);
                if (candidate) {
                    return candidate;
                }
            }
        }
    }

    return '';
}

export function extractAaguidFromCertificateEntry(entry) {
    if (!entry || typeof entry !== 'object') {
        return '';
    }

    if (entry.entry && entry.entry !== entry) {
        const nested = extractAaguidFromCertificateEntry(entry.entry);
        if (nested) {
            return nested;
        }
    }

    const parsed = entry.parsedX5c && typeof entry.parsedX5c === 'object' ? entry.parsedX5c : entry;

    const candidateSources = [
        entry.aaguid,
        entry.aaguidHex,
        entry.aaguidGuid,
        parsed?.aaguid,
        parsed?.aaguidHex,
        parsed?.aaguidGuid,
    ];

    for (const source of candidateSources) {
        const direct = aaguidHex(source);
        if (direct) {
            return direct;
        }
    }

    const extensions = Array.isArray(parsed?.extensions) ? parsed.extensions : [];
    for (const ext of extensions) {
        if (!ext || typeof ext !== 'object') {
            continue;
        }

        const oid = typeof ext.oid === 'string' ? ext.oid.trim() : '';
        const friendlyName = typeof ext.friendlyName === 'string' ? ext.friendlyName.trim().toLowerCase() : '';
        const extName = typeof ext.name === 'string' ? ext.name.trim().toLowerCase() : '';
        const isAaguidExtension = (
            oid === AAGUID_EXTENSION_OID
            || friendlyName.includes('aaguid')
            || extName.includes('aaguid')
        );

        if (!isAaguidExtension) {
            continue;
        }

        const valueCandidate = extractAaguidFromExtensionValue(ext.value);
        if (valueCandidate) {
            return valueCandidate;
        }
    }

    return '';
}

export function extractAaguidFromCertificateEntries(entries) {
    if (!entries) {
        return '';
    }

    if (!Array.isArray(entries)) {
        return extractAaguidFromCertificateEntry(entries);
    }

    for (const entry of entries) {
        const candidate = extractAaguidFromCertificateEntry(entry);
        if (candidate) {
            return candidate;
        }
    }

    return '';
}
