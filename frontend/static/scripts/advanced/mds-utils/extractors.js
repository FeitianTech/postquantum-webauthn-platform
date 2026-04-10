import { formatEnum } from './formatters.js';

export function extractAttestationKeyIdentifiers(metadata, entry) {
    const map = new Map();
    const addValue = value => {
        if (value === undefined || value === null) {
            return;
        }
        const text = String(value).trim();
        if (!text) {
            return;
        }
        const key = text.toLowerCase();
        if (!map.has(key)) {
            map.set(key, text);
        }
    };

    extractList(metadata?.attestationCertificateKeyIdentifiers).forEach(addValue);
    extractList(entry?.attestationCertificateKeyIdentifiers).forEach(addValue);

    return Array.from(map.values());
}

export function extractByteArray(value) {
    if (!value) {
        return null;
    }
    if (Array.isArray(value)) {
        return value.every(item => Number.isInteger(item)) ? value : null;
    }
    if (value instanceof Uint8Array) {
        return Array.from(value);
    }
    if (ArrayBuffer.isView(value)) {
        return Array.from(new Uint8Array(value.buffer, value.byteOffset, value.byteLength));
    }
    if (value instanceof ArrayBuffer) {
        return Array.from(new Uint8Array(value));
    }
    return null;
}

export function extractUserVerification(details) {
    const values = new Set();
    if (Array.isArray(details)) {
        details.forEach(group => {
            if (Array.isArray(group)) {
                group.forEach(entry => {
                    if (entry && entry.userVerificationMethod) {
                        values.add(formatEnum(entry.userVerificationMethod));
                    }
                });
            }
        });
    }
    return Array.from(values).sort((a, b) => a.localeCompare(b));
}

export function extractTransports(metadata) {
    const infoTransports = extractList(metadata?.authenticatorGetInfo?.transports);
    const metadataTransports = extractList(metadata?.transports);
    const combined = new Set([
        ...infoTransports.map(formatEnum),
        ...metadataTransports.map(formatEnum),
    ]);
    return Array.from(combined).sort((a, b) => a.localeCompare(b));
}

export function extractList(value) {
    if (!value) {
        return [];
    }
    if (Array.isArray(value)) {
        return value.filter(Boolean);
    }
    return [value];
}