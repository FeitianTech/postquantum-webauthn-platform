import { extractByteArray, extractList } from './extractors.js';

export function normaliseIcon(icon, iconType) {
    if (!icon) {
        return '';
    }
    const value = String(icon).trim();
    if (!value) {
        return '';
    }
    if (/^data:/i.test(value)) {
        return value;
    }
    if (/^https?:\/\//i.test(value)) {
        return value;
    }
    const type = typeof iconType === 'string' && iconType.trim() ? iconType.trim() : 'image/png';
    return `data:${type};base64,${value}`;
}

export function resolveName(metadata, entry) {
    const description = metadata.description;
    if (typeof description === 'string' && description.trim()) {
        return description.trim();
    }
    if (description && typeof description === 'object') {
        const values = Object.values(description).filter(Boolean);
        if (values.length) {
            return String(values[0]).trim();
        }
    }
    const altDescriptions = metadata.alternativeDescriptions;
    if (altDescriptions) {
        const altValues = typeof altDescriptions === 'object' ? Object.values(altDescriptions) : [];
        const candidate = altValues.find(value => typeof value === 'string' && value.trim());
        if (candidate) {
            return candidate.trim();
        }
    }
    const statusDescriptor = entry?.statusReports?.find(report => report.certificationDescriptor)?.certificationDescriptor;
    if (statusDescriptor) {
        return statusDescriptor;
    }
    return 'Unknown Authenticator';
}

export function resolveIdentifier(entry, metadata) {
    if (entry?.aaguid) {
        return entry.aaguid;
    }
    if (metadata?.aaguid) {
        return metadata.aaguid;
    }
    if (metadata?.aaid) {
        return metadata.aaid;
    }
    const attestKeyIds = extractList(metadata?.attestationCertificateKeyIdentifiers);
    if (attestKeyIds.length) {
        return attestKeyIds[0];
    }
    return '—';
}

export function resolveAaguid(entry, metadata) {
    const candidates = [entry?.aaguid, metadata?.aaguid];
    for (const candidate of candidates) {
        const formatted = formatGuidCandidate(candidate);
        if (formatted) {
            return formatted;
        }
    }
    return '';
}

export function formatGuidCandidate(value) {
    if (value === undefined || value === null) {
        return '';
    }

    if (typeof value === 'string') {
        const trimmed = value.trim();
        if (!trimmed) {
            return '';
        }
        if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(trimmed)) {
            return trimmed.toLowerCase();
        }
        const clean = trimmed.replace(/[^0-9a-fA-F]/g, '').toLowerCase();
        if (clean.length === 32) {
            return `${clean.slice(0, 8)}-${clean.slice(8, 12)}-${clean.slice(12, 16)}-${clean.slice(16, 20)}-${clean.slice(20)}`;
        }
        return '';
    }

    const bytes = extractByteArray(value);
    if (bytes && bytes.length === 16) {
        const hex = bytes.map(byte => byte.toString(16).padStart(2, '0')).join('');
        return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
    }

    try {
        if (typeof value.toString === 'function') {
            return formatGuidCandidate(value.toString());
        }
    } catch (error) {
        // Ignore conversion errors.
    }
    return '';
}

export function normaliseAaguid(value) {
    const formatted = formatGuidCandidate(value);
    return formatted ? formatted.toLowerCase() : '';
}