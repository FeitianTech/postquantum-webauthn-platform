export function formatUpv(upv) {
    const list = Array.isArray(upv) ? upv : upv ? [upv] : [];
    const formatted = [];
    list.forEach(item => {
        if (item && typeof item === 'object') {
            const major = item.major ?? item.Major;
            const minor = item.minor ?? item.Minor;
            if (major !== undefined && minor !== undefined) {
                formatted.push(`${major}.${minor}`);
            }
        }
    });
    return formatted;
}

export function formatDetailValue(value) {
    if (typeof value === 'boolean') {
        return value ? 'true' : 'false';
    }
    if (value === undefined || value === null) {
        return '—';
    }
    if (Array.isArray(value)) {
        return value.map(item => formatDetailValue(item)).join(', ');
    }
    return String(value);
}

export function normaliseEnumKey(value) {
    if (value === undefined || value === null) {
        return '';
    }
    // A level's "+" is its "plus" (FIDO Certified L1+ is FIDO_CERTIFIED_L1PLUS), never L1.
    return String(value)
        .trim()
        .toUpperCase()
        .replace(/\+/g, 'PLUS')
        .replace(/[^A-Z0-9]+/g, '_')
        .replace(/^_+|_+$/g, '');
}

// Whether a status key (normaliseEnumKey's) is a FIDO certification: FIDO_CERTIFIED or
// one of its levels (FIDO_CERTIFIED_L1, …).
/**
 * @param {string} statusKey
 * @returns {boolean}
 */
export function isCertifiedStatus(statusKey) {
    return statusKey === 'FIDO_CERTIFIED' || statusKey.startsWith('FIDO_CERTIFIED_');
}

export function formatCertificateDateDisplay(value) {
    if (!value) {
        return '';
    }
    const date = new Date(value);
    if (!Number.isNaN(date.getTime())) {
        return date.toUTCString();
    }
    return typeof value === 'string' ? value : '';
}

export function formatSignatureHashName(hash) {
    if (typeof hash !== 'string') {
        return '';
    }
    const trimmed = hash.trim();
    if (!trimmed) {
        return '';
    }
    const simpleShaMatch = /^sha(\d{3})$/i.exec(trimmed);
    if (simpleShaMatch) {
        return `SHA-${simpleShaMatch[1]}`;
    }
    return trimmed.toUpperCase();
}