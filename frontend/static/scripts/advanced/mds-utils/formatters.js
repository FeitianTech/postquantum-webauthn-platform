import { sortStatusReportsByEffectiveDateDesc } from './status-reports.js';

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

export function formatProtocol(protocol) {
    if (!protocol) {
        return '';
    }
    const normalised = formatEnum(protocol);
    const compact = normalised.replace(/\s+/g, '');
    if (/^fido\d$/i.test(compact)) {
        return compact.toUpperCase();
    }
    return normalised;
}

export function normaliseEnumKey(value) {
    if (value === undefined || value === null) {
        return '';
    }
    return String(value)
        .trim()
        .toUpperCase()
        .replace(/[^A-Z0-9]+/g, '_')
        .replace(/^_+|_+$/g, '');
}

export function formatEnum(value) {
    if (!value && value !== 0) {
        return '';
    }
    return String(value)
        .split(/[_-]/)
        .map(part => part.trim())
        .filter(Boolean)
        .map(part => {
            if (/^[A-Z0-9]+$/.test(part)) {
                if (part.length <= 4) {
                    return part;
                }
                const lower = part.toLowerCase();
                return lower.charAt(0).toUpperCase() + lower.slice(1);
            }
            if (/^.*\d.*$/.test(part)) {
                return part.toUpperCase();
            }
            const lower = part.toLowerCase();
            return lower.charAt(0).toUpperCase() + lower.slice(1);
        })
        .join(' ');
}

export function formatCertification(statusReports) {
    const sorted = sortStatusReportsByEffectiveDateDesc(statusReports);
    const latest = sorted[0];

    if (!latest) {
        return { display: '', status: '' };
    }

    const statusRaw = typeof latest.status === 'string' ? latest.status.trim() : '';
    const statusValue = statusRaw ? statusRaw.toUpperCase() : '';
    const descriptor = typeof latest.certificationDescriptor === 'string' ? latest.certificationDescriptor.trim() : '';
    const certificateNumber = typeof latest.certificateNumber === 'string' ? latest.certificateNumber.trim() : '';

    const parts = [];
    const statusDisplay = statusValue ? formatEnum(statusValue) : '';
    if (statusDisplay) {
        parts.push(statusDisplay);
    }
    if (descriptor) {
        parts.push(descriptor);
    }
    if (certificateNumber) {
        parts.push(`(${certificateNumber})`);
    }

    return {
        display: parts.filter(Boolean).join(' • '),
        status: statusValue,
    };
}

export function parseIsoDate(value) {
    if (typeof value !== 'string' || !value.trim()) {
        return null;
    }
    const parsed = new Date(value);
    if (Number.isNaN(parsed.getTime())) {
        return null;
    }
    return parsed;
}

export function formatDate(value) {
    if (!value) {
        return '';
    }
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) {
        return value;
    }
    return new Intl.DateTimeFormat(undefined, {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
    }).format(date);
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