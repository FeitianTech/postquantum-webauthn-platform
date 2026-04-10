import { ENCODER_FORMAT_ALIASES } from './constants.js';
import { formatKey } from './labels.js';

function normalizeEncoderFormat(format) {
    if (typeof format !== 'string') {
        return '';
    }
    return format.trim().toLowerCase();
}

function getCanonicalEncoderFormat(format) {
    const normalized = normalizeEncoderFormat(format);
    if (!normalized) {
        return '';
    }
    return ENCODER_FORMAT_ALIASES.get(normalized) || normalized;
}

export function canEncodeToFormat(parsedValue, format) {
    const canonical = getCanonicalEncoderFormat(format);
    if (!canonical) {
        return true;
    }

    if (canonical === 'cbor' || canonical === 'json' || canonical === 'cose') {
        return parsedValue !== undefined;
    }

    if (['der', 'pem'].includes(canonical)) {
        return hasBinaryConvertibleValue(parsedValue);
    }

    return true;
}

function looksLikeBinarySummary(value) {
    if (!value || typeof value !== 'object' || Array.isArray(value)) {
        return false;
    }
    if (typeof value.hex === 'string' && value.hex.trim()) {
        return true;
    }
    if (typeof value.base64 === 'string' && value.base64.trim()) {
        return true;
    }
    if (typeof value.base64url === 'string' && value.base64url.trim()) {
        return true;
    }
    return false;
}

export function findEncodedSummary(value, label = '') {
    if (value === null || value === undefined) {
        return null;
    }

    if (Array.isArray(value)) {
        for (const item of value) {
            const result = findEncodedSummary(item, label);
            if (result) {
                return result;
            }
        }
        return null;
    }

    if (typeof value !== 'object') {
        return null;
    }

    if (looksLikeBinarySummary(value)) {
        const friendly = label ? formatKey(label) : 'Encoded output';
        return {
            summary: value,
            label: friendly.toLowerCase() === 'binary' ? 'Encoded output' : friendly,
        };
    }

    if (value.binary && looksLikeBinarySummary(value.binary)) {
        const friendly = label ? formatKey(label) : 'Encoded output';
        return {
            summary: value.binary,
            label: friendly.toLowerCase() === 'binary' ? 'Encoded output' : friendly,
        };
    }

    for (const [key, nested] of Object.entries(value)) {
        const result = findEncodedSummary(nested, key);
        if (result) {
            return result;
        }
    }

    return null;
}

function createEncodedFormatBlock(key, value) {
    const block = document.createElement('div');
    block.className = 'codec-encoded-format';

    const label = document.createElement('div');
    label.className = 'codec-encoded-label';
    label.textContent = formatKey(key);
    block.appendChild(label);

    const pre = document.createElement('pre');
    pre.className = 'decoder-pre codec-encoded-value';
    pre.textContent = value;
    block.appendChild(pre);

    return block;
}

export function createEncodedFormatElements(summary) {
    if (!summary || typeof summary !== 'object') {
        return [];
    }

    const order = ['hex', 'base64', 'base64url', 'colonHex'];
    const blocks = [];
    const used = new Set();
    const skipKeys = new Set(['encoding']);

    order.forEach(key => {
        const value = summary[key];
        if (typeof value === 'string') {
            const trimmed = value.trim();
            if (trimmed) {
                blocks.push(createEncodedFormatBlock(key, value));
                used.add(key);
            }
        }
    });

    Object.entries(summary).forEach(([key, value]) => {
        if (used.has(key)) {
            return;
        }
        if (skipKeys.has(key)) {
            return;
        }
        if (typeof value === 'string') {
            const trimmed = value.trim();
            if (!trimmed) {
                return;
            }
            blocks.push(createEncodedFormatBlock(key, value));
            used.add(key);
        }
    });

    return blocks;
}

function hasBinaryConvertibleValue(value) {
    if (value === null || value === undefined) {
        return false;
    }

    if (typeof value === 'string') {
        const trimmed = value.trim();
        if (!trimmed) {
            return false;
        }
        if (isPemString(trimmed)) {
            return true;
        }
        if (isLikelyHex(trimmed)) {
            return true;
        }
        if (isLikelyBase64(trimmed) || isLikelyBase64Url(trimmed)) {
            return true;
        }
        return false;
    }

    if (Array.isArray(value)) {
        if (value.length === 0) {
            return false;
        }
        if (value.every((item) => Number.isInteger(item) && item >= 0 && item <= 255)) {
            return true;
        }
        return value.some((item) => hasBinaryConvertibleValue(item));
    }

    if (typeof value === 'object') {
        const keysToInspect = [
            'value',
            'data',
            'raw',
            'binary',
            'bytes',
            'hex',
            'base64',
            'base64url',
            'derBase64',
            'pem',
        ];

        for (const key of keysToInspect) {
            if (Object.prototype.hasOwnProperty.call(value, key)) {
                if (hasBinaryConvertibleValue(value[key])) {
                    return true;
                }
            }
        }

        return Object.values(value).some((entry) => hasBinaryConvertibleValue(entry));
    }

    return false;
}

function isLikelyHex(value) {
    const candidate = value.trim().replace(/^0x/i, '').replace(/[\s:]/g, '');
    return candidate.length > 0 && candidate.length % 2 === 0 && /^[0-9a-fA-F]+$/.test(candidate);
}

function isLikelyBase64(value) {
    const candidate = value.replace(/\s+/g, '');
    if (!candidate) {
        return false;
    }
    return /^[A-Za-z0-9+/=]+$/.test(candidate);
}

function isLikelyBase64Url(value) {
    const candidate = value.replace(/\s+/g, '');
    if (!candidate) {
        return false;
    }
    return /^[A-Za-z0-9_\-]+=*$/.test(candidate);
}

function isPemString(value) {
    return /-----BEGIN [^-]+-----/.test(value) && /-----END [^-]+-----/.test(value);
}
