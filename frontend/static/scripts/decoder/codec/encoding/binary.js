const BINARY_CONVERTIBLE_KEYS = [
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

const STRING_BINARY_MATCHERS = [
    isPemString,
    isLikelyHex,
    isLikelyBase64,
    isLikelyBase64Url,
];

function hasBinaryConvertibleString(value) {
    const trimmed = value.trim();
    if (!trimmed) {
        return false;
    }

    return STRING_BINARY_MATCHERS.some((matcher) => matcher(trimmed));
}

function isByteArray(value) {
    return value.every((item) => Number.isInteger(item) && item >= 0 && item <= 255);
}

export function hasBinaryConvertibleValue(value) {
    if (value === null || value === undefined) {
        return false;
    }

    if (typeof value === 'string') {
        return hasBinaryConvertibleString(value);
    }

    if (Array.isArray(value)) {
        if (value.length === 0) {
            return false;
        }

        if (isByteArray(value)) {
            return true;
        }

        return value.some((entry) => hasBinaryConvertibleValue(entry));
    }

    if (typeof value === 'object') {
        for (const key of BINARY_CONVERTIBLE_KEYS) {
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
