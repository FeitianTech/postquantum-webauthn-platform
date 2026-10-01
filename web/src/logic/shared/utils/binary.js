import { state } from '../state.js';
import { Base64Error, base64UrlToBytes, bytesToBase64, bytesToBase64Url, forgivingBase64ToBytes } from './base64.js';

export function isValidHex(str) {
    return /^[0-9a-fA-F]*$/.test(str) && str.length > 0;
}

export function generateRandomHex(bytes) {
    const array = new Uint8Array(bytes);
    crypto.getRandomValues(array);
    return Array.from(array).map(b => b.toString(16).padStart(2, '0')).join('');
}

// Hex as bytes, or a refusal: the caller keeps what does not convert as hex.
function wholeBytes(hexString) {
    const bytes = hexToUint8Array(hexString);
    if (!bytes) {
        throw new Base64Error('hex that is not whole bytes has no base64');
    }
    return bytes;
}

// An odd number of digits is read with a leading zero.
export function hexToBase64Url(hexString) {
    if (!hexString) return '';
    return bytesToBase64Url(wholeBytes(hexString.length % 2 === 0 ? hexString : `0${hexString}`));
}

// Tolerant of either alphabet, padding and whitespace: for values a person typed.
export function base64UrlToHex(base64url) {
    if (!base64url) return '';
    return bytesToHex(forgivingBase64ToBytes(base64url));
}

export function base64ToBase64Url(base64) {
    if (!base64) return '';
    return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

export function hexToBase64(hexString) {
    if (!hexString) return '';
    return bytesToBase64(wholeBytes(hexString));
}

export function hexToGuid(hexString) {
    if (!hexString || hexString.length !== 32) return '';
    return [
        hexString.substring(0, 8),
        hexString.substring(8, 12),
        hexString.substring(12, 16),
        hexString.substring(16, 20),
        hexString.substring(20, 32)
    ].join('-');
}

export function bytesToHex(bytes) {
    if (!bytes) {
        return '';
    }
    return Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('');
}

export function hexToJs(hexString) {
    if (!hexString) return '';
    const bytes = [];
    for (let i = 0; i < hexString.length; i += 2) {
        bytes.push(parseInt(hexString.substr(i, 2), 16));
    }
    return `new Uint8Array([${bytes.join(', ')}])`;
}

// Standard base64, tolerant of padding and whitespace: for values a person typed.
export function base64ToHex(base64) {
    if (!base64) return '';
    if (/[-_]/.test(base64)) {
        throw new Base64Error('base64 has a base64url character');
    }
    return bytesToHex(forgivingBase64ToBytes(base64));
}

export function jsToHex(jsString) {
    if (!jsString) return '';
    const match = jsString.match(/new Uint8Array\(\[([0-9, ]+)\]\)/);
    if (!match) return '';
    const numbers = match[1].split(',').map(n => parseInt(n.trim()));
    return numbers.map(n => n.toString(16).padStart(2, '0')).join('');
}

export function convertFormat(value, fromFormat, toFormat) {
    if (!value || fromFormat === toFormat) return value;

    let hexValue = '';
    switch (fromFormat) {
        case 'hex':
            hexValue = value;
            break;
        case 'b64':
            hexValue = base64ToHex(value);
            break;
        case 'b64u':
            hexValue = base64UrlToHex(value);
            break;
        case 'js':
            hexValue = jsToHex(value);
            break;
    }

    switch (toFormat) {
        case 'hex':
            return hexValue;
        case 'b64':
            return hexToBase64(hexValue);
        case 'b64u':
            return hexToBase64Url(hexValue);
        case 'js':
            return hexToJs(hexValue);
        default:
            return hexValue;
    }
}

export function hexToUint8Array(hex) {
    if (!hex) return null;
    const normalized = hex.replace(/\s+/g, '').toLowerCase();
    if (normalized.length % 2 !== 0) {
        return null;
    }

    const bytes = new Uint8Array(normalized.length / 2);
    for (let i = 0; i < normalized.length; i += 2) {
        const byte = parseInt(normalized.substr(i, 2), 16);
        if (Number.isNaN(byte)) {
            return null;
        }
        bytes[i / 2] = byte;
    }
    return bytes;
}

// Text the browser or the server wrote in base64url (a credential's client
// data): decoded strictly, so other text throws rather than decoding to junk.
export function base64UrlToUtf8String(base64url) {
    if (!base64url) return null;
    if (!state.utf8Decoder) return null;
    const bytes = base64UrlToBytes(base64url);
    try {
        return state.utf8Decoder.decode(bytes);
    } catch (error) {
        return null;
    }
}

export function base64UrlToJson(base64url) {
    try {
        const decoded = base64UrlToUtf8String(base64url);
        if (!decoded) return null;
        return JSON.parse(decoded);
    } catch (error) {
        return null;
    }
}

export function bufferSourceToUint8Array(value) {
    if (value instanceof ArrayBuffer) {
        return new Uint8Array(value);
    }

    if (ArrayBuffer.isView(value)) {
        return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
    }

    return null;
}

export function sortObjectKeys(value) {
    if (Array.isArray(value)) {
        return value.map(item => sortObjectKeys(item));
    }

    if (value && Object.prototype.toString.call(value) === '[object Object]') {
        const sorted = {};
        Object.keys(value)
            .sort((a, b) => a.localeCompare(b))
            .forEach(key => {
                sorted[key] = sortObjectKeys(value[key]);
            });
        return sorted;
    }

    return value;
}

const ACTIVE_BINARY_FORMAT = 'hex';
export function getCurrentBinaryFormat() {
    if (typeof window !== 'undefined') {
        const runtimeFormat = typeof window.__binaryFormat === 'string'
            ? window.__binaryFormat.trim().toLowerCase()
            : '';
        if (runtimeFormat) {
            return runtimeFormat;
        }
    }
    return ACTIVE_BINARY_FORMAT;
}

export function currentFormatToJsonFormat(value) {
    if (!value) return '';
    const format = getCurrentBinaryFormat();

    switch (format) {
        case 'hex':
            return {
                '$hex': value
            };
        case 'b64':
            return {
                '$base64': value
            };
        case 'b64u':
            return {
                '$base64url': value
            };
        case 'js':
            return {
                '$js': value
            };
        default:
            return {
                '$base64url': currentFormatToBase64Url(value)
            };
    }
}

export function currentFormatToBase64Url(value) {
    if (!value) return '';
    const format = getCurrentBinaryFormat();
    const hexValue = convertFormat(value, format, 'hex');
    return hexToBase64Url(hexValue);
}

export function normalizeToHex(value) {
    if (!value) {
        return '';
    }

    if (typeof value === 'string') {
        const trimmed = value.trim();
        if (!trimmed) {
            return '';
        }

        if (isValidHex(trimmed) && trimmed.length % 2 === 0) {
            return trimmed.toLowerCase();
        }

        try {
            return base64UrlToHex(trimmed).toLowerCase();
        } catch (error) {
            return '';
        }
    }

    if (typeof value === 'object') {
        if (value.$hex) {
            return normalizeToHex(value.$hex);
        }
        if (value.$base64url) {
            return normalizeToHex(value.$base64url);
        }
        if (value.$base64) {
            return normalizeToHex(value.$base64);
        }
        if (value.$js) {
            return normalizeToHex(jsToHex(value.$js));
        }
    }

    return '';
}
