// Bytes in their spellings: hex, base64 and base64url (read forgivingly where a
// person typed them), buffers, and text or JSON a credential spelled in
// base64url. DOM-free.
import { Base64Error, base64UrlToBytes, forgivingBase64ToBytes } from './base64.js';

/**
 * @param {number} bytes
 * @returns {string}
 */
export function generateRandomHex(bytes) {
    const array = new Uint8Array(bytes);
    crypto.getRandomValues(array);
    return bytesToHex(array);
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

export function bytesToHex(bytes) {
    if (!bytes) {
        return '';
    }
    return Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('');
}

// Standard base64, tolerant of padding and whitespace: for values a person typed.
export function base64ToHex(base64) {
    if (!base64) return '';
    if (/[-_]/.test(base64)) {
        throw new Base64Error('base64 has a base64url character');
    }
    return bytesToHex(forgivingBase64ToBytes(base64));
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

const UTF8 = new TextDecoder();

// Text the browser or the server wrote in base64url (a credential's client
// data): decoded strictly, so other text throws rather than decoding to junk.
export function base64UrlToUtf8String(base64url) {
    if (!base64url) return null;
    return UTF8.decode(base64UrlToBytes(base64url));
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

