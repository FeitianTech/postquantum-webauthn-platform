// The byte values a request's JSON spells: written as `{"$hex": …}`, and read
// as hex from `{"$hex": …}`, `{"$base64url": …}`, `{"$base64": …}`, a bare
// base64url string or a buffer. DOM-free.
import {
    base64ToHex,
    base64UrlToHex,
    bufferSourceToUint8Array,
    bytesToHex,
} from '../../shared/bytes.js';

export function extractHexFromJsonFormat(jsonValue) {
    if (!jsonValue) return '';
    const directBuffer = bufferSourceToUint8Array(jsonValue);
    if (directBuffer) return bytesToHex(directBuffer);
    if (jsonValue.$hex) return jsonValue.$hex;
    if (jsonValue.$base64url) return base64UrlToHex(jsonValue.$base64url);
    if (jsonValue.$base64) return base64ToHex(jsonValue.$base64);
    if (typeof jsonValue === 'string') return base64UrlToHex(jsonValue);
    return '';
}

/** A byte value as the request writes it ({"$hex": …}), or '' for none. */
export function jsonBytes(hex) {
    return hex ? { $hex: hex } : '';
}
