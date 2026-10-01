// An AAGUID read from the spelling it comes in, by one of two readers:
// - aaguidHex: a record's or the server's spelling (hex, a dashed GUID,
//   base64url or base64, bytes, or the relying party's {guid, raw}), as
//   lower-case hex;
// - aaguidGuid: an MDS entry's, as the server spells entry ids (mds/build.py's
//   format_guid_candidate), as a dashed lower-case GUID.
// DOM-free.
import { base64ToHex, base64UrlToHex, bytesToHex } from './bytes.js';
import { base64UrlToBytes } from './base64.js';

const GUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

// Sixteen bytes in base64url are 22 characters, which as hex would be eleven
// bytes, no AAGUID's length: the all-zero AAGUID is "AAAAAAAAAAAAAAAAAAAAAA",
// every character a hex digit. The strict decoder takes only the one spelling.
function sixteenBytesFromBase64Url(text) {
    if (text.length !== 22) {
        return '';
    }
    try {
        return bytesToHex(base64UrlToBytes(text));
    } catch {
        return '';
    }
}

const hexDigits = text => text.replace(/[^0-9a-fA-F]/g, '').toLowerCase();

function hexOfText(trimmed) {
    const sixteenBytes = sixteenBytesFromBase64Url(trimmed);
    if (sixteenBytes) {
        return sixteenBytes;
    }
    if (/^[0-9a-fA-F]+$/.test(trimmed) && trimmed.length % 2 === 0) {
        return trimmed.toLowerCase();
    }
    // A dashed GUID is hex: read as base64url, its dashes would be bytes.
    if (GUID_PATTERN.test(trimmed)) {
        return hexDigits(trimmed);
    }
    // Either decoder gives hex for text it reads, and throws for text it
    // cannot ("abcde" has no base64 length): that text holds no AAGUID.
    const decode = /^[A-Za-z0-9+/=]+$/.test(trimmed)
        ? base64ToHex
        : /^[A-Za-z0-9_-]+$/.test(trimmed) ? base64UrlToHex : null;
    if (decode) {
        try {
            return decode(trimmed).toLowerCase();
        } catch {
            return '';
        }
    }
    return hexDigits(trimmed);
}

/** A record's or the server's AAGUID as lower-case hex, of whatever length it holds; '' for none. */
export function aaguidHex(value) {
    if (value === null || value === undefined) {
        return '';
    }
    if (typeof value === 'string') {
        const trimmed = value.trim();
        return trimmed ? hexOfText(trimmed) : '';
    }
    if (Array.isArray(value)) {
        try {
            return bytesToHex(Uint8Array.from(value));
        } catch {
            return '';
        }
    }
    if (ArrayBuffer.isView(value)) {
        return bytesToHex(new Uint8Array(value.buffer, value.byteOffset, value.byteLength));
    }
    if (value instanceof ArrayBuffer) {
        return bytesToHex(new Uint8Array(value));
    }
    if (typeof value === 'object') {
        // The relying party's AAGUID: its raw bytes, else its GUID.
        if (typeof value.raw === 'string' || Array.isArray(value.raw)) {
            const raw = aaguidHex(value.raw);
            if (raw) {
                return raw;
            }
        }
        if (typeof value.guid === 'string') {
            return hexDigits(value.guid);
        }
    }
    return '';
}

function byteList(value) {
    if (Array.isArray(value)) {
        return value.every(item => Number.isInteger(item)) ? value : null;
    }
    if (ArrayBuffer.isView(value)) {
        return Array.from(new Uint8Array(value.buffer, value.byteOffset, value.byteLength));
    }
    if (value instanceof ArrayBuffer) {
        return Array.from(new Uint8Array(value));
    }
    return null;
}

const dashed = hex => `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;

/**
 * An AAGUID as a dashed lower-case GUID, read as the server reads an MDS entry's:
 * a GUID, text whose hex digits number 32, sixteen bytes, or a value by its text
 * form; '' for anything else.
 */
export function aaguidGuid(value) {
    if (value === undefined || value === null) {
        return '';
    }
    if (typeof value === 'string') {
        const trimmed = value.trim();
        if (GUID_PATTERN.test(trimmed)) {
            return trimmed.toLowerCase();
        }
        const clean = hexDigits(trimmed);
        return clean.length === 32 ? dashed(clean) : '';
    }
    const bytes = byteList(value);
    if (bytes && bytes.length === 16) {
        return dashed(bytes.map(byte => byte.toString(16).padStart(2, '0')).join(''));
    }
    try {
        if (typeof value.toString === 'function') {
            return aaguidGuid(value.toString());
        }
    } catch {
        // A value whose text form throws has no GUID.
    }
    return '';
}
