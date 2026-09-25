// Strict base64url and base64 (RFC 4648), without atob.
//
// Every byte field the server sends is base64url, unpadded, as WebAuthn's JSON
// is; a field whose name says Base64 (derBase64, publicKeyBase64, ...) is
// standard base64, padded. Each decoder accepts exactly one spelling of a byte
// string: its own alphabet, its own padding rule, no whitespace, and zero bits
// where the last character has more than the bytes need. Anything else throws
// Base64Error rather than decoding to other bytes. This is the frontend's twin of
// server/app/encoding.py's strict decoders.

const STANDARD = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
const URL_SAFE = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

function lookup(alphabet) {
    const table = new Map();
    for (let index = 0; index < alphabet.length; index += 1) {
        table.set(alphabet[index], index);
    }
    return table;
}

const STANDARD_VALUES = lookup(STANDARD);
const URL_SAFE_VALUES = lookup(URL_SAFE);

export class Base64Error extends Error {
    constructor(message) {
        super(message);
        this.name = 'Base64Error';
    }
}

function decodeBody(body, values, name, { allowStrayBits = false } = {}) {
    if (body.length % 4 === 1) {
        throw new Base64Error(`${name} cannot be ${body.length} characters long`);
    }
    const bytes = new Uint8Array(Math.floor((body.length * 3) / 4));
    let buffer = 0;
    let bits = 0;
    let offset = 0;
    for (let index = 0; index < body.length; index += 1) {
        const value = values.get(body[index]);
        if (value === undefined) {
            throw new Base64Error(`${name} has "${body[index]}" at position ${index}, outside its alphabet`);
        }
        buffer = ((buffer << 6) | value) & 0xffffff;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            bytes[offset] = (buffer >> bits) & 0xff;
            offset += 1;
        }
    }
    if (!allowStrayBits && bits > 0 && (buffer & ((1 << bits) - 1)) !== 0) {
        throw new Base64Error(`${name} ends in bits that belong to no byte`);
    }
    return bytes;
}

function requireString(text, name) {
    if (typeof text !== 'string') {
        throw new Base64Error(`${name} must be a string`);
    }
}

/** Decode unpadded base64url, the spelling of every byte field on the wire. */
export function base64UrlToBytes(text) {
    requireString(text, 'base64url');
    return decodeBody(text, URL_SAFE_VALUES, 'base64url');
}

/** Decode padded standard base64, for a field whose name says Base64. */
export function base64ToBytes(text) {
    requireString(text, 'base64');
    if (text.length % 4 !== 0) {
        throw new Base64Error('base64 must be padded to a multiple of four characters');
    }
    const padding = text.endsWith('==') ? 2 : text.endsWith('=') ? 1 : 0;
    const body = text.slice(0, text.length - padding);
    if (body.length % 4 !== (padding ? 4 - padding : 0)) {
        throw new Base64Error('base64 padding does not match its length');
    }
    return decodeBody(body, STANDARD_VALUES, 'base64');
}

/**
 * atob()'s forgiving decode, without atob: whitespace ignored, padding optional,
 * stray bits in the last character dropped, either alphabet. Only for text a
 * person typed into the request editor; bytes from the server are decoded with
 * base64UrlToBytes or base64ToBytes.
 */
export function forgivingBase64ToBytes(text) {
    requireString(text, 'base64');
    let body = text.replace(/[\t\n\f\r ]+/g, '').replace(/-/g, '+').replace(/_/g, '/');
    if (body.length % 4 === 0) {
        body = body.replace(/==?$/, '');
    }
    return decodeBody(body, STANDARD_VALUES, 'base64', { allowStrayBits: true });
}

function encode(bytes, alphabet) {
    const view = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
    let text = '';
    for (let index = 0; index < view.length; index += 3) {
        const chunk = (view[index] << 16) | ((view[index + 1] ?? 0) << 8) | (view[index + 2] ?? 0);
        const characters = Math.min(4, Math.ceil(((view.length - index) * 8) / 6));
        for (let position = 0; position < characters; position += 1) {
            text += alphabet[(chunk >> (18 - 6 * position)) & 0x3f];
        }
    }
    return text;
}

/** Encode bytes as unpadded base64url. */
export function bytesToBase64Url(bytes) {
    return encode(bytes, URL_SAFE);
}

/** Encode bytes as padded standard base64. */
export function bytesToBase64(bytes) {
    const text = encode(bytes, STANDARD);
    return text + '='.repeat((4 - (text.length % 4)) % 4);
}
