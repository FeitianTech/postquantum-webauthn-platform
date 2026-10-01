// An AAGUID as lower-case hex, from whichever spelling a record or the server
// gives it: hex, a dashed GUID, base64url (or base64), bytes, or an object with
// one of those spellings. DOM-free.
import { base64ToHex, base64UrlToHex, bytesToHex } from './binary.js';
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

export function normaliseAaguidValue(value) {
    if (value === null || value === undefined) {
        return '';
    }

    const normaliseGuidString = (guidString) => {
        if (!guidString || typeof guidString !== 'string') {
            return '';
        }
        return guidString.replace(/[^0-9a-fA-F]/g, '').toLowerCase();
    };

    if (typeof value === 'string') {
        const trimmed = value.trim();
        if (!trimmed) {
            return '';
        }

        const sixteenBytes = sixteenBytesFromBase64Url(trimmed);
        if (sixteenBytes) {
            return sixteenBytes;
        }

        const hexPattern = /^[0-9a-fA-F]+$/;
        if (hexPattern.test(trimmed) && trimmed.length % 2 === 0) {
            return trimmed.toLowerCase();
        }

        // A dashed GUID is hex: read as base64url, its dashes would be bytes.
        if (GUID_PATTERN.test(trimmed)) {
            return normaliseGuidString(trimmed);
        }

        // Either decoder gives hex for text it reads, and throws for text it
        // cannot ("abcde" has no base64 length): that text holds no AAGUID.
        const base64Pattern = /^[A-Za-z0-9+/=]+$/;
        const base64UrlPattern = /^[A-Za-z0-9_-]+$/;
        const decode = base64Pattern.test(trimmed)
            ? base64ToHex
            : base64UrlPattern.test(trimmed) ? base64UrlToHex : null;
        if (decode) {
            try {
                return decode(trimmed).toLowerCase();
            } catch {
                return '';
            }
        }

        const cleaned = trimmed.replace(/[^0-9a-fA-F]/g, '');
        return cleaned ? cleaned.toLowerCase() : '';
    }

    if (Array.isArray(value)) {
        try {
            const bytes = Uint8Array.from(value);
            return Array.from(bytes).map(byte => byte.toString(16).padStart(2, '0')).join('');
        } catch (error) {
            return '';
        }
    }

    if (ArrayBuffer.isView(value)) {
        const view = new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
        return Array.from(view).map(byte => byte.toString(16).padStart(2, '0')).join('');
    }

    if (value instanceof ArrayBuffer) {
        return Array.from(new Uint8Array(value)).map(byte => byte.toString(16).padStart(2, '0')).join('');
    }

    if (typeof value === 'object') {
        if (typeof value.hex === 'function') {
            try {
                return normaliseAaguidValue(value.hex());
            } catch (error) {
                return '';
            }
        }
        if (typeof value.hex === 'string') {
            const normalized = normaliseAaguidValue(value.hex);
            if (normalized) {
                return normalized;
            }
        }

        if (typeof value.raw === 'string' || Array.isArray(value.raw)) {
            const normalizedRaw = normaliseAaguidValue(value.raw);
            if (normalizedRaw) {
                return normalizedRaw;
            }
        }

        if (typeof value.guid === 'string') {
            const normalizedGuid = normaliseGuidString(value.guid);
            if (normalizedGuid) {
                return normalizedGuid;
            }
        }

        const base64Candidates = [
            value.base64,
            value.base64url,
            value.base64Url,
            value.b64,
            value.b64u,
        ];
        for (const candidate of base64Candidates) {
            if (typeof candidate === 'string' && candidate.trim()) {
                const fromBase64 = normaliseAaguidValue(candidate);
                if (fromBase64) {
                    return fromBase64;
                }
            }
        }

        const nestedCandidates = [
            value.aaguid,
            value.metadata && value.metadata.aaguid,
            value.metadata && value.metadata.hex,
        ];
        for (const candidate of nestedCandidates) {
            const normalized = normaliseAaguidValue(candidate);
            if (normalized) {
                return normalized;
            }
        }
    }

    return '';
}
