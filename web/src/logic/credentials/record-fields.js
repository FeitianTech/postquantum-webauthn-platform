// A saved credential's fields as the pages compare them: its credential ID and
// user handle in hex, its authenticator attachment, and the AAGUID its
// authenticator data holds. DOM-free.
import { base64ToHex, base64UrlToHex } from '../shared/bytes.js';

// A stored byte value as lower-case hex: hex text as it is, else base64url text
// decoded; '' for anything else.
export function normalizeToHex(value) {
    if (typeof value !== 'string') {
        return '';
    }
    const trimmed = value.trim();
    if (!trimmed) {
        return '';
    }
    if (/^[0-9a-fA-F]+$/.test(trimmed) && trimmed.length % 2 === 0) {
        return trimmed.toLowerCase();
    }
    try {
        return base64UrlToHex(trimmed).toLowerCase();
    } catch (error) {
        return '';
    }
}

export function getCredentialIdHex(credential) {
    if (!credential) {
        return '';
    }

    const candidates = [
        credential.credentialIdHex,
        credential.credentialId,
        credential.id,
    ];

    for (const candidate of candidates) {
        const hex = normalizeToHex(candidate);
        if (hex) {
            return hex.toLowerCase();
        }
    }

    return '';
}

export function getCredentialUserHandleHex(credential) {
    if (!credential) {
        return '';
    }

    const candidates = [
        credential.userHandleHex,
        credential.userHandle,
        credential.userHandleBase64,
        credential.userHandleBase64Url,
    ];

    for (const candidate of candidates) {
        const hex = normalizeToHex(candidate);
        if (hex) {
            return hex.toLowerCase();
        }
    }

    return '';
}

export function normalizeAttachmentValue(value) {
    if (typeof value !== 'string') {
        return '';
    }
    return value.trim().toLowerCase();
}

export function getStoredCredentialAttachment(cred) {
    if (!cred || typeof cred !== 'object') {
        return '';
    }
    const directValue = normalizeAttachmentValue(cred.authenticatorAttachment);
    if (directValue) {
        return directValue;
    }
    const properties = cred.properties && typeof cred.properties === 'object'
        ? cred.properties
        : {};
    const propertyValue = normalizeAttachmentValue(
        properties.authenticatorAttachment
    );
    return propertyValue;
}

// Authenticator data as hex, from the text a record keeps it as: hex, base64 or
// base64url; '' for anything else.
export function extractAuthenticatorDataHex(source) {
    if (typeof source !== 'string') {
        return '';
    }
    const trimmed = source.trim();
    if (!trimmed) {
        return '';
    }
    const hexCandidate = trimmed.replace(/[^0-9a-fA-F]/g, '');
    if (hexCandidate.length === trimmed.length && hexCandidate.length % 2 === 0) {
        return hexCandidate.toLowerCase();
    }
    try {
        const fromBase64 = base64ToHex(trimmed);
        if (fromBase64) {
            return fromBase64;
        }
    } catch (error) {
        // Not base64: base64url is tried next.
    }
    try {
        return base64UrlToHex(trimmed);
    } catch (error) {
        return '';
    }
}

export function extractAaguidFromAuthDataHex(authDataHex) {
    if (!authDataHex) {
        return '';
    }

    const sanitized = authDataHex.replace(/[^0-9a-f]/gi, '').toLowerCase();
    const minimumLength = (32 + 1 + 4 + 16) * 2;
    if (sanitized.length < minimumLength) {
        return '';
    }

    // Hex digits only, and long enough: the flags byte and the AAGUID are there.
    const flagsHex = sanitized.substr(64, 2);
    const flagsValue = Number.parseInt(flagsHex, 16);
    const hasAttestedCredentialData = (flagsValue & 0x40) !== 0;
    if (!hasAttestedCredentialData) {
        return '';
    }

    const aaguidStart = (32 + 1 + 4) * 2;
    return sanitized.substr(aaguidStart, 32);
}

export function deriveAaguidFromCredentialData(cred) {
    if (!cred || typeof cred !== 'object') {
        return '';
    }

    const sources = [
        cred.relyingParty?.registrationData?.authenticatorData,
        cred.authenticatorData,
    ];

    for (const source of sources) {
        const authDataHex = extractAuthenticatorDataHex(source);
        const aaguid = extractAaguidFromAuthDataHex(authDataHex);
        if (aaguid) {
            return aaguid;
        }
    }

    return '';
}
