// A saved credential's fields as the pages compare them: its credential ID and
// user handle in hex, its authenticator attachment, and the AAGUID its
// authenticator data holds. DOM-free.
import {
    base64ToHex,
    base64UrlToHex,
    bytesToHex,
    normalizeToHex,
} from '../shared/binary.js';

export function getCredentialIdHex(credential) {
    if (!credential) {
        return '';
    }

    const candidates = [
        credential.credentialIdHex,
        credential.credentialId,
        credential.credentialID,
        credential.id,
        credential.rawId
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
        credential.userId,
        credential.userHandleBase64,
        credential.userHandleBase64Url
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

export function extractAuthenticatorDataHex(source) {
    if (!source) {
        return '';
    }

    if (typeof source === 'string') {
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
            // Ignore decode errors and continue checking other encodings
        }
        try {
            const fromBase64Url = base64UrlToHex(trimmed);
            if (fromBase64Url) {
                return fromBase64Url;
            }
        } catch (error) {
            // Ignore decode errors
        }
        return '';
    }

    if (Array.isArray(source)) {
        try {
            return bytesToHex(Uint8Array.from(source));
        } catch (error) {
            return '';
        }
    }

    if (ArrayBuffer.isView(source)) {
        return bytesToHex(new Uint8Array(source.buffer, source.byteOffset, source.byteLength));
    }

    if (source instanceof ArrayBuffer) {
        return bytesToHex(new Uint8Array(source));
    }

    if (typeof source === 'object') {
        const candidates = [
            source.$hex,
            source.$base64,
            source.$base64url,
            source.hex,
            source.base64,
            source.base64url,
            source.raw,
            source.value,
        ];
        for (const candidate of candidates) {
            const extracted = extractAuthenticatorDataHex(candidate);
            if (extracted) {
                return extracted;
            }
        }
    }

    return '';
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
        cred.registrationData && cred.registrationData.authenticatorData,
        cred.properties && cred.properties.registrationData && cred.properties.registrationData.authenticatorData,
        cred.properties && cred.properties.authenticatorData,
        cred.relyingParty && cred.relyingParty.registrationData && cred.relyingParty.registrationData.authenticatorData,
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
