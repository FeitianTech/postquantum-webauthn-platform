import {
    arrayBufferToHex,
    base64ToHex,
    base64UrlToHex,
    bytesToHex,
    bufferSourceToUint8Array,
    hexToBase64,
    normalizeToHex
} from '../shared/binary-utils.js';

export function normaliseAaguidValue(value) {
    if (value === null || value === undefined) {
        return '';
    }
    if (typeof value === 'string') {
        const cleaned = value.replace(/[^0-9a-fA-F]/g, '');
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
            return normaliseAaguidValue(value.hex);
        }
    }
    return '';
}

export function normalizeMinPinLengthValue(value) {
    if (value === null || value === undefined) {
        return null;
    }
    if (typeof value === 'number' && Number.isFinite(value)) {
        const normalized = Math.floor(value);
        return normalized >= 0 ? normalized : null;
    }
    if (typeof value === 'string') {
        const trimmed = value.trim();
        if (!trimmed) {
            return null;
        }
        const parsed = Number.parseInt(trimmed, 10);
        if (!Number.isNaN(parsed) && Number.isFinite(parsed) && parsed >= 0) {
            return parsed;
        }
    }
    return null;
}

export function extractMinPinLengthValue(source) {
    if (!source || typeof source !== 'object') {
        return null;
    }

    const properties = (source.properties && typeof source.properties === 'object')
        ? source.properties
        : null;
    if (properties) {
        const propertyCandidates = [
            properties.minPinLength,
            properties.min_pin_length,
        ];
        for (const candidate of propertyCandidates) {
            const normalized = normalizeMinPinLengthValue(candidate);
            if (normalized !== null) {
                return normalized;
            }
        }
    }

    const clientOutputs = (source.clientExtensionOutputs && typeof source.clientExtensionOutputs === 'object')
        ? source.clientExtensionOutputs
        : null;
    if (clientOutputs && Object.prototype.hasOwnProperty.call(clientOutputs, 'minPinLength')) {
        const extensionValue = clientOutputs.minPinLength;
        const directValue = normalizeMinPinLengthValue(extensionValue);
        if (directValue !== null) {
            return directValue;
        }
        if (extensionValue && typeof extensionValue === 'object') {
            const nestedCandidates = [
                extensionValue.minPinLength,
                extensionValue.minimumPinLength,
                extensionValue.value,
            ];
            for (const nested of nestedCandidates) {
                const normalized = normalizeMinPinLengthValue(nested);
                if (normalized !== null) {
                    return normalized;
                }
            }
        }
    }

    const registrationData = (source.registrationData && typeof source.registrationData === 'object')
        ? source.registrationData
        : null;
    if (registrationData) {
        const authenticatorExtensions = registrationData.authenticatorExtensions;
        if (authenticatorExtensions && typeof authenticatorExtensions === 'object') {
            if (Object.prototype.hasOwnProperty.call(authenticatorExtensions, 'minPinLength')) {
                const normalized = normalizeMinPinLengthValue(authenticatorExtensions.minPinLength);
                if (normalized !== null) {
                    return normalized;
                }
            }
        }
    }

    return null;
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

    const flagsHex = sanitized.substr(64, 2);
    const flagsValue = Number.parseInt(flagsHex, 16);
    if (!Number.isFinite(flagsValue)) {
        return '';
    }
    const hasAttestedCredentialData = (flagsValue & 0x40) !== 0;
    if (!hasAttestedCredentialData) {
        return '';
    }

    const aaguidStart = (32 + 1 + 4) * 2;
    const aaguidHex = sanitized.substr(aaguidStart, 32);
    if (aaguidHex.length !== 32) {
        return '';
    }
    return aaguidHex;
}

export function deriveAaguidFromCredentialData(cred) {
    if (!cred || typeof cred !== 'object') {
        return '';
    }

    const sources = [
        cred.registrationData && cred.registrationData.authenticatorData,
        cred.registrationData && cred.registrationData.authenticator_data,
        cred.properties && cred.properties.registrationData && cred.properties.registrationData.authenticatorData,
        cred.properties && cred.properties.registrationData && cred.properties.registrationData.authenticator_data,
        cred.properties && cred.properties.registration_data && cred.properties.registration_data.authenticatorData,
        cred.properties && cred.properties.registration_data && cred.properties.registration_data.authenticator_data,
        cred.properties && cred.properties.authenticatorData,
        cred.properties && cred.properties.authenticator_data,
        cred.relyingParty && cred.relyingParty.registrationData && cred.relyingParty.registrationData.authenticatorData,
        cred.relyingParty && cred.relyingParty.registrationData && cred.relyingParty.registrationData.authenticator_data,
        cred.authenticatorData,
        cred.authenticator_data,
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

export function getCoseMapValue(coseMap, key) {
    if (!coseMap || typeof coseMap !== 'object') {
        return undefined;
    }
    if (Object.prototype.hasOwnProperty.call(coseMap, key)) {
        return coseMap[key];
    }
    const stringKey = String(key);
    if (Object.prototype.hasOwnProperty.call(coseMap, stringKey)) {
        return coseMap[stringKey];
    }
    return undefined;
}

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
    const directValue = normalizeAttachmentValue(cred.authenticatorAttachment || cred.authenticator_attachment);
    if (directValue) {
        return directValue;
    }
    const properties = cred.properties && typeof cred.properties === 'object'
        ? cred.properties
        : {};
    const propertyValue = normalizeAttachmentValue(
        properties.authenticatorAttachment || properties.authenticator_attachment
    );
    return propertyValue;
}

export function extractHexFromJsonFormat(jsonValue) {
    if (!jsonValue) return '';
    const directBuffer = bufferSourceToUint8Array(jsonValue);
    if (directBuffer) return arrayBufferToHex(directBuffer);
    if (jsonValue.$hex) return jsonValue.$hex;
    if (jsonValue.$base64url) return base64UrlToHex(jsonValue.$base64url);
    if (jsonValue.$base64) return base64ToHex(jsonValue.$base64);
    if (typeof jsonValue === 'string') return base64UrlToHex(jsonValue);
    return '';
}

export function deriveAaguidDisplayValues(aaguidHex) {
    const normalizedAaguidHex = aaguidHex ? aaguidHex.toLowerCase() : '';
    let aaguidB64 = '';
    let aaguidB64u = '';
    if (normalizedAaguidHex && normalizedAaguidHex.length % 2 === 0) {
        try {
            aaguidB64 = hexToBase64(normalizedAaguidHex);
        } catch (error) {
            aaguidB64 = '';
        }
        try {
            aaguidB64u = hexToBase64(normalizedAaguidHex).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
        } catch (error) {
            aaguidB64u = '';
        }
    }
    return {
        aaguidHex: normalizedAaguidHex,
        aaguidB64,
        aaguidB64u
    };
}
