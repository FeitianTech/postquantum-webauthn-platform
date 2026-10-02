// The places a saved record may keep its registration's parts (the response,
// the attestation object, the authenticator data), in the order they are read,
// and the first value of a kind among candidates. DOM-free.

export function pickFirstString(...candidates) {
    for (const candidate of candidates) {
        if (typeof candidate !== 'string') {
            continue;
        }
        const trimmed = candidate.trim();
        if (trimmed) {
            return trimmed;
        }
    }
    return '';
}

export function pickFirstObject(...candidates) {
    for (const candidate of candidates) {
        if (candidate && typeof candidate === 'object') {
            return candidate;
        }
    }
    return null;
}

export function resolveStoredRegistrationResponse(registrationResponseStored) {
    if (registrationResponseStored && typeof registrationResponseStored === 'object') {
        const nestedResponse = registrationResponseStored.response;
        if (nestedResponse && typeof nestedResponse === 'object') {
            return nestedResponse;
        }
        return registrationResponseStored;
    }
    return null;
}

export function attestationObjectStringCandidates(source) {
    if (!source || typeof source !== 'object') {
        return [];
    }

    return [source.attestationObject];
}

export function attestationObjectDecodedCandidates(source) {
    if (!source || typeof source !== 'object') {
        return [];
    }

    return [typeof source.attestationObject === 'object' ? source.attestationObject : null];
}

export function authenticatorDataStringCandidates(source) {
    if (!source || typeof source !== 'object') {
        return [];
    }

    return [source.authenticatorData];
}

export function authenticatorDataHexCandidates(source) {
    if (!source || typeof source !== 'object') {
        return [];
    }

    return [source.authenticatorDataHex];
}
