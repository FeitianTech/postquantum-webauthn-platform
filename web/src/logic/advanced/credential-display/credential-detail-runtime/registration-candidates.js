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

    return [
        source.attestationObjectRaw,
        source.attestationObject,
        source.attestationObjectBase64,
    ];
}

export function attestationObjectDecodedCandidates(source) {
    if (!source || typeof source !== 'object') {
        return [];
    }

    return [
        source.attestationObjectDecoded,
        typeof source.attestationObject === 'object' ? source.attestationObject : null,
    ];
}

export function authenticatorDataStringCandidates(source) {
    if (!source || typeof source !== 'object') {
        return [];
    }

    return [
        source.authenticatorDataRaw,
        source.authenticatorData,
        source.authenticatorDataBase64,
        source.authenticatorDataBase64Url,
    ];
}

export function authenticatorDataHexCandidates(source) {
    if (!source || typeof source !== 'object') {
        return [];
    }

    return [
        source.authenticatorDataHex,
    ];
}
