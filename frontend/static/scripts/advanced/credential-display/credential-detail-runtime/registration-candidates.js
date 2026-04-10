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
        source.attestation_object_raw,
        source.attestation_object,
        source.attestationObjectBase64,
        source.attestation_object_base64,
    ];
}

export function attestationObjectDecodedCandidates(source) {
    if (!source || typeof source !== 'object') {
        return [];
    }

    return [
        source.attestationObjectDecoded,
        source.attestation_object_decoded,
        typeof source.attestationObject === 'object' ? source.attestationObject : null,
        typeof source.attestation_object === 'object' ? source.attestation_object : null,
    ];
}

export function authenticatorDataStringCandidates(source) {
    if (!source || typeof source !== 'object') {
        return [];
    }

    return [
        source.authenticatorDataRaw,
        source.authenticatorData,
        source.authenticator_data_raw,
        source.authenticator_data,
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
        source.authenticator_data_hex,
    ];
}
