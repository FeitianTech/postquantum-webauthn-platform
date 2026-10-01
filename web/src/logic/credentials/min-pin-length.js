// The minimum PIN length a saved credential reports, from the record's
// properties, its extension outputs or the authenticator's extensions. DOM-free.

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
    if (clientOutputs && Object.hasOwn(clientOutputs, 'minPinLength')) {
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
            if (Object.hasOwn(authenticatorExtensions, 'minPinLength')) {
                const normalized = normalizeMinPinLengthValue(authenticatorExtensions.minPinLength);
                if (normalized !== null) {
                    return normalized;
                }
            }
        }
    }

    return null;
}
