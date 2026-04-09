import {
    createNormalizedKeySet,
    isPlainObject,
    KNOWN_AUTHENTICATION_EXTENSION_KEYS,
    KNOWN_AUTHENTICATION_PUBLIC_KEY_KEYS,
    KNOWN_AUTH_SELECTION_KEYS,
    KNOWN_LARGE_BLOB_AUTH_KEYS,
    KNOWN_LARGE_BLOB_REG_KEYS,
    KNOWN_PRF_EVAL_KEYS,
    KNOWN_PRF_KEYS,
    KNOWN_REGISTRATION_EXTENSION_KEYS,
    KNOWN_REGISTRATION_PUBLIC_KEY_KEYS,
    KNOWN_RP_KEYS,
    KNOWN_USER_KEYS,
    shouldPreserveUnknownKey,
} from './schema.js';
import {
    validateAuthenticationPublicKey,
} from './validation-authentication.js';
import { validateRegistrationPublicKey } from './validation-registration.js';

export function mergeKnownProperties(existingValue, latestValue, knownKeys) {
    const latest = isPlainObject(latestValue) ? { ...latestValue } : {};
    if (!isPlainObject(existingValue)) {
        return latest;
    }

    const result = { ...latest };
    const keySet = knownKeys instanceof Set ? knownKeys : new Set();
    const normalizedKnown = createNormalizedKeySet(keySet);

    Object.keys(existingValue).forEach(key => {
        if (
            !keySet.has(key)
            && !Object.prototype.hasOwnProperty.call(result, key)
            && shouldPreserveUnknownKey(key, normalizedKnown)
        ) {
            result[key] = existingValue[key];
        }
    });

    return result;
}

export function mergePublicKey(existingPublicKey, latestPublicKey, scope) {
    if (!isPlainObject(latestPublicKey)) {
        return isPlainObject(existingPublicKey) ? { ...existingPublicKey } : {};
    }

    const merged = { ...latestPublicKey };
    const existing = isPlainObject(existingPublicKey) ? existingPublicKey : {};

    const managedTopLevelKeys = scope === 'authentication'
        ? KNOWN_AUTHENTICATION_PUBLIC_KEY_KEYS
        : KNOWN_REGISTRATION_PUBLIC_KEY_KEYS;
    const normalizedManagedKeys = createNormalizedKeySet(managedTopLevelKeys);

    Object.keys(existing).forEach(key => {
        if (
            !Object.prototype.hasOwnProperty.call(merged, key)
            && !managedTopLevelKeys.has(key)
            && shouldPreserveUnknownKey(key, normalizedManagedKeys)
        ) {
            merged[key] = existing[key];
        }
    });

    if (scope !== 'authentication') {
        if (merged.rp) {
            merged.rp = mergeKnownProperties(existing.rp, merged.rp, KNOWN_RP_KEYS);
        }
        if (merged.user) {
            merged.user = mergeKnownProperties(existing.user, merged.user, KNOWN_USER_KEYS);
        }
        if (merged.authenticatorSelection) {
            merged.authenticatorSelection = mergeKnownProperties(
                existing.authenticatorSelection,
                merged.authenticatorSelection,
                KNOWN_AUTH_SELECTION_KEYS,
            );
        }
    }

    if (merged.extensions) {
        const existingExtensions = existing.extensions;
        const knownExtensionKeys = scope === 'authentication'
            ? KNOWN_AUTHENTICATION_EXTENSION_KEYS
            : KNOWN_REGISTRATION_EXTENSION_KEYS;
        merged.extensions = mergeKnownProperties(existingExtensions, merged.extensions, knownExtensionKeys);

        if (merged.extensions.largeBlob) {
            const largeBlobKeys = scope === 'authentication'
                ? KNOWN_LARGE_BLOB_AUTH_KEYS
                : KNOWN_LARGE_BLOB_REG_KEYS;
            merged.extensions.largeBlob = mergeKnownProperties(
                existingExtensions && existingExtensions.largeBlob,
                merged.extensions.largeBlob,
                largeBlobKeys,
            );
        }

        if (merged.extensions.prf) {
            merged.extensions.prf = mergeKnownProperties(
                existingExtensions && existingExtensions.prf,
                merged.extensions.prf,
                KNOWN_PRF_KEYS,
            );
            if (merged.extensions.prf && merged.extensions.prf.eval) {
                merged.extensions.prf.eval = mergeKnownProperties(
                    existingExtensions && existingExtensions.prf && existingExtensions.prf.eval,
                    merged.extensions.prf.eval,
                    KNOWN_PRF_EVAL_KEYS,
                );
            }
        }
    }

    if (
        scope === 'authentication'
        && Array.isArray(existing.allowCredentials)
        && existing.allowCredentials.length === 0
    ) {
        if (!Object.prototype.hasOwnProperty.call(merged, 'allowCredentials')) {
            merged.allowCredentials = [];
        } else if (!Array.isArray(merged.allowCredentials)) {
            merged.allowCredentials = [];
        }
    }

    return merged;
}

export function pruneUnsupportedProperties(mergedPublicKey, scope) {
    if (!isPlainObject(mergedPublicKey)) {
        return;
    }

    const validator = scope === 'authentication'
        ? validateAuthenticationPublicKey
        : validateRegistrationPublicKey;

    const maxAttempts = 10;
    for (let attempt = 0; attempt < maxAttempts; attempt += 1) {
        try {
            validator({ ...mergedPublicKey });
            return;
        } catch (error) {
            if (!(error instanceof Error)) {
                throw error;
            }

            const unsupportedMatch = /(publicKey(?:\.[a-zA-Z0-9]+)*) contains unsupported properties: (.+)/.exec(error.message);
            if (!unsupportedMatch) {
                throw error;
            }

            const [, path, properties] = unsupportedMatch;
            const propertyList = properties.split(',').map(prop => prop.trim()).filter(Boolean);
            if (propertyList.length === 0) {
                throw error;
            }

            const pathSegments = path.split('.').slice(1);
            let container = mergedPublicKey;
            for (const segment of pathSegments) {
                if (!isPlainObject(container[segment])) {
                    container = null;
                    break;
                }
                container = container[segment];
            }

            if (!isPlainObject(container)) {
                throw error;
            }

            propertyList.forEach(propertyName => {
                if (Object.prototype.hasOwnProperty.call(container, propertyName)) {
                    delete container[propertyName];
                }
            });
        }
    }
}
