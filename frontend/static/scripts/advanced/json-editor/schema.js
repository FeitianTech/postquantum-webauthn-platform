import { COSE_ALGORITHM_LABELS } from '../constants.js';

export const KNOWN_REGISTRATION_PUBLIC_KEY_KEYS = new Set([
    'rp',
    'user',
    'challenge',
    'pubKeyCredParams',
    'timeout',
    'authenticatorSelection',
    'attestation',
    'extensions',
    'excludeCredentials',
    'hints',
]);

export const KNOWN_AUTHENTICATION_PUBLIC_KEY_KEYS = new Set([
    'challenge',
    'timeout',
    'rpId',
    'allowCredentials',
    'userVerification',
    'extensions',
    'hints',
]);

export const KNOWN_RP_KEYS = new Set(['name', 'id']);
export const KNOWN_USER_KEYS = new Set(['id', 'name', 'displayName']);
export const KNOWN_AUTH_SELECTION_KEYS = new Set([
    'authenticatorAttachment',
    'residentKey',
    'requireResidentKey',
    'userVerification',
]);
export const KNOWN_REGISTRATION_EXTENSION_KEYS = new Set([
    'credProps',
    'minPinLength',
    'credentialProtectionPolicy',
    'enforceCredentialProtectionPolicy',
    'largeBlob',
    'prf',
]);
export const KNOWN_AUTHENTICATION_EXTENSION_KEYS = new Set(['largeBlob', 'prf']);
export const KNOWN_LARGE_BLOB_REG_KEYS = new Set(['support']);
export const KNOWN_LARGE_BLOB_AUTH_KEYS = new Set(['read', 'write']);
export const KNOWN_PRF_KEYS = new Set(['eval']);
export const KNOWN_PRF_EVAL_KEYS = new Set(['first', 'second']);
export const KNOWN_HINT_VALUES = new Set(['client-device', 'hybrid', 'security-key']);

export const KNOWN_ALGORITHMS = new Set(
    Object.keys(COSE_ALGORITHM_LABELS).map(key => Number.parseInt(key, 10)),
);

export function normalizeKeyName(key) {
    if (typeof key !== 'string') {
        return '';
    }
    return key.trim().toLowerCase().replace(/[^a-z0-9]+/g, '');
}

export function createNormalizedKeySet(keys) {
    const normalized = new Set();
    if (!keys) {
        return normalized;
    }

    (keys instanceof Set ? Array.from(keys) : keys).forEach(key => {
        const normalizedKey = normalizeKeyName(key);
        if (normalizedKey) {
            normalized.add(normalizedKey);
        }
    });

    return normalized;
}

export function shouldPreserveUnknownKey(key, normalizedKnownKeys) {
    const normalizedKey = normalizeKeyName(key);
    if (!normalizedKey) {
        return false;
    }
    if (normalizedKnownKeys.has(normalizedKey)) {
        return false;
    }

    for (const known of normalizedKnownKeys) {
        if (normalizedKey.startsWith(known) && normalizedKey.length - known.length <= 8) {
            return false;
        }
        if (normalizedKey.endsWith(known) && normalizedKey.length - known.length <= 8) {
            return false;
        }
    }

    return true;
}

export function isPlainObject(value) {
    return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

export function assertPlainObject(value, path) {
    if (!isPlainObject(value)) {
        throw new Error(`${path} must be an object.`);
    }
}

export function assertAllowedKeys(object, allowedKeys, path) {
    if (!isPlainObject(object)) {
        return;
    }

    const keys = Object.keys(object);
    const invalid = keys.filter(key => !allowedKeys.has(key));
    if (invalid.length > 0) {
        throw new Error(`${path} contains unsupported properties: ${invalid.join(', ')}`);
    }
}
