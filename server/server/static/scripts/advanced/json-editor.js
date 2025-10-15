import { state } from '../shared/state.js';
import {
    base64ToHex,
    base64UrlToHex,
    convertFormat,
    currentFormatToJsonFormat,
    getCurrentBinaryFormat,
    sortObjectKeys
} from '../shared/binary-utils.js';
import {
    collectSelectedHints,
    deriveAllowedAttachmentsFromHints,
    enforceAuthenticatorAttachmentWithHints,
    applyHintsToCheckboxes,
    registerHintsChangeCallback
} from './hints.js';
import {
    getCredentialIdHex,
    getCredentialUserHandleHex,
    getStoredCredentialAttachment,
    extractHexFromJsonFormat
} from './credential-utils.js';
import { showStatus } from '../shared/status.js';
import {
    getFakeExcludeCredentials,
    getFakeAllowCredentials,
    setFakeExcludeCredentials
} from './exclude-credentials.js';
import { COSE_ALGORITHM_LABELS } from './constants.js';

registerHintsChangeCallback(() => updateJsonEditor());

const KNOWN_REGISTRATION_PUBLIC_KEY_KEYS = new Set([
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

const KNOWN_AUTHENTICATION_PUBLIC_KEY_KEYS = new Set([
    'challenge',
    'timeout',
    'rpId',
    'allowCredentials',
    'userVerification',
    'extensions',
    'hints',
]);

const KNOWN_RP_KEYS = new Set(['name', 'id']);
const KNOWN_USER_KEYS = new Set(['id', 'name', 'displayName']);
const KNOWN_AUTH_SELECTION_KEYS = new Set([
    'authenticatorAttachment',
    'residentKey',
    'requireResidentKey',
    'userVerification',
]);
const KNOWN_REGISTRATION_EXTENSION_KEYS = new Set([
    'credProps',
    'minPinLength',
    'credentialProtectionPolicy',
    'enforceCredentialProtectionPolicy',
    'largeBlob',
    'prf',
]);
const KNOWN_AUTHENTICATION_EXTENSION_KEYS = new Set(['largeBlob', 'prf']);
const KNOWN_LARGE_BLOB_REG_KEYS = new Set(['support']);
const KNOWN_LARGE_BLOB_AUTH_KEYS = new Set(['read', 'write']);
const KNOWN_PRF_KEYS = new Set(['eval']);
const KNOWN_PRF_EVAL_KEYS = new Set(['first', 'second']);
const KNOWN_HINT_VALUES = new Set(['client-device', 'hybrid', 'security-key']);

const KNOWN_ALGORITHMS = new Set(Object.keys(COSE_ALGORITHM_LABELS).map(key => Number.parseInt(key, 10)));

function normalizeKeyName(key) {
    if (typeof key !== 'string') {
        return '';
    }
    return key.trim().toLowerCase().replace(/[^a-z0-9]+/g, '');
}

function createNormalizedKeySet(keys) {
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

function shouldPreserveUnknownKey(key, normalizedKnownKeys) {
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

function isPlainObject(value) {
    return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

function assertPlainObject(value, path) {
    if (!isPlainObject(value)) {
        throw new Error(`${path} must be an object.`);
    }
}

function assertAllowedKeys(object, allowedKeys, path) {
    if (!isPlainObject(object)) {
        return;
    }
    const keys = Object.keys(object);
    const invalid = keys.filter(key => !allowedKeys.has(key));
    if (invalid.length > 0) {
        throw new Error(`${path} contains unsupported properties: ${invalid.join(', ')}`);
    }
}

function validateBinaryField(value, path, { allowEmpty = false } = {}) {
    if (value === null || value === undefined) {
        if (allowEmpty) {
            return '';
        }
        throw new Error(`${path} is required.`);
    }

    let hexValue;
    try {
        hexValue = extractHexFromJsonFormat(value);
    } catch (error) {
        hexValue = '';
    }

    if (!hexValue) {
        if (allowEmpty && typeof value === 'string' && value.trim() === '') {
            return '';
        }
        throw new Error(`${path} must be a base64url, base64, or hexadecimal value.`);
    }

    return hexValue;
}

function normalizeInteger(value, path) {
    if (value === null || value === undefined) {
        return null;
    }
    if (typeof value === 'number' && Number.isFinite(value)) {
        return Math.floor(value);
    }
    if (typeof value === 'string') {
        const trimmed = value.trim();
        if (!trimmed) {
            return null;
        }
        const parsed = Number.parseInt(trimmed, 10);
        if (!Number.isNaN(parsed) && Number.isFinite(parsed)) {
            return parsed;
        }
    }
    throw new Error(`${path} must be a whole number.`);
}

function validateHints(hints, path) {
    if (hints === undefined) {
        return;
    }
    if (!Array.isArray(hints)) {
        throw new Error(`${path} must be an array of strings.`);
    }
    hints.forEach((hint, index) => {
        if (typeof hint !== 'string') {
            throw new Error(`${path}[${index}] must be a string.`);
        }
        const normalized = hint.trim().toLowerCase();
        if (!KNOWN_HINT_VALUES.has(normalized)) {
            throw new Error(`${path}[${index}] is not a supported hint value.`);
        }
    });
}

function validateRegistrationPublicKey(publicKey) {
    assertPlainObject(publicKey, 'publicKey');
    assertAllowedKeys(publicKey, KNOWN_REGISTRATION_PUBLIC_KEY_KEYS, 'publicKey');

    assertPlainObject(publicKey.rp, 'publicKey.rp');
    assertAllowedKeys(publicKey.rp, KNOWN_RP_KEYS, 'publicKey.rp');
    if (typeof publicKey.rp.name !== 'string' || !publicKey.rp.name.trim()) {
        throw new Error('publicKey.rp.name must be a non-empty string.');
    }
    if (publicKey.rp.id !== undefined && typeof publicKey.rp.id !== 'string') {
        throw new Error('publicKey.rp.id must be a string when provided.');
    }

    assertPlainObject(publicKey.user, 'publicKey.user');
    assertAllowedKeys(publicKey.user, KNOWN_USER_KEYS, 'publicKey.user');
    validateBinaryField(publicKey.user.id, 'publicKey.user.id');
    if (typeof publicKey.user.name !== 'string' || !publicKey.user.name.trim()) {
        throw new Error('publicKey.user.name must be a non-empty string.');
    }
    if (typeof publicKey.user.displayName !== 'string' || !publicKey.user.displayName.trim()) {
        throw new Error('publicKey.user.displayName must be a non-empty string.');
    }

    validateBinaryField(publicKey.challenge, 'publicKey.challenge');

    if (publicKey.timeout !== undefined) {
        const timeoutValue = normalizeInteger(publicKey.timeout, 'publicKey.timeout');
        if (timeoutValue !== null && timeoutValue < 0) {
            throw new Error('publicKey.timeout must be zero or greater.');
        }
    }

    if (publicKey.pubKeyCredParams !== undefined) {
        if (!Array.isArray(publicKey.pubKeyCredParams)) {
            throw new Error('publicKey.pubKeyCredParams must be an array.');
        }
        publicKey.pubKeyCredParams.forEach((param, index) => {
            assertPlainObject(param, `publicKey.pubKeyCredParams[${index}]`);
            const { type, alg } = param;
            if (type && type !== 'public-key') {
                throw new Error(`publicKey.pubKeyCredParams[${index}].type must be "public-key".`);
            }
            if (alg === undefined || alg === null) {
                throw new Error(`publicKey.pubKeyCredParams[${index}].alg is required.`);
            }
            const normalizedAlg = typeof alg === 'string' ? Number.parseInt(alg, 10) : alg;
            if (Number.isNaN(normalizedAlg) || !Number.isFinite(normalizedAlg)) {
                throw new Error(`publicKey.pubKeyCredParams[${index}].alg must be a valid COSE algorithm number.`);
            }
            if (!KNOWN_ALGORITHMS.has(Number(normalizedAlg))) {
                throw new Error(`publicKey.pubKeyCredParams[${index}].alg is not a supported algorithm.`);
            }
        });
    }

    if (publicKey.authenticatorSelection !== undefined) {
        assertPlainObject(publicKey.authenticatorSelection, 'publicKey.authenticatorSelection');
        assertAllowedKeys(publicKey.authenticatorSelection, KNOWN_AUTH_SELECTION_KEYS, 'publicKey.authenticatorSelection');
        const selection = publicKey.authenticatorSelection;
        if (selection.authenticatorAttachment !== undefined) {
            const attachment = selection.authenticatorAttachment;
            if (typeof attachment !== 'string' || !['platform', 'cross-platform'].includes(attachment)) {
                throw new Error('publicKey.authenticatorSelection.authenticatorAttachment must be "platform" or "cross-platform".');
            }
        }
        if (selection.residentKey !== undefined) {
            if (typeof selection.residentKey !== 'string' || !['discouraged', 'preferred', 'required'].includes(selection.residentKey)) {
                throw new Error('publicKey.authenticatorSelection.residentKey must be discouraged, preferred, or required.');
            }
        }
        if (selection.requireResidentKey !== undefined && typeof selection.requireResidentKey !== 'boolean') {
            throw new Error('publicKey.authenticatorSelection.requireResidentKey must be a boolean.');
        }
        if (selection.userVerification !== undefined) {
            if (typeof selection.userVerification !== 'string' || !['required', 'preferred', 'discouraged'].includes(selection.userVerification)) {
                throw new Error('publicKey.authenticatorSelection.userVerification must be required, preferred, or discouraged.');
            }
        }
    }

    if (publicKey.attestation !== undefined) {
        if (typeof publicKey.attestation !== 'string' || !['none', 'indirect', 'direct', 'enterprise'].includes(publicKey.attestation)) {
            throw new Error('publicKey.attestation must be none, indirect, direct, or enterprise.');
        }
    }

    if (publicKey.excludeCredentials !== undefined) {
        if (!Array.isArray(publicKey.excludeCredentials)) {
            throw new Error('publicKey.excludeCredentials must be an array.');
        }
        publicKey.excludeCredentials.forEach((descriptor, index) => {
            assertPlainObject(descriptor, `publicKey.excludeCredentials[${index}]`);
            if (descriptor.type && descriptor.type !== 'public-key') {
                throw new Error(`publicKey.excludeCredentials[${index}].type must be "public-key".`);
            }
            validateBinaryField(descriptor.id, `publicKey.excludeCredentials[${index}].id`);
            if (descriptor.transports !== undefined) {
                if (!Array.isArray(descriptor.transports) || !descriptor.transports.every(item => typeof item === 'string')) {
                    throw new Error(`publicKey.excludeCredentials[${index}].transports must be an array of strings.`);
                }
            }
        });
    }

    if (publicKey.extensions !== undefined) {
        assertPlainObject(publicKey.extensions, 'publicKey.extensions');
        assertAllowedKeys(publicKey.extensions, KNOWN_REGISTRATION_EXTENSION_KEYS, 'publicKey.extensions');
        const extensions = publicKey.extensions;
        if (extensions.credProps !== undefined && typeof extensions.credProps !== 'boolean') {
            throw new Error('publicKey.extensions.credProps must be a boolean.');
        }
        if (extensions.minPinLength !== undefined && typeof extensions.minPinLength !== 'boolean') {
            throw new Error('publicKey.extensions.minPinLength must be a boolean.');
        }
        if (extensions.credentialProtectionPolicy !== undefined) {
            if (typeof extensions.credentialProtectionPolicy !== 'string' || ![
                'userVerificationOptional',
                'userVerificationOptionalWithCredentialIDList',
                'userVerificationRequired',
            ].includes(extensions.credentialProtectionPolicy)) {
                throw new Error('publicKey.extensions.credentialProtectionPolicy must be a recognised policy value.');
            }
        }
        if (extensions.enforceCredentialProtectionPolicy !== undefined && typeof extensions.enforceCredentialProtectionPolicy !== 'boolean') {
            throw new Error('publicKey.extensions.enforceCredentialProtectionPolicy must be a boolean.');
        }
        if (extensions.largeBlob !== undefined) {
            assertPlainObject(extensions.largeBlob, 'publicKey.extensions.largeBlob');
            assertAllowedKeys(extensions.largeBlob, KNOWN_LARGE_BLOB_REG_KEYS, 'publicKey.extensions.largeBlob');
            if (extensions.largeBlob.support !== undefined) {
                if (typeof extensions.largeBlob.support !== 'string' || !['preferred', 'required'].includes(extensions.largeBlob.support)) {
                    throw new Error('publicKey.extensions.largeBlob.support must be preferred or required.');
                }
            }
        }
        if (extensions.prf !== undefined) {
            assertPlainObject(extensions.prf, 'publicKey.extensions.prf');
            assertAllowedKeys(extensions.prf, KNOWN_PRF_KEYS, 'publicKey.extensions.prf');
            if (extensions.prf.eval !== undefined) {
                assertPlainObject(extensions.prf.eval, 'publicKey.extensions.prf.eval');
                assertAllowedKeys(extensions.prf.eval, KNOWN_PRF_EVAL_KEYS, 'publicKey.extensions.prf.eval');
                if (extensions.prf.eval.first !== undefined) {
                    validateBinaryField(extensions.prf.eval.first, 'publicKey.extensions.prf.eval.first');
                }
                if (extensions.prf.eval.second !== undefined) {
                    validateBinaryField(extensions.prf.eval.second, 'publicKey.extensions.prf.eval.second');
                }
            }
        }
    }

    validateHints(publicKey.hints, 'publicKey.hints');
}

function validateAuthenticationPublicKey(publicKey) {
    assertPlainObject(publicKey, 'publicKey');
    assertAllowedKeys(publicKey, KNOWN_AUTHENTICATION_PUBLIC_KEY_KEYS, 'publicKey');

    validateBinaryField(publicKey.challenge, 'publicKey.challenge');

    if (publicKey.timeout !== undefined) {
        const timeoutValue = normalizeInteger(publicKey.timeout, 'publicKey.timeout');
        if (timeoutValue !== null && timeoutValue < 0) {
            throw new Error('publicKey.timeout must be zero or greater.');
        }
    }

    if (publicKey.rpId !== undefined && (typeof publicKey.rpId !== 'string' || !publicKey.rpId.trim())) {
        throw new Error('publicKey.rpId must be a non-empty string when provided.');
    }

    if (publicKey.allowCredentials !== undefined) {
        if (!Array.isArray(publicKey.allowCredentials)) {
            throw new Error('publicKey.allowCredentials must be an array.');
        }
        publicKey.allowCredentials.forEach((descriptor, index) => {
            assertPlainObject(descriptor, `publicKey.allowCredentials[${index}]`);
            if (descriptor.type && descriptor.type !== 'public-key') {
                throw new Error(`publicKey.allowCredentials[${index}].type must be "public-key".`);
            }
            validateBinaryField(descriptor.id, `publicKey.allowCredentials[${index}].id`);
            if (descriptor.transports !== undefined) {
                if (!Array.isArray(descriptor.transports) || !descriptor.transports.every(item => typeof item === 'string')) {
                    throw new Error(`publicKey.allowCredentials[${index}].transports must be an array of strings.`);
                }
            }
        });
    }

    if (publicKey.userVerification !== undefined) {
        if (typeof publicKey.userVerification !== 'string' || !['required', 'preferred', 'discouraged'].includes(publicKey.userVerification)) {
            throw new Error('publicKey.userVerification must be required, preferred, or discouraged.');
        }
    }

    if (publicKey.extensions !== undefined) {
        assertPlainObject(publicKey.extensions, 'publicKey.extensions');
        assertAllowedKeys(publicKey.extensions, KNOWN_AUTHENTICATION_EXTENSION_KEYS, 'publicKey.extensions');
        const extensions = publicKey.extensions;
        if (extensions.largeBlob !== undefined) {
            assertPlainObject(extensions.largeBlob, 'publicKey.extensions.largeBlob');
            assertAllowedKeys(extensions.largeBlob, KNOWN_LARGE_BLOB_AUTH_KEYS, 'publicKey.extensions.largeBlob');
            if (extensions.largeBlob.read !== undefined && typeof extensions.largeBlob.read !== 'boolean') {
                throw new Error('publicKey.extensions.largeBlob.read must be a boolean.');
            }
            if (extensions.largeBlob.write !== undefined) {
                validateBinaryField(extensions.largeBlob.write, 'publicKey.extensions.largeBlob.write');
            }
        }
        if (extensions.prf !== undefined) {
            assertPlainObject(extensions.prf, 'publicKey.extensions.prf');
            assertAllowedKeys(extensions.prf, KNOWN_PRF_KEYS, 'publicKey.extensions.prf');
            if (extensions.prf.eval !== undefined) {
                assertPlainObject(extensions.prf.eval, 'publicKey.extensions.prf.eval');
                assertAllowedKeys(extensions.prf.eval, KNOWN_PRF_EVAL_KEYS, 'publicKey.extensions.prf.eval');
                if (extensions.prf.eval.first !== undefined) {
                    validateBinaryField(extensions.prf.eval.first, 'publicKey.extensions.prf.eval.first');
                }
                if (extensions.prf.eval.second !== undefined) {
                    validateBinaryField(extensions.prf.eval.second, 'publicKey.extensions.prf.eval.second');
                }
            }
        }
    }

    validateHints(publicKey.hints, 'publicKey.hints');
}

function mergeKnownProperties(existingValue, latestValue, knownKeys) {
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

function mergePublicKey(existingPublicKey, latestPublicKey, scope) {
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

    return merged;
}

function pruneUnsupportedProperties(mergedPublicKey, scope) {
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

function buildOptionsForCurrentScope(scope) {
    if (scope === 'authentication') {
        return getCredentialRequestOptions();
    }
    return getCredentialCreationOptions();
}

function mergeParsedJsonWithForm(parsedRoot, scope) {
    const latestOptions = buildOptionsForCurrentScope(scope);
    const latestPublicKey = latestOptions?.publicKey || {};

    if (!isPlainObject(parsedRoot)) {
        return latestOptions;
    }

    const merged = { ...parsedRoot };

    Object.keys(latestOptions).forEach(key => {
        if (key === 'publicKey') {
            merged.publicKey = mergePublicKey(parsedRoot.publicKey, latestPublicKey, scope);
            pruneUnsupportedProperties(merged.publicKey, scope);
        } else {
            merged[key] = latestOptions[key];
        }
    });

    return merged;
}

function setJsonEditorContent(content) {
    const jsonEditor = document.getElementById('json-editor');
    if (!jsonEditor) {
        return;
    }
    jsonEditor.value = content;
    jsonEditor.scrollTop = 0;
    jsonEditor.scrollLeft = 0;
}

export function getCredentialCreationOptions() {
    const userId = document.getElementById('user-id')?.value || '';
    const userName = document.getElementById('user-name')?.value || '';
    const userDisplayName = document.getElementById('user-display-name')?.value || '';
    const challenge = document.getElementById('challenge-reg')?.value || '';

    const publicKey = {
        rp: {
            name: 'Post-Quantum WebAuthn Test Platform',
            id: window.location.hostname
        },
        user: {
            id: currentFormatToJsonFormat(userId),
            name: userName,
            displayName: userDisplayName
        },
        challenge: currentFormatToJsonFormat(challenge),
        pubKeyCredParams: [],
        timeout: parseInt(document.getElementById('timeout-reg')?.value) || 90000,
        authenticatorSelection: {},
        attestation: document.getElementById('attestation')?.value || 'direct',
        extensions: {}
    };

    const authenticatorAttachment = document.getElementById('authenticator-attachment')?.value || 'cross-platform';
    if (authenticatorAttachment && authenticatorAttachment !== 'unspecified') {
        publicKey.authenticatorSelection.authenticatorAttachment = authenticatorAttachment;
    }

    if (document.getElementById('param-mldsa44')?.checked) {
        publicKey.pubKeyCredParams.push({type: 'public-key', alg: -48});
    }
    if (document.getElementById('param-mldsa65')?.checked) {
        publicKey.pubKeyCredParams.push({type: 'public-key', alg: -49});
    }
    if (document.getElementById('param-mldsa87')?.checked) {
        publicKey.pubKeyCredParams.push({type: 'public-key', alg: -50});
    }
    if (document.getElementById('param-eddsa')?.checked) {
        publicKey.pubKeyCredParams.push({type: 'public-key', alg: -8});
    }
    if (document.getElementById('param-es256')?.checked) {
        publicKey.pubKeyCredParams.push({type: 'public-key', alg: -7});
    }
    if (document.getElementById('param-rs256')?.checked) {
        publicKey.pubKeyCredParams.push({type: 'public-key', alg: -257});
    }
    if (document.getElementById('param-es384')?.checked) {
        publicKey.pubKeyCredParams.push({type: 'public-key', alg: -35});
    }
    if (document.getElementById('param-es512')?.checked) {
        publicKey.pubKeyCredParams.push({type: 'public-key', alg: -36});
    }
    if (document.getElementById('param-rs384')?.checked) {
        publicKey.pubKeyCredParams.push({type: 'public-key', alg: -258});
    }
    if (document.getElementById('param-rs512')?.checked) {
        publicKey.pubKeyCredParams.push({type: 'public-key', alg: -259});
    }
    if (document.getElementById('param-rs1')?.checked) {
        publicKey.pubKeyCredParams.push({type: 'public-key', alg: -65535});
    }
    if (document.getElementById('param-es256k')?.checked) {
        publicKey.pubKeyCredParams.push({type: 'public-key', alg: -47});
    }
    if (document.getElementById('param-esp256')?.checked) {
        publicKey.pubKeyCredParams.push({type: 'public-key', alg: -9});
    }
    if (document.getElementById('param-esp384')?.checked) {
        publicKey.pubKeyCredParams.push({type: 'public-key', alg: -51});
    }
    if (document.getElementById('param-esp512')?.checked) {
        publicKey.pubKeyCredParams.push({type: 'public-key', alg: -52});
    }
    if (document.getElementById('param-ps256')?.checked) {
        publicKey.pubKeyCredParams.push({type: 'public-key', alg: -37});
    }
    if (document.getElementById('param-ps384')?.checked) {
        publicKey.pubKeyCredParams.push({type: 'public-key', alg: -38});
    }
    if (document.getElementById('param-ps512')?.checked) {
        publicKey.pubKeyCredParams.push({type: 'public-key', alg: -39});
    }
    if (document.getElementById('param-ed448')?.checked) {
        publicKey.pubKeyCredParams.push({type: 'public-key', alg: -53});
    }

    const residentKeyValue = document.getElementById('resident-key')?.value || 'discouraged';
    publicKey.authenticatorSelection.residentKey = residentKeyValue;
    publicKey.authenticatorSelection.requireResidentKey = residentKeyValue === 'required';

    const userVerification = document.getElementById('user-verification-reg')?.value;
    if (userVerification) publicKey.authenticatorSelection.userVerification = userVerification;

    const excludeList = [];
    const includeExcludes = document.getElementById('exclude-credentials')?.checked;
    if (includeExcludes) {
        const currentBinaryFormat = getCurrentBinaryFormat();
        const userIdHex = (convertFormat(userId, currentBinaryFormat, 'hex') || '').toLowerCase();

        if (userIdHex && Array.isArray(state.storedCredentials) && state.storedCredentials.length > 0) {
            state.storedCredentials.forEach(cred => {
                const handleHex = getCredentialUserHandleHex(cred);
                const credentialIdHex = getCredentialIdHex(cred);

                if (handleHex && credentialIdHex && handleHex === userIdHex) {
                    excludeList.push({
                        type: 'public-key',
                        id: {
                            '$hex': credentialIdHex
                        }
                    });
                }
            });
        }

        getFakeExcludeCredentials().forEach(hexValue => {
            if (!hexValue) {
                return;
            }

            let idValue = { '$hex': hexValue };
            try {
                const formattedValue = convertFormat(hexValue, 'hex', currentBinaryFormat);
                const jsonValue = currentFormatToJsonFormat(formattedValue);
                if (jsonValue && typeof jsonValue === 'object') {
                    idValue = jsonValue;
                }
            } catch (error) {
                // Fall back to hex representation on conversion errors
            }

            excludeList.push({
                type: 'public-key',
                id: idValue,
            });
        });
    }

    publicKey.excludeCredentials = excludeList;

    if (document.getElementById('cred-props')?.checked) publicKey.extensions.credProps = true;
    if (document.getElementById('min-pin-length')?.checked) publicKey.extensions.minPinLength = true;

    const credentialProtection = document.getElementById('cred-protect')?.value;
    if (credentialProtection) {
        publicKey.extensions.credentialProtectionPolicy = credentialProtection;
        if (document.getElementById('enforce-cred-protect')?.checked) {
            publicKey.extensions.enforceCredentialProtectionPolicy = true;
        }
    }

    const largeBlobReg = document.getElementById('large-blob-reg')?.value;
    if (largeBlobReg) publicKey.extensions.largeBlob = {support: largeBlobReg};

    if (document.getElementById('prf-reg')?.checked) {
        const prfFirst = document.getElementById('prf-eval-first-reg')?.value;
        const prfSecond = document.getElementById('prf-eval-second-reg')?.value;
        if (prfFirst) {
            publicKey.extensions.prf = {
                eval: {
                    first: currentFormatToJsonFormat(prfFirst)
                }
            };
            if (prfSecond) {
                publicKey.extensions.prf.eval.second = currentFormatToJsonFormat(prfSecond);
            }
        }
    }

    const hints = collectSelectedHints('registration');
    if (hints.length > 0) publicKey.hints = hints;

    enforceAuthenticatorAttachmentWithHints(publicKey);

    return { publicKey };
}

export function getCredentialRequestOptions() {
    const challenge = document.getElementById('challenge-auth')?.value || '';
    const hints = collectSelectedHints('authentication');
    const allowedAttachments = deriveAllowedAttachmentsFromHints(hints);

    const publicKey = {
        challenge: currentFormatToJsonFormat(challenge),
        timeout: parseInt(document.getElementById('timeout-auth')?.value) || 90000,
        rpId: window.location.hostname,
        allowCredentials: [],
        userVerification: document.getElementById('user-verification-auth')?.value || 'preferred',
        extensions: {},
    };

    const allowCreds = document.getElementById('allow-credentials')?.value;
    let shouldRemoveAllowCredentials = false;

    if (allowCreds === 'empty') {
        publicKey.allowCredentials = [];
        shouldRemoveAllowCredentials = true;
    } else if (allowCreds === 'all') {
        const credentialSource = (state.storedCredentials || []).filter(cred => {
            if (allowedAttachments.length === 0) {
                return true;
            }
            const attachment = getStoredCredentialAttachment(cred);
            return attachment && allowedAttachments.includes(attachment);
        });

        const allCredentials = credentialSource
            .map(cred => {
                const credentialIdHex = cred.credentialIdHex || getCredentialIdHex(cred);
                if (!credentialIdHex) {
                    return null;
                }

                const formatValue = convertFormat(credentialIdHex, 'hex', getCurrentBinaryFormat());
                const formattedId = currentFormatToJsonFormat(formatValue);
                if (!formattedId || typeof formattedId !== 'object') {
                    return null;
                }

                return {
                    type: 'public-key',
                    id: formattedId,
                };
            })
            .filter(Boolean);
        publicKey.allowCredentials = allCredentials;
    } else {
        const selectedCred = (state.storedCredentials || []).find(
            cred => (cred.credentialIdHex || getCredentialIdHex(cred)) === allowCreds
        );
        if (selectedCred) {
            const attachment = getStoredCredentialAttachment(selectedCred);
            if (allowedAttachments.length > 0 && (!attachment || !allowedAttachments.includes(attachment))) {
                publicKey.allowCredentials = [];
            } else {
                const credentialIdHex = selectedCred.credentialIdHex || getCredentialIdHex(selectedCred);
                const formatValue = convertFormat(credentialIdHex, 'hex', getCurrentBinaryFormat());
                const formattedId = currentFormatToJsonFormat(formatValue);
                if (formattedId && typeof formattedId === 'object') {
                    publicKey.allowCredentials = [{
                        type: 'public-key',
                        id: formattedId,
                    }];
                }
            }
        } else {
            const fallbackSource = (state.storedCredentials || []).filter(cred => {
                if (allowedAttachments.length === 0) {
                    return true;
                }
                const attachment = getStoredCredentialAttachment(cred);
                return attachment && allowedAttachments.includes(attachment);
            });
            const fallbackCredentials = fallbackSource
                .map(cred => {
                    const credentialIdHex = cred.credentialIdHex || getCredentialIdHex(cred);
                    if (!credentialIdHex) {
                        return null;
                    }

                    const formatValue = convertFormat(credentialIdHex, 'hex', getCurrentBinaryFormat());
                    const formattedId = currentFormatToJsonFormat(formatValue);
                    if (!formattedId || typeof formattedId !== 'object') {
                        return null;
                    }

                    return {
                        type: 'public-key',
                        id: formattedId,
                    };
                })
                .filter(Boolean);
            publicKey.allowCredentials = fallbackCredentials;
        }
    }

    const fakeAllowCredentials = getFakeAllowCredentials();
    if (Array.isArray(fakeAllowCredentials) && fakeAllowCredentials.length) {
        if (!Array.isArray(publicKey.allowCredentials)) {
            publicKey.allowCredentials = [];
        }

        fakeAllowCredentials.forEach(hexValue => {
            if (!hexValue) {
                return;
            }

            let idValue = { '$hex': hexValue };
            try {
                const formattedValue = convertFormat(hexValue, 'hex', getCurrentBinaryFormat());
                const jsonValue = currentFormatToJsonFormat(formattedValue);
                if (jsonValue && typeof jsonValue === 'object') {
                    idValue = jsonValue;
                }
            } catch (error) {
                // Fallback to hex representation if conversion fails.
            }

            publicKey.allowCredentials.push({
                type: 'public-key',
                id: idValue,
            });
        });

        shouldRemoveAllowCredentials = false;
    }

    if (shouldRemoveAllowCredentials && (!publicKey.allowCredentials || !publicKey.allowCredentials.length)) {
        delete publicKey.allowCredentials;
    }

    const largeBlobAuth = document.getElementById('large-blob-auth')?.value;
    if (largeBlobAuth) {
        if (largeBlobAuth === 'read') {
            publicKey.extensions.largeBlob = {read: true};
        } else if (largeBlobAuth === 'write') {
            const largeBlobWrite = document.getElementById('large-blob-write')?.value;
            if (largeBlobWrite) {
                publicKey.extensions.largeBlob = {
                    write: currentFormatToJsonFormat(largeBlobWrite)
                };
            }
        }
    }

    const prfFirst = document.getElementById('prf-eval-first-auth')?.value;
    const prfSecond = document.getElementById('prf-eval-second-auth')?.value;
    if (prfFirst) {
        publicKey.extensions.prf = {
            eval: {
                first: currentFormatToJsonFormat(prfFirst)
            }
        };
        if (prfSecond) {
            publicKey.extensions.prf.eval.second = currentFormatToJsonFormat(prfSecond);
        }
    }

    if (hints.length > 0) publicKey.hints = hints;

    return { publicKey };
}

export function updateJsonEditor() {
    let options = {};
    let title = 'JSON Editor';

    if (state.currentSubTab === 'registration') {
        options = getCredentialCreationOptions();
        title = 'JSON Editor (CredentialCreationOptions)';
    } else if (state.currentSubTab === 'authentication') {
        options = getCredentialRequestOptions();
        title = 'JSON Editor (CredentialRequestOptions)';
    }

    const sortedOptions = sortObjectKeys(options);
    setJsonEditorContent(JSON.stringify(sortedOptions, null, 2));

    const titleElement = document.querySelector('.json-editor-column h3');
    if (titleElement) {
        titleElement.textContent = title;
    }
}

export function saveJsonEditor() {
    try {
        const editor = document.getElementById('json-editor');
        const jsonText = editor ? editor.value : '';
        const parsed = JSON.parse(jsonText || '{}');

        if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
            throw new Error('Invalid JSON structure.');
        }

        if (!parsed.publicKey || typeof parsed.publicKey !== 'object') {
            throw new Error('Invalid JSON structure: Missing "publicKey" object.');
        }

        const scope = state.currentSubTab === 'authentication' ? 'authentication' : 'registration';

        if (scope === 'registration') {
            validateRegistrationPublicKey(parsed.publicKey);
            updateRegistrationFormFromJson(parsed.publicKey);
        } else {
            validateAuthenticationPublicKey(parsed.publicKey);
            updateAuthenticationFormFromJson(parsed.publicKey);
        }

        const merged = mergeParsedJsonWithForm(parsed, scope);
        const sorted = sortObjectKeys(merged);
        setJsonEditorContent(JSON.stringify(sorted, null, 2));

        showStatus('advanced', 'JSON changes saved successfully!', 'success');
    } catch (error) {
        showStatus('advanced', `JSON validation failed: ${error.message}`, 'error');
    }
}

export function resetJsonEditor() {
    const scope = state.currentSubTab === 'authentication' ? 'authentication' : 'registration';
    const editor = document.getElementById('json-editor');
    let parsed = null;

    if (editor && editor.value) {
        try {
            parsed = JSON.parse(editor.value);
        } catch (error) {
            parsed = null;
        }
    }

    try {
        const merged = mergeParsedJsonWithForm(parsed, scope);
        const sorted = sortObjectKeys(merged);
        setJsonEditorContent(JSON.stringify(sorted, null, 2));
        showStatus('advanced', 'JSON editor reset to current settings.', 'info');
    } catch (error) {
        showStatus('advanced', `Unable to reset JSON editor: ${error.message}`, 'error');
    }
}

export function updateRegistrationFormFromJson(publicKey) {
    if (publicKey.user) {
        if (publicKey.user.id) {
            let userIdValue = '';
            if (publicKey.user.id.$base64) {
                userIdValue = base64UrlToHex(publicKey.user.id.$base64);
            } else if (publicKey.user.id.$base64url) {
                userIdValue = base64UrlToHex(publicKey.user.id.$base64url);
            } else if (publicKey.user.id.$hex) {
                userIdValue = publicKey.user.id.$hex;
            } else if (typeof publicKey.user.id === 'string') {
                userIdValue = base64UrlToHex(publicKey.user.id);
            }
            if (userIdValue) {
                document.getElementById('user-id').value = userIdValue;
            }
        }
        if (publicKey.user.name) {
            document.getElementById('user-name').value = publicKey.user.name;
        }
        if (publicKey.user.displayName) {
            document.getElementById('user-display-name').value = publicKey.user.displayName;
        }
    }

    if (publicKey.challenge) {
        let challengeValue = '';
        if (publicKey.challenge.$base64) {
            challengeValue = base64UrlToHex(publicKey.challenge.$base64);
        } else if (publicKey.challenge.$base64url) {
            challengeValue = base64UrlToHex(publicKey.challenge.$base64url);
        } else if (publicKey.challenge.$hex) {
            challengeValue = publicKey.challenge.$hex;
        } else if (typeof publicKey.challenge === 'string') {
            challengeValue = base64UrlToHex(publicKey.challenge);
        }
        if (challengeValue) {
            document.getElementById('challenge-reg').value = challengeValue;
        }
    }

    if (publicKey.timeout) {
        document.getElementById('timeout-reg').value = publicKey.timeout.toString();
    }

    if (Object.prototype.hasOwnProperty.call(publicKey, 'attestation')) {
        document.getElementById('attestation').value = publicKey.attestation || 'direct';
    }

    if (publicKey.pubKeyCredParams && Array.isArray(publicKey.pubKeyCredParams)) {
        if (document.getElementById('param-mldsa44')) document.getElementById('param-mldsa44').checked = false;
        if (document.getElementById('param-mldsa65')) document.getElementById('param-mldsa65').checked = false;
        if (document.getElementById('param-mldsa87')) document.getElementById('param-mldsa87').checked = false;
        document.getElementById('param-eddsa').checked = false;
        document.getElementById('param-es256').checked = false;
        document.getElementById('param-rs256').checked = false;
        document.getElementById('param-es384').checked = false;
        document.getElementById('param-es512').checked = false;
        document.getElementById('param-rs384').checked = false;
        document.getElementById('param-rs512').checked = false;
        document.getElementById('param-rs1').checked = false;
        document.getElementById('param-es256k').checked = false;
        document.getElementById('param-esp256').checked = false;
        document.getElementById('param-esp384').checked = false;
        document.getElementById('param-esp512').checked = false;
        document.getElementById('param-ps256').checked = false;
        document.getElementById('param-ps384').checked = false;
        document.getElementById('param-ps512').checked = false;
        document.getElementById('param-ed448').checked = false;

        publicKey.pubKeyCredParams.forEach(param => {
            if (param && Object.prototype.hasOwnProperty.call(param, 'alg')) {
                const rawAlg = param.alg;
                const algValue = typeof rawAlg === 'string' ? parseInt(rawAlg, 10) : rawAlg;
                if (Number.isNaN(algValue)) {
                    return;
                }
                switch(algValue) {
                    case -48:
                        if (document.getElementById('param-mldsa44')) document.getElementById('param-mldsa44').checked = true;
                        break;
                    case -49:
                        if (document.getElementById('param-mldsa65')) document.getElementById('param-mldsa65').checked = true;
                        break;
                    case -50:
                        if (document.getElementById('param-mldsa87')) document.getElementById('param-mldsa87').checked = true;
                        break;
                    case -8:
                        document.getElementById('param-eddsa').checked = true;
                        break;
                    case -7:
                        document.getElementById('param-es256').checked = true;
                        break;
                    case -257:
                        document.getElementById('param-rs256').checked = true;
                        break;
                    case -35:
                        document.getElementById('param-es384').checked = true;
                        break;
                    case -36:
                        document.getElementById('param-es512').checked = true;
                        break;
                    case -47:
                        document.getElementById('param-es256k').checked = true;
                        break;
                    case -9:
                        document.getElementById('param-esp256').checked = true;
                        break;
                    case -51:
                        document.getElementById('param-esp384').checked = true;
                        break;
                    case -52:
                        document.getElementById('param-esp512').checked = true;
                        break;
                    case -37:
                        document.getElementById('param-ps256').checked = true;
                        break;
                    case -38:
                        document.getElementById('param-ps384').checked = true;
                        break;
                    case -39:
                        document.getElementById('param-ps512').checked = true;
                        break;
                    case -53:
                        document.getElementById('param-ed448').checked = true;
                        break;
                    case -258:
                        document.getElementById('param-rs384').checked = true;
                        break;
                    case -259:
                        document.getElementById('param-rs512').checked = true;
                        break;
                    case -65535:
                        document.getElementById('param-rs1').checked = true;
                        break;
                }
            }
        });
    }

    if (publicKey.authenticatorSelection) {
        const attachmentElement = document.getElementById('authenticator-attachment');
        if (attachmentElement) {
            const attachmentValue = publicKey.authenticatorSelection.authenticatorAttachment;
            let normalizedAttachment = 'cross-platform';
            if (attachmentValue === 'platform' || attachmentValue === 'cross-platform') {
                normalizedAttachment = attachmentValue;
            } else if (attachmentValue === 'unspecified') {
                normalizedAttachment = 'unspecified';
            }
            attachmentElement.value = normalizedAttachment;
            try {
                attachmentElement.dispatchEvent(new Event('change', { bubbles: true }));
            } catch (error) {
                const changeEvent = document.createEvent('Event');
                changeEvent.initEvent('change', true, true);
                attachmentElement.dispatchEvent(changeEvent);
            }
        }
        const residentKeyElement = document.getElementById('resident-key');
        if (residentKeyElement) {
            let residentKeySetting = publicKey.authenticatorSelection.residentKey || 'discouraged';
            if (publicKey.authenticatorSelection.requireResidentKey === true) {
                residentKeySetting = 'required';
            }
            residentKeyElement.value = residentKeySetting;
        }
        if (Object.prototype.hasOwnProperty.call(publicKey.authenticatorSelection, 'userVerification')) {
            const userVerificationValue = publicKey.authenticatorSelection.userVerification || 'preferred';
            document.getElementById('user-verification-reg').value = userVerificationValue;
        }
    } else {
        const attachmentElement = document.getElementById('authenticator-attachment');
        if (attachmentElement) {
            attachmentElement.value = 'cross-platform';
            try {
                attachmentElement.dispatchEvent(new Event('change', { bubbles: true }));
            } catch (error) {
                const changeEvent = document.createEvent('Event');
                changeEvent.initEvent('change', true, true);
                attachmentElement.dispatchEvent(changeEvent);
            }
        }
    }

    const excludeCredentialsCheckbox = document.getElementById('exclude-credentials');
    if (excludeCredentialsCheckbox) {
        const excludeArray = Array.isArray(publicKey.excludeCredentials)
            ? publicKey.excludeCredentials
            : [];
        excludeCredentialsCheckbox.checked = excludeArray.length > 0;

        const storedIds = new Set(
            (state.storedCredentials || [])
                .map(cred => (cred.credentialIdHex || getCredentialIdHex(cred) || '').toLowerCase())
                .filter(Boolean)
        );

        const fakeHexList = [];
        excludeArray.forEach(entry => {
            if (!entry || typeof entry !== 'object') {
                return;
            }
            const hexValue = extractHexFromJsonFormat(entry.id);
            if (!hexValue) {
                return;
            }
            const normalised = hexValue.toLowerCase();
            if (!storedIds.has(normalised)) {
                fakeHexList.push(hexValue);
            }
        });

        setFakeExcludeCredentials(fakeHexList);
    }

    if (publicKey.extensions) {
        const credPropsCheckbox = document.getElementById('cred-props');
        if (credPropsCheckbox) {
            credPropsCheckbox.checked = !!publicKey.extensions.credProps;
        }

        const minPinLengthCheckbox = document.getElementById('min-pin-length');
        if (minPinLengthCheckbox) {
            minPinLengthCheckbox.checked = !!publicKey.extensions.minPinLength;
        }

        const credProtectSelect = document.getElementById('cred-protect');
        const enforceCredProtectCheckbox = document.getElementById('enforce-cred-protect');
        if (credProtectSelect && enforceCredProtectCheckbox) {
            const policy = publicKey.extensions.credentialProtectionPolicy || '';
            credProtectSelect.value = policy;
            if (policy) {
                enforceCredProtectCheckbox.disabled = false;
                enforceCredProtectCheckbox.checked = !!publicKey.extensions.enforceCredentialProtectionPolicy;
            } else {
                enforceCredProtectCheckbox.checked = true;
                enforceCredProtectCheckbox.disabled = true;
            }
        }

        if (publicKey.extensions.prf && publicKey.extensions.prf.eval) {
            if (publicKey.extensions.prf.eval.first) {
                let prfFirstValue = '';
                if (publicKey.extensions.prf.eval.first.$base64) {
                    prfFirstValue = base64UrlToHex(publicKey.extensions.prf.eval.first.$base64);
                } else if (publicKey.extensions.prf.eval.first.$base64url) {
                    prfFirstValue = base64UrlToHex(publicKey.extensions.prf.eval.first.$base64url);
                } else if (publicKey.extensions.prf.eval.first.$hex) {
                    prfFirstValue = publicKey.extensions.prf.eval.first.$hex;
                } else if (typeof publicKey.extensions.prf.eval.first === 'string') {
                    prfFirstValue = base64UrlToHex(publicKey.extensions.prf.eval.first);
                }
                if (prfFirstValue) {
                    document.getElementById('prf-eval-first-reg').value = prfFirstValue;
                }
            }
            if (publicKey.extensions.prf.eval.second) {
                let prfSecondValue = '';
                if (publicKey.extensions.prf.eval.second.$base64) {
                    prfSecondValue = base64UrlToHex(publicKey.extensions.prf.eval.second.$base64);
                } else if (publicKey.extensions.prf.eval.second.$base64url) {
                    prfSecondValue = base64UrlToHex(publicKey.extensions.prf.eval.second.$base64url);
                } else if (publicKey.extensions.prf.eval.second.$hex) {
                    prfSecondValue = publicKey.extensions.prf.eval.second.$hex;
                } else if (typeof publicKey.extensions.prf.eval.second === 'string') {
                    prfSecondValue = base64UrlToHex(publicKey.extensions.prf.eval.second);
                }
                if (prfSecondValue) {
                    document.getElementById('prf-eval-second-reg').value = prfSecondValue;
                }
            }
        }
    } else {
        const credPropsCheckbox = document.getElementById('cred-props');
        if (credPropsCheckbox) {
            credPropsCheckbox.checked = false;
        }

        const minPinLengthCheckbox = document.getElementById('min-pin-length');
        if (minPinLengthCheckbox) {
            minPinLengthCheckbox.checked = false;
        }

        const credProtectSelect = document.getElementById('cred-protect');
        const enforceCredProtectCheckbox = document.getElementById('enforce-cred-protect');
        if (credProtectSelect && enforceCredProtectCheckbox) {
            credProtectSelect.value = '';
            enforceCredProtectCheckbox.checked = true;
            enforceCredProtectCheckbox.disabled = true;
        }
    }

    if (Array.isArray(publicKey.hints)) {
        applyHintsToCheckboxes(publicKey.hints, 'registration');
    } else {
        applyHintsToCheckboxes([], 'registration');
    }
}

export function updateAuthenticationFormFromJson(publicKey) {
    if (publicKey.challenge) {
        let challengeValue = '';
        if (publicKey.challenge.$base64) {
            challengeValue = base64UrlToHex(publicKey.challenge.$base64);
        } else if (publicKey.challenge.$base64url) {
            challengeValue = base64UrlToHex(publicKey.challenge.$base64url);
        } else if (publicKey.challenge.$hex) {
            challengeValue = publicKey.challenge.$hex;
        } else if (typeof publicKey.challenge === 'string') {
            challengeValue = base64UrlToHex(publicKey.challenge);
        }
        if (challengeValue) {
            document.getElementById('challenge-auth').value = challengeValue;
        }
    }

    if (publicKey.timeout) {
        document.getElementById('timeout-auth').value = publicKey.timeout.toString();
    }

    const allowCredentialsSelect = document.getElementById('allow-credentials');
    if (allowCredentialsSelect) {
        let desiredValue = 'all';

        if (!Object.prototype.hasOwnProperty.call(publicKey, 'allowCredentials')) {
            desiredValue = 'empty';
        } else if (Array.isArray(publicKey.allowCredentials)) {
            if (publicKey.allowCredentials.length === 0) {
                desiredValue = 'empty';
            } else if (publicKey.allowCredentials.length === 1) {
                const descriptor = publicKey.allowCredentials[0];
                if (descriptor && typeof descriptor === 'object') {
                    const extractedHex = extractHexFromJsonFormat(descriptor.id);
                    if (extractedHex) {
                        const hasOption = Array.from(allowCredentialsSelect.options)
                            .some(option => option.value === extractedHex);
                        if (hasOption) {
                            desiredValue = extractedHex;
                        }
                    }
                }
            }
        }

        if (desiredValue !== 'all' && desiredValue !== 'empty') {
            const available = Array.from(allowCredentialsSelect.options)
                .some(option => option.value === desiredValue);
            if (!available) {
                desiredValue = 'all';
            }
        }

        if (allowCredentialsSelect.value !== desiredValue) {
            allowCredentialsSelect.value = desiredValue;
            try {
                allowCredentialsSelect.dispatchEvent(new Event('change', { bubbles: true }));
            } catch (error) {
                const changeEvent = document.createEvent('Event');
                changeEvent.initEvent('change', true, true);
                allowCredentialsSelect.dispatchEvent(changeEvent);
            }
        }
    }

    if (Object.prototype.hasOwnProperty.call(publicKey, 'userVerification')) {
        document.getElementById('user-verification-auth').value = publicKey.userVerification || 'preferred';
    }

    if (publicKey.extensions) {
        if (publicKey.extensions.prf && publicKey.extensions.prf.eval) {
            if (publicKey.extensions.prf.eval.first) {
                let prfFirstValue = '';
                if (publicKey.extensions.prf.eval.first.$base64) {
                    prfFirstValue = base64UrlToHex(publicKey.extensions.prf.eval.first.$base64);
                } else if (publicKey.extensions.prf.eval.first.$base64url) {
                    prfFirstValue = base64UrlToHex(publicKey.extensions.prf.eval.first.$base64url);
                } else if (publicKey.extensions.prf.eval.first.$hex) {
                    prfFirstValue = publicKey.extensions.prf.eval.first.$hex;
                } else if (typeof publicKey.extensions.prf.eval.first === 'string') {
                    prfFirstValue = base64UrlToHex(publicKey.extensions.prf.eval.first);
                }
                if (prfFirstValue) {
                    document.getElementById('prf-eval-first-auth').value = prfFirstValue;
                }
            }
            if (publicKey.extensions.prf.eval.second) {
                let prfSecondValue = '';
                if (publicKey.extensions.prf.eval.second.$base64) {
                    prfSecondValue = base64UrlToHex(publicKey.extensions.prf.eval.second.$base64);
                } else if (publicKey.extensions.prf.eval.second.$base64url) {
                    prfSecondValue = base64UrlToHex(publicKey.extensions.prf.eval.second.$base64url);
                } else if (publicKey.extensions.prf.eval.second.$hex) {
                    prfSecondValue = publicKey.extensions.prf.eval.second.$hex;
                } else if (typeof publicKey.extensions.prf.eval.second === 'string') {
                    prfSecondValue = base64UrlToHex(publicKey.extensions.prf.eval.second);
                }
                if (prfSecondValue) {
                    document.getElementById('prf-eval-second-auth').value = prfSecondValue;
                }
            }
        }

        if (publicKey.extensions.largeBlob) {
            if (publicKey.extensions.largeBlob.read) {
                document.getElementById('large-blob-auth').value = 'read';
            } else if (publicKey.extensions.largeBlob.write) {
                document.getElementById('large-blob-auth').value = 'write';
                let largeBlobValue = '';
                if (publicKey.extensions.largeBlob.write.$base64) {
                    largeBlobValue = base64UrlToHex(publicKey.extensions.largeBlob.write.$base64);
                } else if (publicKey.extensions.largeBlob.write.$base64url) {
                    largeBlobValue = base64UrlToHex(publicKey.extensions.largeBlob.write.$base64url);
                } else if (publicKey.extensions.largeBlob.write.$hex) {
                    largeBlobValue = publicKey.extensions.largeBlob.write.$hex;
                } else if (typeof publicKey.extensions.largeBlob.write === 'string') {
                    largeBlobValue = base64UrlToHex(publicKey.extensions.largeBlob.write);
                }
                if (largeBlobValue) {
                    document.getElementById('large-blob-write').value = largeBlobValue;
                }
            }
        }
    } else {
        const credPropsCheckbox = document.getElementById('cred-props');
        if (credPropsCheckbox) {
            credPropsCheckbox.checked = false;
        }

        const minPinLengthCheckbox = document.getElementById('min-pin-length');
        if (minPinLengthCheckbox) {
            minPinLengthCheckbox.checked = false;
        }

        const credProtectSelect = document.getElementById('cred-protect');
        const enforceCredProtectCheckbox = document.getElementById('enforce-cred-protect');
        if (credProtectSelect && enforceCredProtectCheckbox) {
            credProtectSelect.value = '';
            enforceCredProtectCheckbox.checked = true;
            enforceCredProtectCheckbox.disabled = true;
        }
    }

    if (Array.isArray(publicKey.hints)) {
        applyHintsToCheckboxes(publicKey.hints, 'authentication');
    }
}

export function getAdvancedCreateOptions() {
    const currentFormat = getCurrentBinaryFormat();

    const options = {
        username: document.getElementById('user-name').value,
        displayName: document.getElementById('user-display-name').value || document.getElementById('user-name').value,
        userId: convertFormat(document.getElementById('user-id').value, currentFormat, 'hex'),

        attestation: document.getElementById('attestation').value,
        userVerification: document.getElementById('user-verification-reg').value,
        residentKey: document.getElementById('resident-key').value,
        authenticatorAttachment: document.getElementById('authenticator-attachment').value || 'cross-platform',

        excludeCredentials: document.getElementById('exclude-credentials').checked,
        fakeCredLength: parseInt(document.getElementById('fake-cred-length-reg').value) || 0,

        challenge: convertFormat(document.getElementById('challenge-reg').value, currentFormat, 'hex'),
        timeout: parseInt(document.getElementById('timeout-reg').value) || 90000,

        pubKeyCredParams: [],
        hints: [],
        extensions: {}
    };

    if (document.getElementById('param-mldsa44')?.checked) options.pubKeyCredParams.push('ML-DSA-44');
    if (document.getElementById('param-mldsa65')?.checked) options.pubKeyCredParams.push('ML-DSA-65');
    if (document.getElementById('param-mldsa87')?.checked) options.pubKeyCredParams.push('ML-DSA-87');
    if (document.getElementById('param-eddsa')?.checked) options.pubKeyCredParams.push('EdDSA');
    if (document.getElementById('param-es256')?.checked) options.pubKeyCredParams.push('ES256');
    if (document.getElementById('param-rs256')?.checked) options.pubKeyCredParams.push('RS256');
    if (document.getElementById('param-es384')?.checked) options.pubKeyCredParams.push('ES384');
    if (document.getElementById('param-es512')?.checked) options.pubKeyCredParams.push('ES512');
    if (document.getElementById('param-rs384')?.checked) options.pubKeyCredParams.push('RS384');
    if (document.getElementById('param-rs512')?.checked) options.pubKeyCredParams.push('RS512');
    if (document.getElementById('param-rs1')?.checked) options.pubKeyCredParams.push('RS1');
    if (document.getElementById('param-es256k')?.checked) options.pubKeyCredParams.push('ES256K');
    if (document.getElementById('param-esp256')?.checked) options.pubKeyCredParams.push('ESP256');
    if (document.getElementById('param-esp384')?.checked) options.pubKeyCredParams.push('ESP384');
    if (document.getElementById('param-esp512')?.checked) options.pubKeyCredParams.push('ESP512');
    if (document.getElementById('param-ps256')?.checked) options.pubKeyCredParams.push('PS256');
    if (document.getElementById('param-ps384')?.checked) options.pubKeyCredParams.push('PS384');
    if (document.getElementById('param-ps512')?.checked) options.pubKeyCredParams.push('PS512');
    if (document.getElementById('param-ed448')?.checked) options.pubKeyCredParams.push('Ed448');

    options.hints = collectSelectedHints('registration');
    if (document.getElementById('cred-props')?.checked) {
        options.extensions.credProps = true;
    }

    if (document.getElementById('min-pin-length')?.checked) {
        options.extensions.minPinLength = true;
    }

    const credProtect = document.getElementById('cred-protect')?.value;
    if (credProtect && credProtect !== '') {
        options.extensions.credentialProtectionPolicy = credProtect;
        if (document.getElementById('enforce-cred-protect')?.checked) {
            options.extensions.enforceCredentialProtectionPolicy = true;
        }
    }

    const largeBlob = document.getElementById('large-blob-reg')?.value;
    if (largeBlob && largeBlob !== '') {
        options.extensions.largeBlob = { support: largeBlob };
    }

    if (document.getElementById('prf-reg')?.checked) {
        const prfFirst = document.getElementById('prf-eval-first-reg')?.value;
        const prfSecond = document.getElementById('prf-eval-second-reg')?.value;
        if (prfFirst) {
            options.extensions.prf = {
                eval: {
                    first: currentFormatToJsonFormat(prfFirst)
                }
            };
            if (prfSecond) {
                options.extensions.prf.eval.second = currentFormatToJsonFormat(prfSecond);
            }
        }
    }

    return options;
}

export function getAdvancedAssertOptions() {
    const allowCreds = document.getElementById('allow-credentials').value;
    const currentFormat = getCurrentBinaryFormat();

    const options = {
        userVerification: document.getElementById('user-verification-auth').value,
        allowCredentials: allowCreds,
        fakeCredLength: parseInt(document.getElementById('fake-cred-length-auth').value) || 0,
        challenge: convertFormat(document.getElementById('challenge-auth').value, currentFormat, 'hex'),
        timeout: parseInt(document.getElementById('timeout-auth').value) || 90000,
        extensions: {}
    };

    if (allowCreds !== 'all' && allowCreds !== 'empty') {
        options.specificCredentialId = allowCreds;
    }

    const largeBlob = document.getElementById('large-blob-auth')?.value;
    if (largeBlob === 'read') {
        options.extensions.largeBlob = { read: true };
    } else if (largeBlob === 'write') {
        const largeBlobWrite = document.getElementById('large-blob-write')?.value;
        if (largeBlobWrite) {
            options.extensions.largeBlob = {
                write: currentFormatToJsonFormat(largeBlobWrite)
            };
        }
    }

    const prfFirst = document.getElementById('prf-eval-first-auth')?.value;
    const prfSecond = document.getElementById('prf-eval-second-auth')?.value;
    if (prfFirst || prfSecond) {
        const prfEval = {};
        if (prfFirst) {
            prfEval.first = currentFormatToJsonFormat(prfFirst);
        }
        if (prfSecond) {
            prfEval.second = currentFormatToJsonFormat(prfSecond);
        }
        if (Object.keys(prfEval).length > 0) {
            options.extensions.prf = { eval: prfEval };
        }
    }

    options.hints = collectSelectedHints('authentication');
    return options;
}

export function editCreateOptions() {
    const options = getAdvancedCreateOptions();
    state.currentJsonMode = 'create';
    state.currentJsonData = options;

    const sortedOptions = sortObjectKeys(options);
    setJsonEditorContent(JSON.stringify(sortedOptions, null, 2));
    document.getElementById('apply-json').style.display = 'inline-block';
    document.getElementById('cancel-json').style.display = 'inline-block';
}

export function editAssertOptions() {
    const options = getAdvancedAssertOptions();
    state.currentJsonMode = 'assert';
    state.currentJsonData = options;

    const sortedOptions = sortObjectKeys(options);
    setJsonEditorContent(JSON.stringify(sortedOptions, null, 2));
    document.getElementById('apply-json').style.display = 'inline-block';
    document.getElementById('cancel-json').style.display = 'inline-block';
}

export function applyJsonChanges() {
    try {
        const jsonText = document.getElementById('json-editor').value;
        const parsed = JSON.parse(jsonText);

        if (state.currentJsonMode === 'create') {
            if (parsed.username) document.getElementById('user-name').value = parsed.username;
            if (parsed.displayName) document.getElementById('user-display-name').value = parsed.displayName;
            if (Object.prototype.hasOwnProperty.call(parsed, 'attestation')) {
                document.getElementById('attestation').value = parsed.attestation || 'direct';
            }
            if (Object.prototype.hasOwnProperty.call(parsed, 'userVerification')) {
                document.getElementById('user-verification-reg').value = parsed.userVerification || 'preferred';
            }
            if (parsed.residentKey) document.getElementById('resident-key').value = parsed.residentKey;
            if (Object.prototype.hasOwnProperty.call(parsed, 'authenticatorAttachment')) {
                const attachmentSelect = document.getElementById('authenticator-attachment');
                if (attachmentSelect) {
                    const rawValue = parsed.authenticatorAttachment;
                    const normalized = rawValue === 'platform' || rawValue === 'cross-platform' || rawValue === 'unspecified'
                        ? rawValue
                        : 'cross-platform';
                    attachmentSelect.value = normalized;
                    try {
                        attachmentSelect.dispatchEvent(new Event('change', { bubbles: true }));
                    } catch (error) {
                        const changeEvent = document.createEvent('Event');
                        changeEvent.initEvent('change', true, true);
                        attachmentSelect.dispatchEvent(changeEvent);
                    }
                }
            }
        } else if (state.currentJsonMode === 'assert') {
            if (Object.prototype.hasOwnProperty.call(parsed, 'userVerification')) {
                document.getElementById('user-verification-auth').value = parsed.userVerification || 'preferred';
            }
        }

        showStatus('advanced', 'JSON changes applied successfully!', 'success');
        cancelJsonEdit();
    } catch (error) {
        showStatus('advanced', `Invalid JSON: ${error.message}`, 'error');
    }
}

export function cancelJsonEdit() {
    setJsonEditorContent('');
    document.getElementById('apply-json').style.display = 'none';
    document.getElementById('cancel-json').style.display = 'none';
    state.currentJsonMode = null;
    state.currentJsonData = {};
}

export function updateJsonFromForm() {
    if (state.currentJsonMode) {
        if (state.currentJsonMode === 'create') {
            const options = getAdvancedCreateOptions();
            const sortedOptions = sortObjectKeys(options);
            setJsonEditorContent(JSON.stringify(sortedOptions, null, 2));
        } else if (state.currentJsonMode === 'assert') {
            const options = getAdvancedAssertOptions();
            const sortedOptions = sortObjectKeys(options);
            setJsonEditorContent(JSON.stringify(sortedOptions, null, 2));
        }
    }
}
