import {
    assertAllowedKeys,
    assertPlainObject,
    KNOWN_ALGORITHMS,
    KNOWN_AUTH_SELECTION_KEYS,
    KNOWN_REGISTRATION_EXTENSION_KEYS,
    KNOWN_REGISTRATION_PUBLIC_KEY_KEYS,
    KNOWN_RP_KEYS,
    KNOWN_USER_KEYS,
} from '../editor/schema.js';
import {
    normalizeInteger,
    validateBinaryField,
    validateHints,
    validateLargeBlobExtension,
    validatePrfExtension,
} from '../editor/validation.js';

function validateRp(rp) {
    assertPlainObject(rp, 'publicKey.rp');
    assertAllowedKeys(rp, KNOWN_RP_KEYS, 'publicKey.rp');
    if (typeof rp.name !== 'string' || !rp.name.trim()) {
        throw new Error('publicKey.rp.name must be a non-empty string.');
    }
    if (rp.id !== undefined && typeof rp.id !== 'string') {
        throw new Error('publicKey.rp.id must be a string when provided.');
    }
}

function validateUser(user) {
    assertPlainObject(user, 'publicKey.user');
    assertAllowedKeys(user, KNOWN_USER_KEYS, 'publicKey.user');
    validateBinaryField(user.id, 'publicKey.user.id');
    if (typeof user.name !== 'string' || !user.name.trim()) {
        throw new Error('publicKey.user.name must be a non-empty string.');
    }
    if (typeof user.displayName !== 'string' || !user.displayName.trim()) {
        throw new Error('publicKey.user.displayName must be a non-empty string.');
    }
}

function validateTimeout(timeout) {
    if (timeout !== undefined) {
        const timeoutValue = normalizeInteger(timeout, 'publicKey.timeout');
        if (timeoutValue !== null && timeoutValue < 0) {
            throw new Error('publicKey.timeout must be zero or greater.');
        }
    }
}

function validatePubKeyCredParams(pubKeyCredParams) {
    if (pubKeyCredParams === undefined) {
        return;
    }
    if (!Array.isArray(pubKeyCredParams)) {
        throw new Error('publicKey.pubKeyCredParams must be an array.');
    }

    pubKeyCredParams.forEach((param, index) => {
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

function validateAuthenticatorSelection(selection) {
    if (selection === undefined) {
        return;
    }
    assertPlainObject(selection, 'publicKey.authenticatorSelection');
    assertAllowedKeys(selection, KNOWN_AUTH_SELECTION_KEYS, 'publicKey.authenticatorSelection');

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

function validateAttestation(attestation) {
    if (attestation !== undefined) {
        if (typeof attestation !== 'string' || !['none', 'indirect', 'direct', 'enterprise'].includes(attestation)) {
            throw new Error('publicKey.attestation must be none, indirect, direct, or enterprise.');
        }
    }
}

function validateExcludeCredentials(excludeCredentials) {
    if (excludeCredentials === undefined) {
        return;
    }
    if (!Array.isArray(excludeCredentials)) {
        throw new Error('publicKey.excludeCredentials must be an array.');
    }

    excludeCredentials.forEach((descriptor, index) => {
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

function validateRegistrationExtensions(extensions) {
    if (extensions === undefined) {
        return;
    }
    assertPlainObject(extensions, 'publicKey.extensions');
    assertAllowedKeys(extensions, KNOWN_REGISTRATION_EXTENSION_KEYS, 'publicKey.extensions');

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
        validateLargeBlobExtension(extensions.largeBlob, 'publicKey.extensions.largeBlob', 'registration');
    }
    if (extensions.prf !== undefined) {
        validatePrfExtension(extensions.prf, 'publicKey.extensions.prf');
    }
}

/**
 * Throws the first thing a registration's publicKey gets wrong, in this order:
 * its keys, rp, user, challenge, timeout, pubKeyCredParams,
 * authenticatorSelection, attestation, excludeCredentials, extensions, hints.
 * @param {any} publicKey
 */
export function validateRegistrationPublicKey(publicKey) {
    assertPlainObject(publicKey, 'publicKey');
    assertAllowedKeys(publicKey, KNOWN_REGISTRATION_PUBLIC_KEY_KEYS, 'publicKey');
    validateRp(publicKey.rp);
    validateUser(publicKey.user);
    validateBinaryField(publicKey.challenge, 'publicKey.challenge');
    validateTimeout(publicKey.timeout);
    validatePubKeyCredParams(publicKey.pubKeyCredParams);
    validateAuthenticatorSelection(publicKey.authenticatorSelection);
    validateAttestation(publicKey.attestation);
    validateExcludeCredentials(publicKey.excludeCredentials);
    validateRegistrationExtensions(publicKey.extensions);
    validateHints(publicKey.hints, 'publicKey.hints');
}
