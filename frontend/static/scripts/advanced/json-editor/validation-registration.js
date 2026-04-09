import {
    assertAllowedKeys,
    assertPlainObject,
    KNOWN_ALGORITHMS,
    KNOWN_AUTH_SELECTION_KEYS,
    KNOWN_REGISTRATION_EXTENSION_KEYS,
    KNOWN_REGISTRATION_PUBLIC_KEY_KEYS,
    KNOWN_RP_KEYS,
    KNOWN_USER_KEYS,
} from './schema.js';
import {
    normalizeInteger,
    validateBinaryField,
    validateHints,
    validateLargeBlobExtension,
    validatePrfExtension,
} from './validation-common.js';

export function validateRegistrationPublicKey(publicKey) {
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
            validateLargeBlobExtension(extensions.largeBlob, 'publicKey.extensions.largeBlob', 'registration');
        }
        if (extensions.prf !== undefined) {
            validatePrfExtension(extensions.prf, 'publicKey.extensions.prf');
        }
    }

    validateHints(publicKey.hints, 'publicKey.hints');
}
