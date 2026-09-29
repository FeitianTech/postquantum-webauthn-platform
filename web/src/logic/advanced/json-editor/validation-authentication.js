import {
    assertAllowedKeys,
    assertPlainObject,
    KNOWN_AUTHENTICATION_EXTENSION_KEYS,
    KNOWN_AUTHENTICATION_PUBLIC_KEY_KEYS,
} from './schema.js';
import {
    normalizeInteger,
    validateBinaryField,
    validateHints,
    validateLargeBlobExtension,
    validatePrfExtension,
} from './validation-common.js';

export function validateAuthenticationPublicKey(publicKey) {
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
            validateLargeBlobExtension(extensions.largeBlob, 'publicKey.extensions.largeBlob', 'authentication');
        }
        if (extensions.prf !== undefined) {
            validatePrfExtension(extensions.prf, 'publicKey.extensions.prf');
        }
    }

    validateHints(publicKey.hints, 'publicKey.hints');
}
