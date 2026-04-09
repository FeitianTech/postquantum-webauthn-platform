import { extractHexFromJsonFormat } from '../credential-utils.js';
import {
    assertAllowedKeys,
    assertPlainObject,
    KNOWN_HINT_VALUES,
    KNOWN_LARGE_BLOB_AUTH_KEYS,
    KNOWN_LARGE_BLOB_REG_KEYS,
    KNOWN_PRF_EVAL_KEYS,
    KNOWN_PRF_KEYS,
} from './schema.js';

export function validateBinaryField(value, path, { allowEmpty = false } = {}) {
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

export function normalizeInteger(value, path) {
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

export function validateHints(hints, path) {
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

export function validatePrfExtension(prf, path) {
    assertPlainObject(prf, path);
    assertAllowedKeys(prf, KNOWN_PRF_KEYS, path);

    if (prf.eval !== undefined) {
        assertPlainObject(prf.eval, `${path}.eval`);
        assertAllowedKeys(prf.eval, KNOWN_PRF_EVAL_KEYS, `${path}.eval`);

        if (prf.eval.first !== undefined) {
            validateBinaryField(prf.eval.first, `${path}.eval.first`);
        }
        if (prf.eval.second !== undefined) {
            validateBinaryField(prf.eval.second, `${path}.eval.second`);
        }
    }
}

export function validateLargeBlobExtension(largeBlob, path, scope) {
    assertPlainObject(largeBlob, path);

    if (scope === 'authentication') {
        assertAllowedKeys(largeBlob, KNOWN_LARGE_BLOB_AUTH_KEYS, path);
        if (largeBlob.read !== undefined && typeof largeBlob.read !== 'boolean') {
            throw new Error('publicKey.extensions.largeBlob.read must be a boolean.');
        }
        if (largeBlob.write !== undefined) {
            validateBinaryField(largeBlob.write, 'publicKey.extensions.largeBlob.write');
        }
        return;
    }

    assertAllowedKeys(largeBlob, KNOWN_LARGE_BLOB_REG_KEYS, path);
    if (largeBlob.support !== undefined) {
        if (typeof largeBlob.support !== 'string' || !['preferred', 'required'].includes(largeBlob.support)) {
            throw new Error('publicKey.extensions.largeBlob.support must be preferred or required.');
        }
    }
}
