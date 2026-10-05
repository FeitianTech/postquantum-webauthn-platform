import {cloneJson} from '../../shared/json.js';

const CERTIFICATE_COLLECTION_KEYS = [
    'attestationCertificate',
    'attestationCertificates',
];

export function stripCertificateCollections(target) {
    CERTIFICATE_COLLECTION_KEYS.forEach(key => {
        if (Object.hasOwn(target, key)) {
            delete target[key];
        }
    });

    Object.keys(target).forEach(key => {
        const value = target[key];
        if (value && typeof value === 'object') {
            stripCertificateCollections(value);
        }
    });
}

export function removeKeysFromObject(target, keys) {
    if (!target || typeof target !== 'object' || !Array.isArray(keys) || !keys.length) {
        return;
    }

    const process = value => {
        if (value && typeof value === 'object') {
            removeKeysFromObject(value, keys);
        }
    };

    if (Array.isArray(target)) {
        target.forEach(process);
        return;
    }

    keys.forEach(key => {
        if (Object.hasOwn(target, key)) {
            delete target[key];
        }
    });

    Object.values(target).forEach(process);
}

export function removeKeysCaseInsensitive(target, keys) {
    if (!target || typeof target !== 'object' || !Array.isArray(keys) || !keys.length) {
        return;
    }

    const lowerKeys = keys.map(key => String(key).toLowerCase());

    const handleValue = value => {
        if (value && typeof value === 'object') {
            removeKeysCaseInsensitive(value, keys);
        }
    };

    if (Array.isArray(target)) {
        target.forEach(handleValue);
        return;
    }

    Object.keys(target).forEach(key => {
        const value = target[key];
        if (lowerKeys.includes(String(key).toLowerCase())) {
            delete target[key];
            return;
        }
        handleValue(value);
    });
}

export function sanitiseRegistrationData(raw) {
    if (!raw || typeof raw !== 'object') {
        return null;
    }

    const cloned = cloneJson(raw);

    const keysToRemove = [
        'attestationObject',
        'attestationStatement',
        'attStmt',
        'rawAuthenticatorData',
        'rawClientDataJSON',
    ];

    removeKeysCaseInsensitive(cloned, keysToRemove);
    stripCertificateCollections(cloned);
    stripSignatureFormatting(cloned);

    return cloned;
}

export function sanitizeParsedCertificateDetails(parsed) {
    if (!parsed || typeof parsed !== 'object') {
        return null;
    }

    const parsedCopy = cloneJson(parsed);

    ['pem', 'der', 'derBase64', 'raw', 'summary', 'error'].forEach(key => {
        if (Object.hasOwn(parsedCopy, key)) {
            delete parsedCopy[key];
        }
    });

    if (Array.isArray(parsedCopy.extensions)) {
        parsedCopy.extensions = parsedCopy.extensions
            .map(ext => {
                if (!ext || typeof ext !== 'object') {
                    return null;
                }

                // Already a copy (parsedCopy is one).
                ['raw', 'hex', 'rawHex', 'der', 'derBase64', 'valueHex'].forEach(key => {
                    if (Object.hasOwn(ext, key)) {
                        delete ext[key];
                    }
                });

                return ext;
            })
            .filter(Boolean);
    }

    return parsedCopy;
}

export function stripSignatureFormatting(target) {
    const process = value => {
        if (value && typeof value === 'object') {
            stripSignatureFormatting(value);
        }
    };

    if (Array.isArray(target)) {
        target.forEach(process);
        return;
    }

    Object.keys(target).forEach(key => {
        const value = target[key];
        if ((key === 'signature' || key === 'sig') && value && typeof value === 'object') {
            if (Object.hasOwn(value, 'colon')) {
                delete value.colon;
            }
            if (Object.hasOwn(value, 'lines')) {
                delete value.lines;
            }
        }
        process(value);
    });
}
