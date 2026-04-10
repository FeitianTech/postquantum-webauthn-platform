import {describeCoseAlgorithm} from '../ui/display-utils.js';

const COSE_ALGORITHM_TAG_LABELS = {
    '-53': 'ED448',
    '-52': 'ESP512',
    '-51': 'ESP384',
    '-50': 'MLDSA87',
    '-49': 'MLDSA65',
    '-48': 'MLDSA44',
    '-47': 'ES256K',
    '-39': 'PS512',
    '-38': 'PS384',
    '-37': 'PS256',
    '-19': 'ED25519',
    '-9': 'ESP256',
    '-8': 'EDDSA',
    '-7': 'ES256',
    '-36': 'ES512',
    '-35': 'ES384',
    '-259': 'RS512',
    '-258': 'RS384',
    '-257': 'RS256',
    '-65535': 'RS1'
};

function normaliseAlgorithmIdentifier(value) {
    if (value === null || value === undefined) {
        return null;
    }

    if (typeof value === 'number' && Number.isFinite(value)) {
        return value;
    }

    if (typeof value === 'string') {
        const trimmed = value.trim();
        if (!trimmed) {
            return null;
        }

        const direct = Number.parseInt(trimmed, 10);
        if (!Number.isNaN(direct) && Number.isFinite(direct)) {
            return direct;
        }

        const matches = trimmed.match(/-?\d+/g);
        if (matches && matches.length) {
            for (let i = matches.length - 1; i >= 0; i -= 1) {
                const candidate = Number.parseInt(matches[i], 10);
                if (!Number.isNaN(candidate) && Number.isFinite(candidate)) {
                    return candidate;
                }
            }
        }
    }

    return null;
}

export function resolveCredentialAlgorithmIdentifier(credential) {
    if (!credential || typeof credential !== 'object') {
        return null;
    }

    const candidates = [
        credential.publicKeyAlgorithm,
        credential.algorithm,
        credential.coseAlgorithm,
        credential.cose_alg,
    ];

    for (const candidate of candidates) {
        const normalized = normaliseAlgorithmIdentifier(candidate);
        if (normalized !== null) {
            return normalized;
        }
    }

    const coseMap = credential.publicKeyCose;
    if (coseMap && typeof coseMap === 'object') {
        const raw = coseMap[3] ?? coseMap['3'];
        const normalized = normaliseAlgorithmIdentifier(raw);
        if (normalized !== null) {
            return normalized;
        }
    }

    return null;
}

export function describeCredentialAlgorithm(credential) {
    const identifier = resolveCredentialAlgorithmIdentifier(credential);
    if (identifier !== null) {
        return describeCoseAlgorithm(identifier);
    }
    const fallback = credential?.publicKeyAlgorithm ?? credential?.algorithm;
    return describeCoseAlgorithm(fallback);
}

export function describeCredentialAlgorithmTag(credential) {
    const identifier = resolveCredentialAlgorithmIdentifier(credential);
    if (identifier !== null && identifier !== undefined) {
        const key = String(identifier);
        if (Object.prototype.hasOwnProperty.call(COSE_ALGORITHM_TAG_LABELS, key)) {
            return COSE_ALGORITHM_TAG_LABELS[key];
        }
    }

    const description = describeCredentialAlgorithm(credential);
    if (typeof description === 'string' && description.trim()) {
        const prefix = description.split('(')[0].trim();
        if (prefix) {
            const normalized = prefix.replace(/[^0-9a-z]+/gi, '');
            if (normalized) {
                if (normalized.toLowerCase() === 'unknown') {
                    return 'Unknown';
                }
                return normalized.toUpperCase();
            }
        }
    }

    if (identifier !== null && identifier !== undefined) {
        const identifierText = String(identifier).replace(/[^0-9a-z-]/gi, '');
        if (identifierText) {
            return `COSE${identifierText}`.toUpperCase();
        }
    }

    return 'Unknown';
}
