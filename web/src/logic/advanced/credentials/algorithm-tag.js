// A credential's algorithm: its COSE identifier, and how a card names it
// ("ES256", "MLDSA65"). DOM-free. How an algorithm is described is passed in
// (the callers give the one in ../cose-labels.js).

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

/** The credential's algorithm described, as describeCoseAlgorithm(alg) says it. */
export function describeCredentialAlgorithmWith(credential, describeCoseAlgorithm) {
    const identifier = resolveCredentialAlgorithmIdentifier(credential);
    if (identifier !== null) {
        return describeCoseAlgorithm(identifier);
    }
    const fallback = credential?.publicKeyAlgorithm ?? credential?.algorithm;
    return describeCoseAlgorithm(fallback);
}

/** The algorithm's tag on a card: a known one's short name, else from its description. */
export function describeCredentialAlgorithmTagWith(credential, describeCoseAlgorithm) {
    const identifier = resolveCredentialAlgorithmIdentifier(credential);
    if (identifier !== null && identifier !== undefined) {
        const key = String(identifier);
        if (Object.prototype.hasOwnProperty.call(COSE_ALGORITHM_TAG_LABELS, key)) {
            return COSE_ALGORITHM_TAG_LABELS[key];
        }
    }

    const description = describeCredentialAlgorithmWith(credential, describeCoseAlgorithm);
    // The COSE labels' own word for an identifier they do not know, "Algorithm
    // (-46)", names nothing: such an algorithm is tagged by its identifier, as the
    // server names it ("COSE alg -46").
    const unnamed = identifier !== null && description === `Algorithm (${identifier})`;
    if (!unnamed && typeof description === 'string' && description.trim()) {
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

    // A finite number: its text has a digit.
    if (identifier !== null && identifier !== undefined) {
        return `COSE${String(identifier).replace(/[^0-9a-z-]/gi, '')}`.toUpperCase();
    }

    return 'Unknown';
}
