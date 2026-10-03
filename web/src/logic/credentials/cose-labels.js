// How a COSE algorithm and key type are named: "ES256 (-7)", "EC2 (2)", and an
// ML-DSA algorithm's parameter set. DOM-free.
export const COSE_ALGORITHM_LABELS = {
    '-53': 'Ed448 (-53)',
    '-52': 'ESP512 (-52)',
    '-51': 'ESP384 (-51)',
    '-50': 'ML-DSA-87 (PQC) (-50)',
    '-49': 'ML-DSA-65 (PQC) (-49)',
    '-48': 'ML-DSA-44 (PQC) (-48)',
    '-47': 'ES256K (-47)',
    '-39': 'PS512 (-39)',
    '-38': 'PS384 (-38)',
    '-37': 'PS256 (-37)',
    '-8': 'EdDSA (-8)',
    '-9': 'ESP256 (-9)',
    '-7': 'ES256 (-7)',
    '-35': 'ES384 (-35)',
    '-36': 'ES512 (-36)',
    '-19': 'Ed25519 (-19)',
    '-257': 'RS256 (-257)',
    '-258': 'RS384 (-258)',
    '-259': 'RS512 (-259)',
    '-65535': 'RS1 (-65535)'
};


const COSE_KEY_TYPE_LABELS = {
    '1': 'OKP (1)',
    '2': 'EC2 (2)',
    '3': 'RSA (3)',
    '4': 'Symmetric (4)',
    '5': 'HSS-LMS (5)',
    '6': 'WalnutDSA (6)',
    '7': 'AKP (7)'
};

export function describeCoseAlgorithm(alg) {
    if (alg === null || alg === undefined || (typeof alg === 'number' && Number.isNaN(alg))) {
        return 'Unknown';
    }
    const key = String(alg);
    return COSE_ALGORITHM_LABELS[key] || `Algorithm (${alg})`;
}

export function describeCoseKeyType(keyType) {
    if (keyType === null || keyType === undefined || (typeof keyType === 'number' && Number.isNaN(keyType))) {
        return 'Unknown';
    }
    const key = String(keyType);
    return COSE_KEY_TYPE_LABELS[key] || `${keyType}`;
}

export function describeMldsaParameterSet(alg) {
    if (alg === -50 || alg === '-50') {
        return 'ML-DSA-87';
    }
    if (alg === -48 || alg === '-48') {
        return 'ML-DSA-44';
    }
    if (alg === -49 || alg === '-49') {
        return 'ML-DSA-65';
    }
    return '';
}
