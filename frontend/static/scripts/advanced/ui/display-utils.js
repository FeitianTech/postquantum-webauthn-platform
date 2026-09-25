import { COSE_ALGORITHM_LABELS, COSE_KEY_TYPE_LABELS } from '../constants.js';

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
