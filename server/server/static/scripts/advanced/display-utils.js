import { COSE_ALGORITHM_LABELS, COSE_KEY_TYPE_LABELS } from './constants.js';

export function formatBoolean(value) {
    if (value === true) {
        return '<span style="color: #0a8754; font-weight: 600;">true</span>';
    }
    if (value === false) {
        return '<span style="color: #c62828; font-weight: 600;">false</span>';
    }
    if (typeof value === 'string') {
        const normalized = value.trim().toLowerCase();
        if (normalized === 'true') {
            return '<span style="color: #0a8754; font-weight: 600;">true</span>';
        }
        if (normalized === 'false') {
            return '<span style="color: #c62828; font-weight: 600;">false</span>';
        }
    }
    if (value === null || value === undefined) {
        return '<span style="color: #6c757d;">N/A</span>';
    }
    const safeValue = String(value)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
    return `<span style="color: #6c757d;">${safeValue}</span>`;
}

export function renderAttestationResultRow(label, value, extraHtml = '') {
    const safeLabel = String(label)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
    const extraContent = extraHtml || '';
    return `
        <div style="display: flex; align-items: center; gap: 0.5rem; margin-bottom: 0.35rem;">
            <span style="min-width: 180px;"><strong>${safeLabel}:</strong></span>
            <span>${formatBoolean(value)}${extraContent}</span>
        </div>
    `.trim();
}

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

export function escapeHtml(value) {
    if (value === undefined || value === null) {
        return '';
    }
    return String(value)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}
