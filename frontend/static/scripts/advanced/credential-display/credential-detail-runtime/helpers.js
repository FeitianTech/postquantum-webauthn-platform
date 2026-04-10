export function pickFirstString(...candidates) {
    for (const candidate of candidates) {
        if (typeof candidate !== 'string') {
            continue;
        }
        const trimmed = candidate.trim();
        if (trimmed) {
            return trimmed;
        }
    }
    return '';
}

export function pickFirstObject(...candidates) {
    for (const candidate of candidates) {
        if (candidate && typeof candidate === 'object') {
            return candidate;
        }
    }
    return null;
}

export function combineRegistrationHtmlSections(html, attestationSectionHtml, combinedHtml) {
    const normalizedCombinedHtml = typeof combinedHtml === 'string' ? combinedHtml : '';
    if (normalizedCombinedHtml) {
        return normalizedCombinedHtml;
    }

    const normalizedHtml = typeof html === 'string' ? html : '';
    const normalizedAttestationHtml = typeof attestationSectionHtml === 'string'
        ? attestationSectionHtml
        : '';

    return [normalizedHtml, normalizedAttestationHtml].filter(Boolean).join('');
}
