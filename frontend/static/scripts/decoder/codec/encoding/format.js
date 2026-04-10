import { ENCODER_FORMAT_ALIASES } from '../constants.js';

function normalizeEncoderFormat(format) {
    if (typeof format !== 'string') {
        return '';
    }

    return format.trim().toLowerCase();
}

export function getCanonicalEncoderFormat(format) {
    const normalized = normalizeEncoderFormat(format);
    if (!normalized) {
        return '';
    }

    return ENCODER_FORMAT_ALIASES.get(normalized) || normalized;
}
