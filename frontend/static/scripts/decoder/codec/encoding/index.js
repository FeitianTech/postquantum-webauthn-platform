import { hasBinaryConvertibleValue } from './binary.js';
import { getCanonicalEncoderFormat } from './format.js';

export { createEncodedFormatElements } from './format-elements.js';
export { findEncodedSummary } from './summary.js';

export function canEncodeToFormat(parsedValue, format) {
    const canonical = getCanonicalEncoderFormat(format);
    if (!canonical) {
        return true;
    }

    if (canonical === 'cbor' || canonical === 'json' || canonical === 'cose') {
        return parsedValue !== undefined;
    }

    if (canonical === 'der' || canonical === 'pem') {
        return hasBinaryConvertibleValue(parsedValue);
    }

    return true;
}
