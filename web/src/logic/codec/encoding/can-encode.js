import { hasBinaryConvertibleValue } from './binary.js';
import { getCanonicalEncoderFormat } from './format.js';

// Whether the encoder can turn this JSON value into `format` at all: CBOR, JSON
// and COSE take any value, DER and PEM need something that holds bytes. A
// format the page does not know is left to the server.
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
