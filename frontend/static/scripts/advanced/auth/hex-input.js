// Whether a byte field's text holds enough bytes, read in the page's binary
// format (hex unless the page says otherwise): empty text is not an error; hex
// is only hex digits; base64, base64url and a Uint8Array literal are decoded.
// DOM-free: the current form (./forms.js marks its fields) and the new UI both
// use it.
import {
    base64ToHex,
    base64UrlToHexFixed,
    getCurrentBinaryFormat,
    jsToHex,
} from '../../shared/utils/binary.js';

export function hexInputIsValid(text, minBytes = 0, format = getCurrentBinaryFormat()) {
    const value = typeof text === 'string' ? text.trim() : '';
    if (!value) {
        return true;
    }

    try {
        switch (format) {
            case 'hex':
                return /^[0-9a-fA-F]+$/.test(value) && value.length >= minBytes * 2;
            case 'b64':
                return base64ToHex(value).length >= minBytes * 2;
            case 'b64u':
                return base64UrlToHexFixed(value).length >= minBytes * 2;
            case 'js':
                return jsToHex(value).length >= minBytes * 2;
            default:
                return false;
        }
    } catch (e) {
        return false;
    }
}
