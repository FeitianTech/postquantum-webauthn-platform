import { SPECIAL_LABELS } from './constants.js';

// A key the decoder spelled as data, not a field name: a typed spelling such as
// "1" (text), h'01' (bytes) or true (boolean) #2, or a key in EDN such as
// [1, 2] or float'7e01'. It is shown exactly as written; the encoder reads it back.
const TYPED_KEY = /^.+ \((?:text|bytes|boolean|float|null|undefined|simple value|array|map|tag|text, not UTF-8|invalid|diagnostic notation)\)(?: #\d+)?$/s;
const EDN_KEY_START = /^(?:"|'|h'|float'|simple\(|\[|\{)/;

export function formatKey(key) {
    if (typeof key !== 'string' || key.length === 0) {
        return 'Value';
    }

    if (TYPED_KEY.test(key) || EDN_KEY_START.test(key)) {
        return key;
    }

    if (Object.prototype.hasOwnProperty.call(SPECIAL_LABELS, key)) {
        return SPECIAL_LABELS[key];
    }

    if (/^[A-Z0-9]{1,4}$/.test(key)) {
        return key;
    }

    // A leading minus before a digit is a sign, not a separator: COSE labels
    // -1, -2 and -3 are different keys from 1, 2 and 3.
    const sign = /^-\d/.test(key) ? '-' : '';
    const spaced = sign + key
        .slice(sign.length)
        .replace(/[_-]+/g, ' ')
        .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
        .trim();

    if (spaced.length === 0) {
        return 'Value';
    }

    const words = spaced.split(/\s+/).map((word) => {
        if (/^[a-z]{1,3}$/.test(word)) {
            return word.toUpperCase();
        }
        if (/^[A-Z0-9]+$/.test(word)) {
            return word;
        }
        if (/^[a-z0-9]+$/.test(word)) {
            return word.charAt(0).toUpperCase() + word.slice(1);
        }
        return word.charAt(0).toUpperCase() + word.slice(1);
    });

    return words.join(' ');
}
