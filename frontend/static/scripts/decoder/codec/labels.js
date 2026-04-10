import { SPECIAL_LABELS } from './constants.js';

export function formatKey(key) {
    if (typeof key !== 'string' || key.length === 0) {
        return 'Value';
    }

    if (Object.prototype.hasOwnProperty.call(SPECIAL_LABELS, key)) {
        return SPECIAL_LABELS[key];
    }

    if (/^[A-Z0-9]{1,4}$/.test(key)) {
        return key;
    }

    const spaced = key
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
