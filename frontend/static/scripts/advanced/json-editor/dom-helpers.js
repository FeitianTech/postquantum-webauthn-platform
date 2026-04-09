import { base64UrlToHex } from '../../shared/binary-utils.js';

export function decodeJsonBinaryToHex(value) {
    if (!value) {
        return '';
    }

    if (value.$base64) {
        return base64UrlToHex(value.$base64);
    }
    if (value.$base64url) {
        return base64UrlToHex(value.$base64url);
    }
    if (value.$hex) {
        return value.$hex;
    }
    if (typeof value === 'string') {
        return base64UrlToHex(value);
    }

    return '';
}

export function dispatchChangeEvent(element) {
    try {
        element.dispatchEvent(new Event('change', { bubbles: true }));
    } catch (error) {
        const changeEvent = document.createEvent('Event');
        changeEvent.initEvent('change', true, true);
        element.dispatchEvent(changeEvent);
    }
}
