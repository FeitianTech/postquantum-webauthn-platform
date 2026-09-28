// The byte values a request holds are read by ./registration-request.js.
export { decodeJsonBinaryToHex } from './registration-request.js';

export function dispatchChangeEvent(element) {
    try {
        element.dispatchEvent(new Event('change', { bubbles: true }));
    } catch (error) {
        const changeEvent = document.createEvent('Event');
        changeEvent.initEvent('change', true, true);
        element.dispatchEvent(changeEvent);
    }
}
