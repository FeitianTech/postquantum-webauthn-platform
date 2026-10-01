// Whether a byte field's text holds enough bytes, as hex: empty text is not an
// error; anything else is only hex digits, two to a byte. DOM-free.

export function hexInputIsValid(text, minBytes = 0) {
    const value = typeof text === 'string' ? text.trim() : '';
    if (!value) {
        return true;
    }
    return /^[0-9a-fA-F]+$/.test(value) && value.length >= minBytes * 2;
}
