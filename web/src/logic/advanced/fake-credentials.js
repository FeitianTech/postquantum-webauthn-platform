// The fake credential IDs a registration's excludeCredentials or an
// authentication's allowCredentials carries after the saved ones, with no page:
// how a typed ID is kept (hex), how long a new one is and what to say about the
// length asked for, removing one, and the list's sentences. DOM-free.

export const FAKE_CREDENTIAL_TEXT = {
    noExclude: 'No fake credential IDs added.',
    noAllow: 'No fake allow credential IDs added.',
    invalidLength: 'Please enter a valid fake credential ID length (at least 1 byte).',
    truncated: 'Credential IDs are limited to 4096 bytes. Generated value truncated to maximum length.',
};

export const FAKE_CREDENTIAL_MAX_BYTES = 4096;

/** @typedef {{ bytes: number, error: string | null, notice: string | null }} FakeLength */

/** An ID as the list keeps it: its hex digits, lower case; '' when it has none. */
export function normaliseFakeCredentialHex(value) {
    if (typeof value !== 'string') {
        return '';
    }
    const trimmed = value.trim();
    if (!trimmed) {
        return '';
    }
    return trimmed.replace(/[^0-9a-fA-F]/g, '').toLowerCase();
}

/**
 * A list of IDs as the list keeps it: each normalised, those with no hex left out.
 * @param {unknown} values
 * @returns {string[]}
 */
export function normaliseFakeCredentialList(values) {
    return Array.isArray(values) ? values.map(normaliseFakeCredentialHex).filter(Boolean) : [];
}

/**
 * How many random bytes a new ID gets for the length typed: none, with the
 * error, for a length that is not a whole number above 0; at most 4096, with a
 * notice when the length asked for was more.
 * @param {string} length
 * @returns {FakeLength}
 */
export function fakeCredentialLength(length) {
    const parsed = Number.parseInt(length, 10);
    if (!Number.isFinite(parsed) || parsed <= 0) {
        return { bytes: 0, error: FAKE_CREDENTIAL_TEXT.invalidLength, notice: null };
    }
    const bytes = Math.min(parsed, FAKE_CREDENTIAL_MAX_BYTES);
    return { bytes, error: null, notice: parsed !== bytes ? FAKE_CREDENTIAL_TEXT.truncated : null };
}

/**
 * An ID's length as the list says it.
 * @param {string} hex
 */
export function fakeCredentialSize(hex) {
    return `${Math.floor(hex.length / 2)} bytes`;
}

/**
 * The list without the ID at `index` (a number or its text), or null when it has none there.
 * @param {string[]} list
 * @param {number | string} index
 * @returns {string[] | null}
 */
export function withoutFakeCredential(list, index) {
    const parsed = Number.parseInt(String(index), 10);
    if (!Number.isInteger(parsed) || parsed < 0 || parsed >= list.length) {
        return null;
    }
    return [...list.slice(0, parsed), ...list.slice(parsed + 1)];
}
