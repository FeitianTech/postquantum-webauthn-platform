// What navigator.credentials.create() or get() means by a SecurityError: most
// often an RP ID that is neither this page's domain nor one it ends with.

export const RP_ID_REFUSED_TEXT = 'The browser refused the RP ID for this page';

/**
 * A SecurityError in words, the browser's own message after it when it gave one.
 * @param {{ message?: string }} error
 * @returns {string}
 */
export function securityErrorText(error) {
    return error.message ? `${RP_ID_REFUSED_TEXT}: ${error.message}` : RP_ID_REFUSED_TEXT;
}
