// Where a ceremony's findings are in what the server answered: a registration's
// errors in attestationErrors, an authentication's in assertionErrors, and the
// warnings in warnings, in both tabs' complete answers and in the body of a Simple
// registration or sign-in the server refused (server/app/routes/simple). Each
// finding is a code, or a code and its reason after ": " (./attestation-findings.js
// has their words, loaded with the list that shows them). DOM-free.

/**
 * A ceremony's findings, each kind in the order the server gave.
 * @typedef {{ errors: string[], warnings: string[] }} AttestationFindings
 */

export const FINDINGS_TITLE = 'Verification findings';

/**
 * A list of findings as the server wrote it: its strings, trimmed, but blank
 * ones; none for a value that is not a list.
 * @param {unknown} value
 * @returns {string[]}
 */
export function findingList(value) {
    return Array.isArray(value)
        ? value.filter(item => typeof item === 'string' && item.trim()).map(item => item.trim())
        : [];
}

/**
 * The findings a complete answer reports, a registration's or an authentication's,
 * or the body of a refused one.
 * @param {Record<string, unknown> | null | undefined} answer
 * @returns {AttestationFindings}
 */
export function answerFindings(answer) {
    return {
        errors: findingList(answer?.attestationErrors ?? answer?.assertionErrors),
        warnings: findingList(answer?.warnings),
    };
}

/**
 * Whether there is a finding to show.
 * @param {AttestationFindings | null | undefined} findings
 * @returns {boolean}
 */
export function hasFindings(findings) {
    return Boolean(findings && (findings.errors.length || findings.warnings.length));
}
