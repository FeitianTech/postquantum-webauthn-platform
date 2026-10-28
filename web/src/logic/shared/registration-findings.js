// Where a registration's attestation findings are in what the server answered:
// the errors in attestationErrors and the warnings in warnings, in both tabs'
// register-complete answers and in the body of a Simple registration the server
// refused (server/app/routes/simple/registration.py). Each finding is a code, or
// a code and its reason after ": " (./attestation-findings.js has their words,
// loaded with the list that shows them). DOM-free.

/**
 * A registration's findings, each kind in the order the server gave.
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
 * The findings a register-complete answer reports, or the body of a refused one.
 * @param {Record<string, unknown> | null | undefined} answer
 * @returns {AttestationFindings}
 */
export function answerFindings(answer) {
    return {
        errors: findingList(answer?.attestationErrors),
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
