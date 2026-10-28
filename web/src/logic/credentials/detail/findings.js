// A saved credential's attestation findings, as its registration's record keeps
// them: its checks, else its summary (an Advanced record keeps only the summary
// in this browser), in the record or in its properties, whichever release saved
// it. DOM-free; the registration's details list them.
import { extractCredentialAttestationContext } from '../attestation-context.js';
import { findingList } from '../../shared/registration-findings.js';

/** @import { AttestationFindings } from '../../shared/registration-findings.js' */

/**
 * @param {Record<string, any>} cred
 * @returns {AttestationFindings}
 */
export function recordFindings(cred) {
    const { attestationChecksData, attestationSummaryData } = extractCredentialAttestationContext(cred);
    const holders = [attestationChecksData, attestationSummaryData].filter(Boolean);
    const listed = (/** @type {'errors' | 'warnings'} */ key) => holders.map(holder => holder[key]).find(Array.isArray);
    return { errors: findingList(listed('errors')), warnings: findingList(listed('warnings')) };
}
