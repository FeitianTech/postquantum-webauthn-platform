// What the explorer's table cells show beyond an entry's own text. No DOM.
import { isCertifiedStatus, normaliseEnumKey } from '../formatters.js';

export const MISSING_CELL_TEXT = '—';
export const NO_ICON_TEXT = 'N/A';

/**
 * @param {Record<string, any> | null | undefined} entry
 * @returns {string}
 */
export function iconAltText(entry) {
    return `${entry?.name || 'Authenticator'} icon`;
}

const DANGER_STATUSES = new Set([
    'REVOKED',
    'USER_VERIFICATION_BYPASS',
    'ATTESTATION_KEY_COMPROMISE',
    'USER_KEY_REMOTE_COMPROMISE',
    'USER_KEY_PHYSICAL_COMPROMISE',
]);

/** @typedef {'success' | 'danger' | 'neutral'} StatusTone */

// A status's tone: danger for a revocation or a compromise, success for a
// certified level, neutral otherwise.
/**
 * @param {string} text
 * @returns {StatusTone}
 */
function statusTone(text) {
    const statusKey = normaliseEnumKey(text);
    if (DANGER_STATUSES.has(statusKey)) {
        return 'danger';
    }
    return isCertifiedStatus(statusKey) ? 'success' : 'neutral';
}

// The level's tone: success while the latest status stands by it (a level, or
// an update available), neutral once a revocation, a compromise or a status
// that is no certification came after it (the Status column says which).
/**
 * @param {Record<string, any> | null | undefined} entry
 * @returns {StatusTone}
 */
function levelTone(entry) {
    const latest = normaliseEnumKey(entry?.latestStatus);
    return isCertifiedStatus(latest) || latest === 'UPDATE_AVAILABLE' ? 'success' : 'neutral';
}

// The certification text as one badge and what follows it: the highest level
// the entry reached (as the server wrote it), then the descriptor and
// certificate number of its report.
/**
 * @param {Record<string, any> | null | undefined} entry
 * @returns {{ level: string, detail: string, tone: StatusTone }}
 */
export function certificationParts(entry) {
    const text = typeof entry?.certification === 'string' ? entry.certification.trim() : '';
    const [level, ...rest] = text ? text.split(' • ') : [];
    return { level: level || MISSING_CELL_TEXT, detail: rest.join(' • '), tone: level ? levelTone(entry) : 'neutral' };
}

// The latest status as one badge, in its tone.
/**
 * @param {Record<string, any> | null | undefined} entry
 * @returns {{ status: string, tone: StatusTone }}
 */
export function statusParts(entry) {
    const status = typeof entry?.latestStatus === 'string' ? entry.latestStatus.trim() : '';
    return { status: status || MISSING_CELL_TEXT, tone: statusTone(status) };
}

const IDENTIFIER_LABELS = {
    aaguid: 'AAGUID',
    aaid: 'AAID',
    akid: 'key identifier',
};

// What the ID column holds, from the entry's id kind (`aaguid:`, `aaid:`,
// `akid:`), to name its copy button.
/**
 * @param {Record<string, any> | null | undefined} entry
 * @returns {string}
 */
export function identifierLabel(entry) {
    const kind = typeof entry?.entryId === 'string' ? entry.entryId.split(':')[0] : '';
    return IDENTIFIER_LABELS[kind] || 'identifier';
}
