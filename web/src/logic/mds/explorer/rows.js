// What the explorer's table cells show beyond an entry's own text. No DOM.
import { normaliseEnumKey } from '../formatters.js';

export const MISSING_CELL_TEXT = '—';
export const NO_ICON_TEXT = 'N/A';

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

// The certification text as one badge and what follows it: the level (the
// latest status, as the server wrote it), then the descriptor and certificate
// number; the tone is success for a certified level, danger for a revocation or
// a compromise, neutral otherwise.
export function certificationParts(entry) {
    const text = typeof entry?.certification === 'string' ? entry.certification.trim() : '';
    const [level, ...rest] = text ? text.split(' • ') : [];
    const statusKey = normaliseEnumKey(entry?.certificationStatus || level);
    let tone = 'neutral';
    if (DANGER_STATUSES.has(statusKey)) {
        tone = 'danger';
    } else if (statusKey.startsWith('FIDO_CERTIFIED')) {
        tone = 'success';
    }
    return { level: level || MISSING_CELL_TEXT, detail: rest.join(' • '), tone };
}

const IDENTIFIER_LABELS = {
    aaguid: 'AAGUID',
    aaid: 'AAID',
    akid: 'key identifier',
};

// What the ID column holds, from the entry's id kind (`aaguid:`, `aaid:`,
// `akid:`), to name its copy button.
export function identifierLabel(entry) {
    const kind = typeof entry?.entryId === 'string' ? entry.entryId.split(':')[0] : '';
    return IDENTIFIER_LABELS[kind] || 'identifier';
}
