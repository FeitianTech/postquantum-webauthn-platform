// Small pieces of the credential detail view, built as nodes.
import {el} from '../../shared/ui/dom.js';

const TRUE_STYLE = 'color: #11b66d; font-weight: 600;';
const FALSE_STYLE = 'color: #c62828; font-weight: 600;';
const OTHER_STYLE = 'color: #6c757d;';

/** A check's value: green true, red false, grey N/A when absent, anything else grey as written. */
export function booleanValue(value) {
    const normalized = typeof value === 'string' ? value.trim().toLowerCase() : value;
    if (normalized === true || normalized === 'true') {
        return el('span', { style: TRUE_STYLE, text: 'true' });
    }
    if (normalized === false || normalized === 'false') {
        return el('span', { style: FALSE_STYLE, text: 'false' });
    }
    if (value === null || value === undefined) {
        return el('span', { style: OTHER_STYLE, text: 'N/A' });
    }
    return el('span', { style: OTHER_STYLE, text: String(value) });
}

/** One attestation check: its label, its value, and whatever follows the value. */
export function attestationResultRow(label, value, extra = null) {
    return el('div', { style: 'display: flex; align-items: center; gap: 0.5rem; margin-bottom: 0.35rem;' },
        el('span', { style: 'min-width: 180px;' }, el('strong', { text: `${label}:` })),
        el('span', {}, booleanValue(value), extra),
    );
}

/** A bold label followed by its value, as the detail view's lines read. */
export function labelledLine(label, value, options = {}) {
    return el('div', options, el('strong', { text: label }), ` ${value}`);
}
