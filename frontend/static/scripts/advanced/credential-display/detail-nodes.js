// Small pieces of the credential detail view, built as nodes.
import {el} from '../../shared/ui/dom.js';
import {describeValue} from './credential-detail-runtime/detail-sections.js';

const STYLES = {
    true: 'color: #11b66d; font-weight: 600;',
    false: 'color: #c62828; font-weight: 600;',
    missing: 'color: #6c757d;',
    other: 'color: #6c757d;',
};

/** A check's value: green true, red false, grey N/A when absent, anything else grey as written. */
export function booleanValue(value) {
    const described = describeValue(value);
    return el('span', { style: STYLES[described.kind], text: described.text });
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
