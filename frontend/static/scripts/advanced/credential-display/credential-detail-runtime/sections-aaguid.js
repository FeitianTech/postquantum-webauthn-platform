import {el, fragment} from '../../../shared/ui/dom.js';
import {describeAaguid} from './detail-sections.js';

// The current UI's AAGUID under "User info at creation", built from
// ./detail-sections.js's data, with the status line the FIDO MDS jump fills.

function renderAaguidValue(label, value) {
    return el('div', { className: 'credential-aaguid-value' },
        el('span', { className: 'credential-aaguid-value-label', text: label }),
        el('div', { className: 'credential-code-block', text: value }),
    );
}

export function renderAaguidSection(aaguid) {
    return fragment(
        el('div', { className: 'credential-aaguid-row' },
            el('span', { className: 'credential-aaguid-label', text: aaguid.title }),
        ),
        el('div', { className: 'credential-aaguid-status', attrs: { role: 'status', 'aria-live': 'polite' } },
            el('span', { className: 'credential-aaguid-spinner', attrs: { 'aria-hidden': 'true', hidden: true } }),
            el('span', { className: 'credential-aaguid-status-text' }),
        ),
        el('div', { className: 'credential-aaguid-values' },
            aaguid.values.map(entry => renderAaguidValue(entry.label, entry.value)),
        ),
    );
}

export function buildAaguidSection(cred, attestationContext) {
    return renderAaguidSection(describeAaguid(cred, attestationContext));
}
