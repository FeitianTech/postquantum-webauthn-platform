import {el} from '../../../shared/ui/dom.js';
import {
    attestationResultRow,
    booleanValue,
    labelledLine,
} from '../detail-nodes.js';
import {DETAIL_TEXT, describeProperties} from './detail-sections.js';

// The current UI's "Properties", built from ./detail-sections.js's data.

function rootCheckColour(value) {
    if (value === true) {
        return '#198754';
    }
    if (value === false) {
        return '#dc3545';
    }
    return '#6c757d';
}

function buildRootChecks(rootChecks) {
    if (!rootChecks) {
        return null;
    }

    const rootCheckParts = rootChecks.map(check => el('span', {
        style: `color: ${rootCheckColour(check.value)}; font-weight: 600;`,
        text: check.label,
    }));

    return el('span', { style: 'margin-left: 0.5rem; color: #6c757d;' },
        '(',
        rootCheckParts.flatMap((part, index) => (index ? [', ', part] : [part])),
        ')',
    );
}

export function renderPropertiesSection(properties) {
    const [before, strong, after] = DETAIL_TEXT.checksNote;
    const attestationChecksNotice = el('p', {
        style: 'margin: 0 0 0.65rem; color: #6c757d; font-size: 0.9rem; line-height: 1.5;',
    },
    before,
    el('strong', { text: strong }),
    after,
    );

    return el('div', { style: 'margin-bottom: 1.5rem;' },
        el('h4', { style: 'color: #0072CE; margin-bottom: 0.5rem;', text: properties.title }),
        el('div', { style: 'font-size: 0.9rem; line-height: 1.4;' },
            el('div', {}, el('strong', { text: DETAIL_TEXT.discoverable }), ' ', booleanValue(properties.discoverable)),
            el('div', {}, el('strong', { text: DETAIL_TEXT.largeBlob }), ' ', booleanValue(properties.largeBlob)),
            properties.minPinLength !== null
                ? labelledLine(DETAIL_TEXT.minPinLength, String(properties.minPinLength))
                : null,
            el('div', { style: 'margin-top: 0.5rem; padding-top: 0.75rem; border-top: 1px solid rgba(0, 114, 206, 0.15);' },
                attestationChecksNotice,
                properties.checks.map(check => attestationResultRow(check.label, check.value, buildRootChecks(check.rootChecks))),
                properties.warning
                    ? el('div', {
                        style: 'margin-top: 0.4rem; color: #c47f16; font-size: 0.85rem;',
                        text: properties.warning,
                    })
                    : null,
            ),
        ),
    );
}

export function buildPropertiesSection(inputs) {
    return renderPropertiesSection(describeProperties(inputs));
}
