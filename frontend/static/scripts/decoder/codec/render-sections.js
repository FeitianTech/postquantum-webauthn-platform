import {
    createEncodedFormatElements,
    findEncodedSummary,
} from './encoding.js';
import {
    autoSizeRawTextarea,
    resetScrollPosition,
} from './dom-state.js';
import { formatKey } from './labels.js';
import { renderExpandedJson, renderValue } from './render-values.js';

// The item as extended diagnostic notation: the bytes exactly, which can be
// long, so the section starts closed. Text only: the notation quotes the input.
function createEdnSection(value) {
    const section = document.createElement('details');
    section.className = 'decoder-section decoder-edn';

    const summary = document.createElement('summary');
    const heading = document.createElement('h4');
    heading.textContent = formatKey('edn');
    summary.appendChild(heading);
    section.appendChild(summary);

    const body = document.createElement('div');
    body.className = 'decoder-section-body';
    const text = document.createElement('pre');
    text.className = 'decoder-pre decoder-edn-text';
    text.textContent = typeof value === 'string' ? value : JSON.stringify(value);
    body.appendChild(text);
    section.appendChild(body);
    return section;
}

function createSection(key, value) {
    if (key === 'edn') {
        return createEdnSection(value);
    }
    const section = document.createElement('div');
    section.className = 'decoder-section';

    const heading = document.createElement('h4');
    heading.textContent = formatKey(key);
    section.appendChild(heading);

    const body = document.createElement('div');
    body.className = 'decoder-section-body';
    if (key === 'expandedJson') {
        const textarea = renderExpandedJson(value);
        body.appendChild(textarea);
        requestAnimationFrame(() => {
            autoSizeRawTextarea(textarea);
            resetScrollPosition(textarea);
        });
    } else {
        body.appendChild(renderValue(value));
    }

    section.appendChild(body);
    return section;
}

function buildSections(type, data) {
    const sections = [];

    if (data === undefined) {
        return sections;
    }

    if (data === null || typeof data !== 'object' || Array.isArray(data)) {
        sections.push(createSection(type || 'Data', data));
        return sections;
    }

    const orderMap = {
        PublicKeyCredential: [
            'credential',
            'attestationObject',
            'attestationStatementDecoded',
            'authenticatorData',
            'clientDataJSON',
            'clientExtensionResults',
            'extensionsDecoded',
            'responseDetails',
        ],
        'Attestation object': [
            'attestationObject',
            'attestationStatementDecoded',
            'authenticatorData',
            'extensionsDecoded',
            'extensions',
            'edn',
        ],
        'Authenticator data': ['authenticatorData'],
        'WebAuthn client data': ['clientDataJSON'],
        'X.509 certificate': ['raw', 'pem', 'parsedX5c', 'certificates'],
        CBOR: [
            'ctapDecoded',
            'getInfoDecoded',
            'attestationStatementDecoded',
            'extensionsDecoded',
            'expandedJson',
            'decodedValue',
            'ctap',
            'edn',
        ],
    };

    const usedKeys = new Set();
    const baseType = typeof type === 'string'
        ? type.split(' (', 1)[0]
        : '';
    const preferredOrder = orderMap[baseType] || [];

    preferredOrder.forEach((key) => {
        if (Object.prototype.hasOwnProperty.call(data, key)) {
            const section = createSection(key, data[key]);
            if (section) {
                sections.push(section);
                usedKeys.add(key);
            }
        }
    });

    Object.keys(data).forEach((key) => {
        if (usedKeys.has(key)) {
            return;
        }
        const section = createSection(key, data[key]);
        if (section) {
            sections.push(section);
        }
    });

    return sections;
}

function buildEncodeSections(type, data) {
    const summaryInfo = findEncodedSummary(data);
    if (!summaryInfo) {
        return buildSections(type, data);
    }

    const { label, summary } = summaryInfo;
    const formatBlocks = createEncodedFormatElements(summary);
    if (formatBlocks.length === 0) {
        return buildSections(type, data);
    }

    const section = document.createElement('div');
    section.className = 'decoder-section codec-encoded-section';

    const heading = document.createElement('h4');
    heading.textContent = label || 'Encoded output';
    section.appendChild(heading);

    const body = document.createElement('div');
    body.className = 'decoder-section-body codec-encoded-body';

    const formatsContainer = document.createElement('div');
    formatsContainer.className = 'codec-encoded-formats';
    formatBlocks.forEach(block => formatsContainer.appendChild(block));
    body.appendChild(formatsContainer);

    const byteLength = typeof summary?.byteLength === 'number'
        ? summary.byteLength
        : typeof summary?.length === 'number'
            ? summary.length
            : null;

    if (typeof byteLength === 'number' && Number.isFinite(byteLength)) {
        const meta = document.createElement('div');
        meta.className = 'codec-encoded-meta';
        meta.textContent = `Byte length: ${byteLength}`;
        body.appendChild(meta);
    }

    section.appendChild(body);
    return [section];
}

// One line per finding: where it is and what it says. Built from text nodes
// only -- a finding's message can quote the input.
function buildFindingsList(findings) {
    const block = document.createElement('div');
    block.className = 'decoder-warning decoder-findings';

    const heading = document.createElement('p');
    heading.className = 'decoder-findings-heading';
    heading.textContent = findings.length === 1 ? '1 finding' : `${findings.length} findings`;
    block.appendChild(heading);

    const list = document.createElement('ul');
    findings.forEach((finding) => {
        const item = document.createElement('li');
        // A finding in JSON has a path and no offset: it is shown by its path alone.
        const offset = Number.isInteger(finding?.offset) ? `offset ${finding.offset} · ` : '';
        const path = typeof finding?.path === 'string' ? finding.path : '';
        const message = typeof finding?.message === 'string' ? finding.message : '';
        // A finding inside a PublicKeyCredential field counts its offset from that field.
        const source = typeof finding?.source === 'string' ? `${finding.source}: ` : '';
        item.textContent = `${source}${offset}${path} — ${message}`;
        list.appendChild(item);
    });
    block.appendChild(list);
    return block;
}

export function renderDecodedResult(container, payload, mode = 'decode') {
    container.replaceChildren();

    if (!payload || typeof payload !== 'object') {
        const empty = document.createElement('div');
        empty.className = 'decoder-empty';
        empty.textContent = 'No decoded data available.';
        container.appendChild(empty);
        return;
    }

    const header = document.createElement('div');
    header.className = 'decoder-summary-header';

    const statusPill = document.createElement('span');
    statusPill.className = `decoder-pill ${payload.success ? 'success' : 'error'}`;
    statusPill.textContent = payload.success ? 'Success' : 'Error';
    header.appendChild(statusPill);

    const typeEl = document.createElement('span');
    typeEl.className = 'decoder-type';
    typeEl.textContent = payload.type || 'Decoded data';
    header.appendChild(typeEl);

    container.appendChild(header);

    if (payload.decodeMode === 'lenient') {
        const note = document.createElement('div');
        note.className = 'decoder-warning';
        note.textContent = 'Decoded in lenient mode (best effort); skipped items are listed below.';
        container.appendChild(note);
    }

    const findings = Array.isArray(payload.findings) ? payload.findings : [];
    if (findings.length > 0) {
        container.appendChild(buildFindingsList(findings));
    } else if (Array.isArray(payload.malformed) && payload.malformed.length > 0) {
        const warning = document.createElement('div');
        warning.className = 'decoder-warning';
        warning.textContent = `Malformed segments: ${payload.malformed.join(', ')}`;
        container.appendChild(warning);
    }

    const sectionsWrapper = document.createElement('div');
    sectionsWrapper.className = 'decoder-sections';

    const sections = mode === 'encode'
        ? buildEncodeSections(payload.type, payload.data)
        : buildSections(payload.type, payload.data);

    if (sections.length === 0) {
        const emptySection = document.createElement('div');
        emptySection.className = 'decoder-empty';
        emptySection.textContent = 'No structured data available.';
        sectionsWrapper.appendChild(emptySection);
    } else {
        sections.forEach((section) => sectionsWrapper.appendChild(section));
    }

    container.appendChild(sectionsWrapper);
}
