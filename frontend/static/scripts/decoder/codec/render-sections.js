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

function createSection(key, value) {
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
            'authenticatorData',
            'clientDataJSON',
            'clientExtensionResults',
            'responseDetails',
        ],
        'Attestation object': ['attestationObject', 'authenticatorData', 'extensions'],
        'Authenticator data': ['authenticatorData'],
        'WebAuthn client data': ['clientDataJSON'],
        'X.509 certificate': ['raw', 'pem', 'parsedX5c', 'certificates'],
        CBOR: ['ctapDecoded', 'expandedJson', 'decodedValue', 'ctap'],
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

export function renderDecodedResult(container, payload, mode = 'decode') {
    container.innerHTML = '';

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

    if (Array.isArray(payload.malformed) && payload.malformed.length > 0) {
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
