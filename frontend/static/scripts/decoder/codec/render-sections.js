import { createEncodedFormatBlocks } from './encoding/format-elements.js';
import {
    autoSizeRawTextarea,
    resetScrollPosition,
} from './dom-state.js';
import { renderExpandedJson, renderValue } from './render-values.js';
import { describeCodecResult } from './result.js';
import { codecEdnText } from './values.js';

// The item as extended diagnostic notation: the bytes exactly, which can be
// long, so the section starts closed. Text only: the notation quotes the input.
function createEdnSection({ label, value }) {
    const section = document.createElement('details');
    section.className = 'decoder-section decoder-edn';

    const summary = document.createElement('summary');
    const heading = document.createElement('h4');
    heading.textContent = label;
    summary.appendChild(heading);
    section.appendChild(summary);

    const body = document.createElement('div');
    body.className = 'decoder-section-body';
    const text = document.createElement('pre');
    text.className = 'decoder-pre decoder-edn-text';
    text.textContent = codecEdnText(value);
    body.appendChild(text);
    section.appendChild(body);
    return section;
}

function createSection(view) {
    if (view.kind === 'edn') {
        return createEdnSection(view);
    }
    const section = document.createElement('div');
    section.className = 'decoder-section';

    const heading = document.createElement('h4');
    heading.textContent = view.label;
    section.appendChild(heading);

    const body = document.createElement('div');
    body.className = 'decoder-section-body';
    if (view.kind === 'expandedJson') {
        const textarea = renderExpandedJson(view.value);
        body.appendChild(textarea);
        requestAnimationFrame(() => {
            autoSizeRawTextarea(textarea);
            resetScrollPosition(textarea);
        });
    } else {
        body.appendChild(renderValue(view.value));
    }

    section.appendChild(body);
    return section;
}

function createEncodedSection(encoded) {
    const section = document.createElement('div');
    section.className = 'decoder-section codec-encoded-section';

    const heading = document.createElement('h4');
    heading.textContent = encoded.label;
    section.appendChild(heading);

    const body = document.createElement('div');
    body.className = 'decoder-section-body codec-encoded-body';

    const formatsContainer = document.createElement('div');
    formatsContainer.className = 'codec-encoded-formats';
    createEncodedFormatBlocks(encoded.formats).forEach(block => formatsContainer.appendChild(block));
    body.appendChild(formatsContainer);

    if (encoded.byteLength !== null) {
        const meta = document.createElement('div');
        meta.className = 'codec-encoded-meta';
        meta.textContent = `Byte length: ${encoded.byteLength}`;
        body.appendChild(meta);
    }

    section.appendChild(body);
    return section;
}

// One line per finding: where it is and what it says. Built from text nodes
// only -- a finding's message can quote the input.
function buildFindingsList(heading, findings) {
    const block = document.createElement('div');
    block.className = 'decoder-warning decoder-findings';

    const headingElement = document.createElement('p');
    headingElement.className = 'decoder-findings-heading';
    headingElement.textContent = heading;
    block.appendChild(headingElement);

    const list = document.createElement('ul');
    findings.forEach((finding) => {
        const item = document.createElement('li');
        item.textContent = finding.line;
        list.appendChild(item);
    });
    block.appendChild(list);
    return block;
}

export function renderDecodedResult(container, payload, mode = 'decode') {
    container.replaceChildren();

    const view = describeCodecResult(payload, mode);
    if (view.empty) {
        const empty = document.createElement('div');
        empty.className = 'decoder-empty';
        empty.textContent = view.empty;
        container.appendChild(empty);
        return;
    }

    const header = document.createElement('div');
    header.className = 'decoder-summary-header';

    const statusPill = document.createElement('span');
    statusPill.className = `decoder-pill ${view.success ? 'success' : 'error'}`;
    statusPill.textContent = view.pill;
    header.appendChild(statusPill);

    const typeEl = document.createElement('span');
    typeEl.className = 'decoder-type';
    typeEl.textContent = view.type;
    header.appendChild(typeEl);

    container.appendChild(header);

    if (view.lenientNote) {
        const note = document.createElement('div');
        note.className = 'decoder-warning';
        note.textContent = view.lenientNote;
        container.appendChild(note);
    }

    if (view.findings.length > 0) {
        container.appendChild(buildFindingsList(view.findingsHeading, view.findings));
    } else if (view.malformed) {
        const warning = document.createElement('div');
        warning.className = 'decoder-warning';
        warning.textContent = view.malformed;
        container.appendChild(warning);
    }

    const sectionsWrapper = document.createElement('div');
    sectionsWrapper.className = 'decoder-sections';

    if (view.encoded) {
        sectionsWrapper.appendChild(createEncodedSection(view.encoded));
    } else if (view.noSections) {
        const emptySection = document.createElement('div');
        emptySection.className = 'decoder-empty';
        emptySection.textContent = view.noSections;
        sectionsWrapper.appendChild(emptySection);
    } else {
        view.sections.forEach((section) => sectionsWrapper.appendChild(createSection(section)));
    }

    container.appendChild(sectionsWrapper);
}
