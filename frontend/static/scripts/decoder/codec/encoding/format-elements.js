import { listEncodedFormats } from './summary.js';

function createEncodedFormatBlock({ label, value }) {
    const block = document.createElement('div');
    block.className = 'codec-encoded-format';

    const labelElement = document.createElement('div');
    labelElement.className = 'codec-encoded-label';
    labelElement.textContent = label;
    block.appendChild(labelElement);

    const pre = document.createElement('pre');
    pre.className = 'decoder-pre codec-encoded-value';
    pre.textContent = value;
    block.appendChild(pre);

    return block;
}

// One labelled block per view of the encoded bytes (listEncodedFormats).
export function createEncodedFormatBlocks(formats) {
    return formats.map(createEncodedFormatBlock);
}

export function createEncodedFormatElements(summary) {
    return createEncodedFormatBlocks(listEncodedFormats(summary));
}
