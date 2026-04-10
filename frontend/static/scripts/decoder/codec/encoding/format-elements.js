import { formatKey } from '../labels.js';

const ENCODED_FORMAT_ORDER = ['hex', 'base64', 'base64url', 'colonHex'];
const ENCODED_FORMAT_SKIP_KEYS = new Set(['encoding']);

function createEncodedFormatBlock(key, value) {
    const block = document.createElement('div');
    block.className = 'codec-encoded-format';

    const label = document.createElement('div');
    label.className = 'codec-encoded-label';
    label.textContent = formatKey(key);
    block.appendChild(label);

    const pre = document.createElement('pre');
    pre.className = 'decoder-pre codec-encoded-value';
    pre.textContent = value;
    block.appendChild(pre);

    return block;
}

function appendStringFormatBlock(blocks, usedKeys, key, value) {
    if (typeof value !== 'string') {
        return;
    }

    if (!value.trim()) {
        return;
    }

    blocks.push(createEncodedFormatBlock(key, value));
    usedKeys.add(key);
}

export function createEncodedFormatElements(summary) {
    if (!summary || typeof summary !== 'object') {
        return [];
    }

    const blocks = [];
    const usedKeys = new Set();

    ENCODED_FORMAT_ORDER.forEach((key) => {
        appendStringFormatBlock(blocks, usedKeys, key, summary[key]);
    });

    Object.entries(summary).forEach(([key, value]) => {
        if (usedKeys.has(key) || ENCODED_FORMAT_SKIP_KEYS.has(key)) {
            return;
        }

        appendStringFormatBlock(blocks, usedKeys, key, value);
    });

    return blocks;
}
