import { formatKey } from './labels.js';

export function renderValue(value) {
    if (value === null || value === undefined) {
        const span = document.createElement('span');
        span.className = 'decoder-empty';
        span.textContent = String(value);
        return span;
    }

    if (typeof value === 'string') {
        const isMultiline = value.includes('\n') || value.length > 80;
        const element = document.createElement(isMultiline ? 'pre' : 'span');
        element.className = isMultiline ? 'decoder-pre' : 'decoder-inline';
        element.textContent = value;
        return element;
    }

    if (typeof value === 'number' || typeof value === 'boolean') {
        const span = document.createElement('span');
        span.className = 'decoder-primitive';
        span.textContent = String(value);
        return span;
    }

    if (Array.isArray(value)) {
        if (value.length === 0) {
            const span = document.createElement('span');
            span.className = 'decoder-empty';
            span.textContent = '[]';
            return span;
        }

        const list = document.createElement('ol');
        list.className = 'decoder-list';
        value.forEach((item) => {
            const listItem = document.createElement('li');
            listItem.appendChild(renderValue(item));
            list.appendChild(listItem);
        });
        return list;
    }

    if (typeof value === 'object') {
        const entries = Object.entries(value);
        if (entries.length === 0) {
            const span = document.createElement('span');
            span.className = 'decoder-empty';
            span.textContent = '{}';
            return span;
        }

        const definition = document.createElement('dl');
        definition.className = 'decoder-definition';

        entries.forEach(([childKey, childValue]) => {
            const term = document.createElement('dt');
            term.className = 'decoder-term';
            term.textContent = formatKey(childKey);

            const detail = document.createElement('dd');
            detail.className = 'decoder-details';
            detail.appendChild(renderValue(childValue));

            definition.appendChild(term);
            definition.appendChild(detail);
        });

        return definition;
    }

    const span = document.createElement('span');
    span.className = 'decoder-primitive';
    span.textContent = String(value);
    return span;
}

export function renderExpandedJson(value) {
    const textarea = document.createElement('textarea');
    textarea.className = 'form-control decoder-expanded-json';
    textarea.setAttribute('readonly', '');
    textarea.setAttribute('spellcheck', 'false');
    textarea.wrap = 'off';

    const payload = { 'decoded json': value === undefined ? null : value };
    try {
        textarea.value = JSON.stringify(payload, null, 2);
    } catch (error) {
        textarea.value = 'Unable to render expanded JSON';
    }

    return textarea;
}
