import { classifyCodecValue, codecExpandedJson } from './values.js';

function withBadges(badges, element) {
    if (badges.length === 0) {
        return element;
    }
    const wrapper = document.createElement('div');
    const row = document.createElement('div');
    row.className = 'decoder-badges';
    badges.forEach(([kind, text]) => {
        const badge = document.createElement('span');
        badge.className = `decoder-badge decoder-badge--${kind}`;
        badge.textContent = text;
        row.appendChild(badge);
    });
    wrapper.appendChild(row);
    wrapper.appendChild(element);
    return wrapper;
}

function textElement(tag, className, text) {
    const element = document.createElement(tag);
    element.className = className;
    element.textContent = text;
    return element;
}

export function renderValue(value) {
    const view = classifyCodecValue(value);

    if (view.kind === 'empty') {
        return textElement('span', 'decoder-empty', view.text);
    }
    if (view.kind === 'block') {
        return textElement('pre', 'decoder-pre', view.text);
    }
    if (view.kind === 'inline') {
        return textElement('span', 'decoder-inline', view.text);
    }
    if (view.kind === 'list') {
        const list = document.createElement('ol');
        list.className = 'decoder-list';
        view.items.forEach((item) => {
            const listItem = document.createElement('li');
            listItem.appendChild(renderValue(item));
            list.appendChild(listItem);
        });
        return list;
    }
    if (view.kind === 'map') {
        const definition = document.createElement('dl');
        definition.className = 'decoder-definition';
        view.entries.forEach((entry) => {
            definition.appendChild(textElement('dt', 'decoder-term', entry.label));
            const detail = document.createElement('dd');
            detail.className = 'decoder-details';
            detail.appendChild(renderValue(entry.value));
            definition.appendChild(detail);
        });
        return withBadges(view.badges, definition);
    }
    return textElement('span', 'decoder-primitive', view.text);
}

export function renderExpandedJson(value) {
    const textarea = document.createElement('textarea');
    textarea.className = 'form-control decoder-expanded-json';
    textarea.setAttribute('readonly', '');
    textarea.setAttribute('spellcheck', 'false');
    textarea.wrap = 'off';
    textarea.value = codecExpandedJson(value);
    return textarea;
}
