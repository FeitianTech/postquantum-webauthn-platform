import { MISSING_CELL_TEXT, NO_ICON_TEXT, iconAltText } from './explorer/rows.js';

export function createTextCell(text, title) {
    const cell = document.createElement('td');
    cell.textContent = text;
    if (title) {
        cell.title = title;
    }
    return cell;
}

export function createNameCell(entry, { onShowAuthenticatorDetail } = {}) {
    const cell = document.createElement('td');
    cell.classList.add('mds-cell-name');
    const label = entry?.name || MISSING_CELL_TEXT;
    const trimmed = label.trim();

    if (!entry || !trimmed || trimmed === MISSING_CELL_TEXT) {
        cell.textContent = label || MISSING_CELL_TEXT;
        return cell;
    }

    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'mds-name-button';
    button.textContent = label;
    button.addEventListener('click', event => {
        event.preventDefault();
        event.stopPropagation();
        if (typeof onShowAuthenticatorDetail === 'function') {
            onShowAuthenticatorDetail(entry);
        }
    });
    cell.appendChild(button);
    return cell;
}

export function createIdCell(id) {
    const cell = createTextCell(id || MISSING_CELL_TEXT);
    cell.classList.add('mds-cell-id');
    return cell;
}

export function createIconCell(entry) {
    const cell = document.createElement('td');
    const wrapper = document.createElement('div');
    wrapper.className = 'mds-icon-wrapper';

    if (entry.icon) {
        const img = document.createElement('img');
        img.src = entry.icon;
        img.alt = iconAltText(entry);
        wrapper.appendChild(img);
    } else {
        const placeholder = document.createElement('span');
        placeholder.className = 'mds-icon-placeholder';
        placeholder.textContent = NO_ICON_TEXT;
        wrapper.appendChild(placeholder);
    }

    cell.appendChild(wrapper);
    return cell;
}

export function createTagCell(items, neutral = false) {
    const cell = document.createElement('td');
    const values = Array.isArray(items) ? items : [];

    if (!values.length) {
        cell.textContent = MISSING_CELL_TEXT;
        return cell;
    }

    const group = document.createElement('div');
    group.className = 'mds-tag-group';

    values.forEach(value => {
        const tag = document.createElement('span');
        tag.className = neutral ? 'mds-tag mds-tag--neutral' : 'mds-tag';
        tag.textContent = value;
        group.appendChild(tag);
    });

    cell.appendChild(group);
    return cell;
}
