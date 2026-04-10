import { extractList } from './utils.js';

export function createDetailSection(title) {
    const section = document.createElement('section');
    section.className = 'mds-detail-section';
    if (title) {
        const heading = document.createElement('h4');
        heading.className = 'mds-detail-section__title';
        heading.textContent = title;
        section.appendChild(heading);
    }
    return section;
}

export function appendDetailGrid(section, items) {
    if (!section || !Array.isArray(items) || !items.length) {
        return;
    }

    const valid = items.filter(item => {
        if (!item || typeof item.label !== 'string') {
            return false;
        }
        if (item.node instanceof Node) {
            return true;
        }
        const value = item.value;
        if (Array.isArray(value)) {
            return value.length > 0;
        }
        return value !== undefined && value !== null && String(value).trim() !== '';
    });

    if (!valid.length) {
        return;
    }

    const grid = document.createElement('div');
    grid.className = 'mds-detail-grid';

    valid.forEach(item => {
        const cell = document.createElement('div');
        cell.className = 'mds-detail-item';
        const labelEl = document.createElement('div');
        labelEl.className = 'mds-detail-item__label';
        labelEl.textContent = item.label;
        const valueEl = document.createElement('div');
        valueEl.className = 'mds-detail-item__value';
        if (item.node instanceof Node) {
            valueEl.appendChild(item.node);
        } else if (Array.isArray(item.value)) {
            valueEl.textContent = item.value.join(', ');
        } else {
            valueEl.textContent = String(item.value);
        }
        cell.appendChild(labelEl);
        cell.appendChild(valueEl);
        grid.appendChild(cell);
    });

    section.appendChild(grid);
}

export function createChipList(label, values) {
    const items = Array.isArray(values) ? values.filter(Boolean) : [];
    if (!items.length) {
        return null;
    }

    const wrapper = document.createElement('div');
    wrapper.className = 'mds-detail-item';
    const labelEl = document.createElement('div');
    labelEl.className = 'mds-detail-item__label';
    labelEl.textContent = label;
    const list = document.createElement('div');
    list.className = 'mds-detail-list';
    items.forEach(value => {
        const chip = document.createElement('span');
        chip.className = 'mds-detail-chip';
        chip.textContent = value;
        list.appendChild(chip);
    });
    wrapper.appendChild(labelEl);
    wrapper.appendChild(list);
    return wrapper;
}

export function createCodeValueList(values) {
    const items = extractList(values)
        .map(value => (value === undefined || value === null ? '' : String(value).trim()))
        .filter(Boolean);
    if (!items.length) {
        return null;
    }

    const container = document.createElement('div');
    container.className = 'mds-detail-code-values';
    items.forEach(value => {
        const code = document.createElement('code');
        code.className = 'mds-detail-code';
        code.textContent = value;
        container.appendChild(code);
    });
    return container;
}

function toRawDisplayString(value) {
    if (value === undefined || value === null) {
        return '';
    }
    if (typeof value === 'string') {
        return value;
    }
    if (typeof value === 'number' || typeof value === 'bigint') {
        return String(value);
    }
    if (typeof value === 'boolean') {
        return value ? 'true' : 'false';
    }
    try {
        return JSON.stringify(value);
    } catch (error) {
        try {
            return String(value);
        } catch (stringError) {
            return '';
        }
    }
}

export function formatRawListValues(value) {
    return extractList(value)
        .map(item => toRawDisplayString(item))
        .filter(text => text !== '');
}

export function formatAuthenticatorInfoValues(value) {
    return formatRawListValues(value);
}
