// The detail page's DOM pieces; what goes in them is explorer/detail.js's.
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
    const wrapper = document.createElement('div');
    wrapper.className = 'mds-detail-item';
    const labelEl = document.createElement('div');
    labelEl.className = 'mds-detail-item__label';
    labelEl.textContent = label;
    const list = document.createElement('div');
    list.className = 'mds-detail-list';
    values.forEach(value => {
        const chip = document.createElement('span');
        chip.className = 'mds-detail-chip';
        chip.textContent = value;
        list.appendChild(chip);
    });
    wrapper.appendChild(labelEl);
    wrapper.appendChild(list);
    return wrapper;
}

export function createCodeValueList(codes) {
    const container = document.createElement('div');
    container.className = 'mds-detail-code-values';
    codes.forEach(value => {
        const code = document.createElement('code');
        code.className = 'mds-detail-code';
        code.textContent = value;
        container.appendChild(code);
    });
    return container;
}
