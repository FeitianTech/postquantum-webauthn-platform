let activeDropdown = null;

export class FilterDropdown {
    constructor(input, onSelect, config = {}) {
        this.input = input;
        this.onSelect = onSelect;
        this.options = [];
        this.filtered = [];
        this.activeIndex = -1;
        this.list = null;
        this.container = null;
        this.expandToContent = Boolean(config.expandDropdown);

        const parent = input.parentElement;
        if (parent) {
            parent.classList.add('mds-filter-cell');
        }

        this.container = document.createElement('div');
        this.container.className = 'mds-filter-dropdown';
        this.container.hidden = true;
        if (this.expandToContent) {
            this.container.classList.add('mds-filter-dropdown--expanded');
        }

        this.list = document.createElement('ul');
        this.list.className = 'mds-filter-dropdown__list';
        this.container.appendChild(this.list);

        if (parent) {
            parent.appendChild(this.container);
        } else {
            input.insertAdjacentElement('afterend', this.container);
        }

        this.handleDocumentClick = this.handleDocumentClick.bind(this);

        input.addEventListener('focus', () => this.open());
        input.addEventListener('click', () => this.open());
        input.addEventListener('keydown', event => this.handleKeyDown(event));
        input.addEventListener('input', () => this.filter(this.input.value));

        this.container.addEventListener('mousedown', event => {
            event.preventDefault();
        });

        this.container.addEventListener('click', event => {
            const optionEl = event.target.closest('.mds-filter-dropdown__option');
            if (optionEl) {
                const value = optionEl.getAttribute('data-value') || optionEl.textContent || '';
                this.select(value);
            }
        });

        document.addEventListener('mousedown', this.handleDocumentClick);
    }

    setOptions(options) {
        const unique = Array.from(new Set(options.filter(Boolean)));
        unique.sort((a, b) => a.localeCompare(b, undefined, { sensitivity: 'base' }));
        this.options = unique;
        this.filter(this.input.value);
    }

    open() {
        if (!this.options.length) {
            return;
        }
        if (activeDropdown && activeDropdown !== this) {
            activeDropdown.close();
        }
        activeDropdown = this;
        this.container.hidden = false;
        this.container.classList.add('is-open');
        this.activeIndex = -1;
        this.filter(this.input.value);
    }

    close() {
        if (activeDropdown === this) {
            activeDropdown = null;
        }
        this.container.hidden = true;
        this.container.classList.remove('is-open');
        this.activeIndex = -1;
    }

    filter(query) {
        const value = (query || '').trim().toLowerCase();
        if (!value) {
            this.filtered = [...this.options];
        } else {
            this.filtered = this.options.filter(option => option.toLowerCase().includes(value));
        }
        this.render();
    }

    render() {
        if (!this.list) {
            return;
        }
        this.list.innerHTML = '';

        const items = this.filtered.length ? this.filtered : [];
        if (!items.length) {
            if (!this.options.length) {
                return;
            }
            const empty = document.createElement('li');
            empty.className = 'mds-filter-dropdown__empty';
            empty.textContent = 'No matches';
            this.list.appendChild(empty);
            return;
        }

        items.forEach((option, index) => {
            const item = document.createElement('li');
            item.className = 'mds-filter-dropdown__option';
            if (index === this.activeIndex) {
                item.classList.add('is-active');
            }
            item.textContent = option;
            item.setAttribute('data-value', option);
            this.list.appendChild(item);
        });
    }

    handleKeyDown(event) {
        if (!this.options.length) {
            return;
        }
        if (event.key === 'Escape') {
            this.close();
            return;
        }
        if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
            if (!this.container.classList.contains('is-open')) {
                this.open();
            }
            const delta = event.key === 'ArrowDown' ? 1 : -1;
            this.move(delta);
            event.preventDefault();
            return;
        }
        if (event.key === 'Enter' && this.container.classList.contains('is-open') && this.activeIndex >= 0) {
            const items = this.filtered.length ? this.filtered : this.options;
            const value = items[this.activeIndex];
            if (value) {
                this.select(value);
                event.preventDefault();
            }
        }
    }

    move(delta) {
        const items = this.filtered.length ? this.filtered : this.options;
        if (!items.length) {
            this.activeIndex = -1;
            this.render();
            return;
        }
        this.activeIndex = (this.activeIndex + delta + items.length) % items.length;
        this.render();
        const activeEl = this.list?.querySelector('.mds-filter-dropdown__option.is-active');
        if (activeEl) {
            activeEl.scrollIntoView({ block: 'nearest' });
        }
    }

    select(value) {
        this.input.value = value;
        this.onSelect(value);
        this.close();
    }

    handleDocumentClick(event) {
        if (!this.container.contains(event.target) && event.target !== this.input) {
            this.close();
        }
    }
}

export function createFilterDropdown(input, onSelect, config = {}) {
    return new FilterDropdown(input, onSelect, config);
}
