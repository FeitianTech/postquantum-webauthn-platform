const MDS_HTML_PATH = 'mds.html';
const MDS_JWS_PATH = 'fido-mds3.jws';
const COLUMN_COUNT = 11;

const CERTIFICATION_OPTIONS = [
    'FIDO_CERTIFIED',
    'FIDO_CERTIFIED_L1',
    'FIDO_CERTIFIED_L2',
    'NOT_FIDO_CERTIFIED',
    'REVOKED',
];

const FILTER_CONFIG = [
    { key: 'name', inputId: 'mds-filter-name' },
    { key: 'protocol', inputId: 'mds-filter-protocol', optionsKey: 'protocol' },
    {
        key: 'certification',
        inputId: 'mds-filter-certification',
        optionsKey: 'certification',
        staticOptions: CERTIFICATION_OPTIONS,
    },
    { key: 'id', inputId: 'mds-filter-id' },
    {
        key: 'userVerification',
        inputId: 'mds-filter-user-verification',
        optionsKey: 'userVerification',
        expandDropdown: true,
    },
    { key: 'attachment', inputId: 'mds-filter-attachment', optionsKey: 'attachment' },
    { key: 'transports', inputId: 'mds-filter-transports', optionsKey: 'transports' },
    { key: 'keyProtection', inputId: 'mds-filter-key-protection', optionsKey: 'keyProtection' },
    {
        key: 'algorithms',
        inputId: 'mds-filter-algorithms',
        optionsKey: 'algorithms',
        expandDropdown: true,
    },
];

const FILTER_LOOKUP = FILTER_CONFIG.reduce((map, config) => {
    map[config.key] = config;
    return map;
}, {});

let activeDropdown = null;

class FilterDropdown {
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

function createFilterDropdown(input, onSelect, config = {}) {
    return new FilterDropdown(input, onSelect, config);
}

let mdsState = null;
let mdsData = [];
let filteredData = [];
let isLoading = false;
let hasLoaded = false;
let isUpdatingMetadata = false;

document.addEventListener('DOMContentLoaded', async () => {
    const tabElement = document.getElementById('mds-tab');
    if (!tabElement) {
        return;
    }

    try {
        const response = await fetch(MDS_HTML_PATH, { cache: 'no-store' });
        if (!response.ok) {
            throw new Error(`Unable to load ${MDS_HTML_PATH}`);
        }
        const markup = await response.text();
        tabElement.innerHTML = markup;
        mdsState = initializeState(tabElement);
    } catch (error) {
        console.error('Failed to initialise the FIDO MDS tab:', error);
        tabElement.innerHTML = `
            <div class="section mds-section">
                <div class="mds-status mds-status-error">Unable to load authenticator explorer. Check the console for details.</div>
            </div>`;
        return;
    }

    if (tabElement.classList.contains('active')) {
        void loadMdsData();
    }
});

document.addEventListener('tab:changed', event => {
    if (event?.detail?.tab === 'mds') {
        void loadMdsData();
    }
});

function initializeState(root) {
    const statusEl = root.querySelector('#mds-status');
    let defaultStatus = null;
    if (statusEl) {
        let variant = 'info';
        if (statusEl.classList.contains('mds-status-success')) {
            variant = 'success';
        } else if (statusEl.classList.contains('mds-status-error')) {
            variant = 'error';
        }
        defaultStatus = {
            html: statusEl.innerHTML,
            variant,
            title: statusEl.getAttribute('title') || '',
        };
    }

    const filters = {};
    const filterInputs = {};

    FILTER_CONFIG.forEach(config => {
        const input = root.querySelector(`#${config.inputId}`);
        if (input) {
            filters[config.key] = '';
            filterInputs[config.key] = input;
        }
    });

    const updateFilter = (key, rawValue) => {
        if (!mdsState) {
            return;
        }
        const value = rawValue.trim();
        if (filters[key] === value) {
            return;
        }
        filters[key] = value;
        applyFilters();
    };

    const dropdowns = {};

    Object.entries(filterInputs).forEach(([key, input]) => {
        input.addEventListener('keydown', event => {
            if (event.key === 'Enter') {
                updateFilter(key, event.target.value);
            }
            if (event.key === 'Escape') {
                event.target.value = '';
                updateFilter(key, '');
            }
        });

        input.addEventListener('change', event => {
            updateFilter(key, event.target.value);
        });

        input.addEventListener('input', event => {
            if (!event.target.value.trim() && filters[key]) {
                updateFilter(key, '');
            }
        });

        const config = FILTER_LOOKUP[key];
        if (config?.optionsKey) {
            const dropdown = createFilterDropdown(input, value => updateFilter(key, value), config);
            dropdowns[key] = dropdown;
            if (Array.isArray(config.staticOptions)) {
                const initialOptions = config.staticOptions
                    .map(option => formatEnum(option))
                    .filter(Boolean);
                dropdown.setOptions(initialOptions);
            }
        }
    });

    const updateButton = root.querySelector('#mds-update-button');
    if (updateButton) {
        updateButton.addEventListener('click', () => {
            void refreshMetadata();
        });
    }

    return {
        root,
        filters,
        filterInputs,
        dropdowns,
        table: root.querySelector('.mds-table'),
        tableBody: root.querySelector('#mds-table-body'),
        countEl: root.querySelector('#mds-entry-count'),
        totalEl: root.querySelector('#mds-total-count'),
        statusEl,
        defaultStatus,
        statusResetTimer: null,
        columnWidths: null,
        columnWidthAttempts: 0,
        updateButton,
    };
}

async function loadMdsData(statusNote) {
    if (isLoading || hasLoaded || !mdsState) {
        return;
    }

    const note = typeof statusNote === 'string' ? statusNote.trim() : '';
    isLoading = true;
    setStatus('Loading metadata BLOB…', 'info');

    try {
        const response = await fetch(MDS_JWS_PATH, { cache: 'no-store' });
        if (!response.ok) {
            if (response.status === 404) {
                setStatus(
                    `Metadata file not found. Download the latest BLOB from ` +
                        `<a href="https://mds3.fidoalliance.org/" target="_blank" rel="noopener">mds3.fidoalliance.org</a> ` +
                        `and save it as <code>${MDS_JWS_PATH}</code> in this directory.`,
                    'error',
                );
                return;
            }
            throw new Error(`Unexpected response status: ${response.status}`);
        }

        const jws = await response.text();
        const payloadSegment = jws.split('.')[1];
        if (!payloadSegment) {
            throw new Error('Invalid metadata BLOB format.');
        }

        const payload = decodeBase64Url(payloadSegment);
        const metadata = JSON.parse(payload);

        mdsData = Array.isArray(metadata.entries)
            ? metadata.entries.map(transformEntry).filter(Boolean)
            : [];
        hasLoaded = true;

        const optionSets = collectOptionSets(mdsData);
        updateOptionLists(optionSets);
        applyFilters();

        const nextUpdate = metadata.nextUpdate ? `Next update: ${formatDate(metadata.nextUpdate)}` : '';
        const statusParts = [`Loaded ${mdsData.length.toLocaleString()} authenticators.`];
        if (nextUpdate) {
            statusParts.push(nextUpdate);
        }
        if (note) {
            statusParts.push(note);
        }
        setStatus(statusParts.join(' '), 'success');

        if (metadata.legalHeader && mdsState.statusEl) {
            mdsState.statusEl.setAttribute('title', metadata.legalHeader);
            if (mdsState.defaultStatus) {
                mdsState.defaultStatus.title = metadata.legalHeader;
            }
        }
    } catch (error) {
        console.error('Failed to load FIDO MDS metadata:', error);
        setStatus(
            `Unable to parse the metadata BLOB. Confirm that <code>${MDS_JWS_PATH}</code> is a valid download from ` +
                `<a href="https://mds3.fidoalliance.org/" target="_blank" rel="noopener">mds3.fidoalliance.org</a>.`,
            'error',
        );
    } finally {
        isLoading = false;
    }
}

function applyFilters() {
    if (!mdsState) {
        return;
    }

    const activeFilters = mdsState.filters;
    filteredData = mdsData.filter(entry => matchesFilters(entry, activeFilters));
    renderTable(filteredData);
    updateCount(filteredData.length, mdsData.length);
}

function matchesFilters(entry, filters) {
    return Object.entries(filters).every(([key, value]) => {
        if (!value) {
            return true;
        }
        const query = value.toLowerCase();
        if (key === 'certification') {
            const canonicalQuery = normaliseEnumKey(value);
            const dropdown = mdsState?.dropdowns?.certification;
            const options = dropdown?.options || [];
            const isKnownOption = Boolean(canonicalQuery) && options.some(option => normaliseEnumKey(option) === canonicalQuery);

            if (isKnownOption && canonicalQuery) {
                const statusKey = normaliseEnumKey(entry.certificationStatus);
                if (canonicalQuery === 'FIDO_CERTIFIED') {
                    if (statusKey) {
                        return statusKey.startsWith('FIDO_CERTIFIED');
                    }
                    const displayKey = normaliseEnumKey((entry.certification || '').split('•')[0]);
                    return displayKey.startsWith('FIDO_CERTIFIED');
                }
                if (statusKey) {
                    return statusKey === canonicalQuery;
                }
                const displayKey = normaliseEnumKey((entry.certification || '').split('•')[0]);
                return displayKey === canonicalQuery;
            }

            const haystacks = [entry.certification, entry.certificationStatus]
                .map(text => (text || '').toLowerCase())
                .filter(Boolean);
            return haystacks.some(text => text.includes(query));
        }
        const haystack = (entry[key] || '').toLowerCase();
        return haystack.includes(query);
    });
}

function renderTable(entries) {
    if (!mdsState?.tableBody) {
        return;
    }

    const tbody = mdsState.tableBody;
    tbody.innerHTML = '';

    if (!entries.length) {
        const emptyRow = document.createElement('tr');
        emptyRow.className = 'mds-empty-row';
        const cell = document.createElement('td');
        cell.colSpan = COLUMN_COUNT;
        cell.textContent = 'No authenticators match the selected filters.';
        emptyRow.appendChild(cell);
        tbody.appendChild(emptyRow);
        stabiliseColumnWidths();
        return;
    }

    const fragment = document.createDocumentFragment();

    entries.forEach(entry => {
        const row = document.createElement('tr');

        row.appendChild(createIconCell(entry));
        row.appendChild(createTextCell(entry.name || '—'));
        row.appendChild(createTextCell(entry.protocol || '—'));
        row.appendChild(createTextCell(entry.certification || '—'));
        row.appendChild(createIdCell(entry.id));
        row.appendChild(createTagCell(entry.userVerificationList));
        row.appendChild(createTagCell(entry.attachmentList));
        row.appendChild(createTagCell(entry.transportsList));
        row.appendChild(createTagCell(entry.keyProtectionList));
        row.appendChild(createTagCell(entry.algorithmsList));
        row.appendChild(createTextCell(entry.dateUpdated || '—', entry.dateTooltip));

        fragment.appendChild(row);
    });

    tbody.appendChild(fragment);
    stabiliseColumnWidths();
}

function stabiliseColumnWidths() {
    if (!mdsState?.table) {
        return;
    }
    if (mdsState.root instanceof HTMLElement && mdsState.root.offsetParent === null) {
        return;
    }
    if (!Array.isArray(mdsState.columnWidths) || !mdsState.columnWidths.length) {
        requestAnimationFrame(() => {
            if (!mdsState?.table) {
                return;
            }
            const headerCells = mdsState.table.querySelectorAll('thead tr:first-child th');
            if (!headerCells.length) {
                return;
            }
            const widths = Array.from(headerCells).map(cell => Math.round(cell.getBoundingClientRect().width));
            if (!widths.length || widths.some(width => width === 0)) {
                if (mdsState) {
                    mdsState.columnWidthAttempts = (mdsState.columnWidthAttempts || 0) + 1;
                    if (mdsState.columnWidthAttempts < 5) {
                        requestAnimationFrame(stabiliseColumnWidths);
                    }
                }
                return;
            }
            mdsState.columnWidths = widths;
            mdsState.columnWidthAttempts = 0;
            applyColumnWidths(widths);
        });
        return;
    }
    applyColumnWidths(mdsState.columnWidths);
}

function applyColumnWidths(widths) {
    if (!mdsState?.table || !Array.isArray(widths) || !widths.length) {
        return;
    }

    mdsState.table.style.tableLayout = 'fixed';

    const tableHead = mdsState.table.tHead;
    if (tableHead) {
        Array.from(tableHead.rows).forEach(row => applyWidthsToCells(row.cells, widths));
    }

    if (mdsState.tableBody) {
        Array.from(mdsState.tableBody.rows).forEach(row => applyWidthsToCells(row.cells, widths));
    }
}

function applyWidthsToCells(cells, widths) {
    if (!cells || !widths) {
        return;
    }

    let columnIndex = 0;
    Array.from(cells).forEach(cell => {
        const span = cell.colSpan || 1;
        if (span === 1) {
            const width = widths[columnIndex];
            if (width && Number.isFinite(width)) {
                const widthPx = `${width}px`;
                cell.style.width = widthPx;
                cell.style.minWidth = widthPx;
                cell.style.maxWidth = widthPx;
            }
        }
        columnIndex += span;
    });
}

function createTextCell(text, title) {
    const cell = document.createElement('td');
    cell.textContent = text;
    if (title) {
        cell.title = title;
    }
    return cell;
}

function createIdCell(id) {
    const cell = createTextCell(id || '—');
    cell.classList.add('mds-cell-id');
    return cell;
}

function createIconCell(entry) {
    const cell = document.createElement('td');
    const wrapper = document.createElement('div');
    wrapper.className = 'mds-icon-wrapper';

    if (entry.icon) {
        const img = document.createElement('img');
        img.src = entry.icon;
        img.alt = `${entry.name || 'Authenticator'} icon`;
        wrapper.appendChild(img);
    } else {
        const placeholder = document.createElement('span');
        placeholder.className = 'mds-icon-placeholder';
        placeholder.textContent = 'N/A';
        wrapper.appendChild(placeholder);
    }

    cell.appendChild(wrapper);
    return cell;
}

function createTagCell(items, neutral = false) {
    const cell = document.createElement('td');
    const values = Array.isArray(items) ? items : [];

    if (!values.length) {
        cell.textContent = '—';
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

function updateCount(filtered, total) {
    if (mdsState?.countEl) {
        mdsState.countEl.textContent = filtered.toLocaleString();
    }
    if (mdsState?.totalEl) {
        mdsState.totalEl.textContent = total ? `of ${total.toLocaleString()} total` : '';
    }
}

function setStatus(message, variant, options = {}) {
    if (!mdsState?.statusEl) {
        return;
    }

    const statusEl = mdsState.statusEl;
    const { restoreDefault = false, delay = 5000 } = options;

    if (mdsState.statusResetTimer) {
        window.clearTimeout(mdsState.statusResetTimer);
        mdsState.statusResetTimer = null;
    }

    statusEl.classList.remove('mds-status-info', 'mds-status-success', 'mds-status-error');
    statusEl.classList.add(`mds-status-${variant}`);
    statusEl.innerHTML = message;

    if (restoreDefault && mdsState.defaultStatus) {
        const timeout = Number.isFinite(delay) ? Math.max(0, delay) : 5000;
        mdsState.statusResetTimer = window.setTimeout(() => {
            if (!mdsState?.statusEl || !mdsState?.defaultStatus) {
                return;
            }
            const target = mdsState.statusEl;
            const defaults = mdsState.defaultStatus;
            target.classList.remove('mds-status-info', 'mds-status-success', 'mds-status-error');
            target.classList.add(`mds-status-${defaults.variant}`);
            target.innerHTML = defaults.html;
            if (defaults.title) {
                target.setAttribute('title', defaults.title);
            } else {
                target.removeAttribute('title');
            }
            mdsState.statusResetTimer = null;
        }, timeout);
    }
}

function setUpdateButtonBusy(isBusy) {
    const button = mdsState?.updateButton;
    if (!button) {
        return;
    }

    if (isBusy) {
        if (!button.dataset.originalLabel) {
            button.dataset.originalLabel = button.textContent || '';
        }
        button.disabled = true;
        button.classList.add('is-busy');
        button.setAttribute('aria-busy', 'true');
        button.textContent = 'Updating…';
        return;
    }

    const originalLabel = button.dataset.originalLabel;
    button.disabled = false;
    button.classList.remove('is-busy');
    button.removeAttribute('aria-busy');
    if (typeof originalLabel === 'string') {
        button.textContent = originalLabel;
        delete button.dataset.originalLabel;
    }
    button.blur();
}

async function refreshMetadata() {
    if (isUpdatingMetadata || !mdsState?.updateButton) {
        return;
    }

    if (isLoading) {
        setStatus(
            'Metadata is currently loading. Please wait for the current operation to finish before requesting another update.',
            'info',
        );
        return;
    }

    isUpdatingMetadata = true;
    setUpdateButtonBusy(true);

    try {
        setStatus('Updating metadata BLOB…', 'info');

        const response = await fetch('/api/mds/update', {
            method: 'POST',
            headers: { Accept: 'application/json' },
            cache: 'no-store',
        });

        let payload = null;
        try {
            payload = await response.json();
        } catch (error) {
            payload = null;
        }

        if (!response.ok) {
            const message =
                (payload && typeof payload.message === 'string' && payload.message.trim()) ||
                `Update request failed with status ${response.status}.`;
            throw new Error(message);
        }

        const note =
            (payload && typeof payload.message === 'string' && payload.message.trim()) || '';
        const shouldReload = (payload && payload.updated) || !hasLoaded;

        if (shouldReload) {
            hasLoaded = false;
            await loadMdsData(note);
        } else {
            const message = note || 'Metadata already up to date.';
            setStatus(message, 'info', { restoreDefault: true, delay: 5000 });
        }
    } catch (error) {
        console.error('Failed to update metadata BLOB:', error);
        const message =
            error instanceof Error && error.message
                ? error.message
                : 'Unable to update the metadata BLOB. Check the server logs for more details.';
        setStatus(message, 'error');
    } finally {
        setUpdateButtonBusy(false);
        isUpdatingMetadata = false;
    }
}

function collectOptionSets(data) {
    const sets = {
        protocol: new Set(),
        certification: new Set(CERTIFICATION_OPTIONS.map(option => formatEnum(option))),
        userVerification: new Set(),
        attachment: new Set(),
        transports: new Set(),
        keyProtection: new Set(),
        algorithms: new Set(),
    };

    data.forEach(entry => {
        if (entry.protocol) {
            sets.protocol.add(entry.protocol);
        }
        if (entry.certificationStatus) {
            sets.certification.add(formatEnum(entry.certificationStatus));
        }
        entry.userVerificationList.forEach(value => sets.userVerification.add(value));
        entry.attachmentList.forEach(value => sets.attachment.add(value));
        entry.transportsList.forEach(value => sets.transports.add(value));
        entry.keyProtectionList.forEach(value => sets.keyProtection.add(value));
        entry.algorithmsList.forEach(value => sets.algorithms.add(value));
    });

    return sets;
}

function updateOptionLists(optionSets) {
    if (!mdsState) {
        return;
    }

    Object.entries(optionSets).forEach(([key, values]) => {
        const dropdown = mdsState.dropdowns[key];
        if (!dropdown) {
            return;
        }
        const config = FILTER_LOOKUP[key];
        const optionList = Array.from(values).filter(Boolean);
        if (config?.staticOptions) {
            const staticValues = config.staticOptions
                .map(option => formatEnum(option))
                .filter(Boolean);
            optionList.push(...staticValues);
        }
        const unique = Array.from(new Set(optionList));
        dropdown.setOptions(unique);
    });
}

function transformEntry(entry) {
    const metadata = entry?.metadataStatement ?? {};
    const name = resolveName(metadata, entry);
    const protocol = formatProtocol(metadata.protocolFamily || metadata.protocolType);
    const { display: certification, status: certificationStatus } = formatCertification(entry?.statusReports || []);
    const identifier = resolveIdentifier(entry, metadata);
    const userVerificationList = extractUserVerification(metadata.userVerificationDetails);
    const attachmentList = extractList(metadata.attachmentHint).map(formatEnum);
    const transportsList = extractTransports(metadata);
    const keyProtectionList = extractList(metadata.keyProtection).map(formatEnum);
    const algorithmsList = extractList(metadata.authenticationAlgorithms).map(formatEnum);
    const icon = normaliseIcon(metadata.icon, metadata.iconType);

    const latestStatusDate = latestEffectiveDate(entry?.statusReports || []);
    const rawDate = entry?.timeOfLastStatusChange || latestStatusDate;
    const dateUpdated = rawDate ? formatDate(rawDate) : '';

    return {
        name,
        protocol,
        certification,
        certificationStatus,
        id: identifier,
        icon,
        userVerification: userVerificationList.join(', '),
        userVerificationList,
        attachment: attachmentList.join(', '),
        attachmentList,
        transports: transportsList.join(', '),
        transportsList,
        keyProtection: keyProtectionList.join(', '),
        keyProtectionList,
        algorithms: algorithmsList.join(', '),
        algorithmsList,
        dateUpdated,
        dateTooltip: rawDate || undefined,
    };
}

function normaliseIcon(icon, iconType) {
    if (!icon) {
        return '';
    }
    const value = String(icon).trim();
    if (!value) {
        return '';
    }
    if (/^data:/i.test(value)) {
        return value;
    }
    if (/^https?:\/\//i.test(value)) {
        return value;
    }
    const type = typeof iconType === 'string' && iconType.trim() ? iconType.trim() : 'image/png';
    return `data:${type};base64,${value}`;
}

function resolveName(metadata, entry) {
    const description = metadata.description;
    if (typeof description === 'string' && description.trim()) {
        return description.trim();
    }
    if (description && typeof description === 'object') {
        const values = Object.values(description).filter(Boolean);
        if (values.length) {
            return String(values[0]).trim();
        }
    }
    const altDescriptions = metadata.alternativeDescriptions;
    if (altDescriptions) {
        const altValues = typeof altDescriptions === 'object' ? Object.values(altDescriptions) : [];
        const candidate = altValues.find(value => typeof value === 'string' && value.trim());
        if (candidate) {
            return candidate.trim();
        }
    }
    const statusDescriptor = entry?.statusReports?.find(report => report.certificationDescriptor)?.certificationDescriptor;
    if (statusDescriptor) {
        return statusDescriptor;
    }
    return 'Unknown Authenticator';
}

function resolveIdentifier(entry, metadata) {
    if (entry?.aaguid) {
        return entry.aaguid;
    }
    if (metadata?.aaguid) {
        return metadata.aaguid;
    }
    if (metadata?.aaid) {
        return metadata.aaid;
    }
    const attestKeyIds = extractList(metadata?.attestationCertificateKeyIdentifiers);
    if (attestKeyIds.length) {
        return attestKeyIds[0];
    }
    return '—';
}

function extractUserVerification(details) {
    const values = new Set();
    if (Array.isArray(details)) {
        details.forEach(group => {
            if (Array.isArray(group)) {
                group.forEach(entry => {
                    if (entry && entry.userVerificationMethod) {
                        values.add(formatEnum(entry.userVerificationMethod));
                    }
                });
            }
        });
    }
    return Array.from(values).sort((a, b) => a.localeCompare(b));
}

function extractTransports(metadata) {
    const infoTransports = extractList(metadata?.authenticatorGetInfo?.transports);
    const metadataTransports = extractList(metadata?.transports);
    const combined = new Set([
        ...infoTransports.map(formatEnum),
        ...metadataTransports.map(formatEnum),
    ]);
    return Array.from(combined).sort((a, b) => a.localeCompare(b));
}

function extractList(value) {
    if (!value) {
        return [];
    }
    if (Array.isArray(value)) {
        return value.filter(Boolean);
    }
    return [value];
}

function formatProtocol(protocol) {
    if (!protocol) {
        return '';
    }
    const normalised = formatEnum(protocol);
    const compact = normalised.replace(/\s+/g, '');
    if (/^fido\d$/i.test(compact)) {
        return compact.toUpperCase();
    }
    return normalised;
}

function normaliseEnumKey(value) {
    if (value === undefined || value === null) {
        return '';
    }
    return String(value)
        .trim()
        .toUpperCase()
        .replace(/[^A-Z0-9]+/g, '_')
        .replace(/^_+|_+$/g, '');
}

function formatEnum(value) {
    if (!value && value !== 0) {
        return '';
    }
    return String(value)
        .split(/[_-]/)
        .map(part => part.trim())
        .filter(Boolean)
        .map(part => {
            if (/^[A-Z0-9]+$/.test(part)) {
                if (part.length <= 4) {
                    return part;
                }
                const lower = part.toLowerCase();
                return lower.charAt(0).toUpperCase() + lower.slice(1);
            }
            if (/^.*\d.*$/.test(part)) {
                return part.toUpperCase();
            }
            const lower = part.toLowerCase();
            return lower.charAt(0).toUpperCase() + lower.slice(1);
        })
        .join(' ');
}

function formatCertification(statusReports) {
    if (!Array.isArray(statusReports) || !statusReports.length) {
        return { display: '', status: '' };
    }

    const sorted = [...statusReports].sort((a, b) => {
        const dateA = Date.parse(a.effectiveDate || '') || 0;
        const dateB = Date.parse(b.effectiveDate || '') || 0;
        return dateB - dateA;
    });

    const latest = sorted[0];
    if (!latest) {
        return { display: '', status: '' };
    }

    const statusRaw = typeof latest.status === 'string' ? latest.status.trim() : '';
    const statusValue = statusRaw ? statusRaw.toUpperCase() : '';
    const descriptor = typeof latest.certificationDescriptor === 'string' ? latest.certificationDescriptor.trim() : '';
    const certificateNumber = typeof latest.certificateNumber === 'string' ? latest.certificateNumber.trim() : '';

    const parts = [];
    const statusDisplay = statusValue ? formatEnum(statusValue) : '';
    if (statusDisplay) {
        parts.push(statusDisplay);
    }
    if (descriptor) {
        parts.push(descriptor);
    }
    if (certificateNumber) {
        parts.push(`(${certificateNumber})`);
    }

    return {
        display: parts.filter(Boolean).join(' • '),
        status: statusValue,
    };
}

function latestEffectiveDate(statusReports) {
    if (!Array.isArray(statusReports) || !statusReports.length) {
        return '';
    }
    const sorted = [...statusReports].sort((a, b) => {
        const dateA = Date.parse(a.effectiveDate || '') || 0;
        const dateB = Date.parse(b.effectiveDate || '') || 0;
        return dateB - dateA;
    });
    return sorted[0]?.effectiveDate || '';
}

function formatDate(value) {
    if (!value) {
        return '';
    }
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) {
        return value;
    }
    return new Intl.DateTimeFormat(undefined, {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
    }).format(date);
}

function decodeBase64Url(value) {
    let base64 = value.replace(/-/g, '+').replace(/_/g, '/');
    const padding = base64.length % 4;
    if (padding) {
        base64 += '='.repeat(4 - padding);
    }
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i += 1) {
        bytes[i] = binary.charCodeAt(i);
    }
    return new TextDecoder().decode(bytes);
}
