import {
    MDS_HTML_PATH,
    MDS_JWS_PATH,
    COLUMN_COUNT,
    MISSING_METADATA_MESSAGE,
    UPDATE_BUTTON_STATES,
    FILTER_CONFIG,
    FILTER_LOOKUP,
} from './mds-constants.js';
import { createFilterDropdown } from './mds-dropdown.js';
import {
    collectOptionSets,
    transformEntry,
    parseIsoDate,
    formatDate,
    decodeBase64Url,
    formatEnum,
    normaliseEnumKey,
    normaliseAaguid,
    formatListValues,
    formatDetailValue,
    formatAuthenticatorAlgorithms,
    formatGuidCandidate,
    formatUpv,
    extractList,
    renderCertificateSummary,
} from './mds-utils.js';

let mdsState = null;
let mdsData = [];
let filteredData = [];
let isLoading = false;
let hasLoaded = false;
let isUpdatingMetadata = false;
let loadPromise = null;
const certificateCache = new Map();
let scrollTopButtonUpdateScheduled = false;
let columnResizerMetricsScheduled = false;
let rowHeightLockScheduled = false;

const METADATA_CACHE_STORAGE_KEY = 'fido2.mds.metadata';

const SORT_NONE = 'none';
const SORT_ASCENDING = 'asc';
const SORT_DESCENDING = 'desc';

const SORT_SEQUENCE = {
    [SORT_NONE]: SORT_ASCENDING,
    [SORT_ASCENDING]: SORT_DESCENDING,
    [SORT_DESCENDING]: SORT_NONE,
};

const SORT_ACCESSORS = {
    icon: entry => {
        const name = typeof entry?.name === 'string' ? entry.name : '';
        return `${entry?.icon ? '1' : '0'}_${name}`;
    },
    name: entry => entry?.name || '',
    protocol: entry => entry?.protocol || '',
    certification: entry => entry?.certification || '',
    id: entry => entry?.id || '',
    userVerification: entry => entry?.userVerification || '',
    attachment: entry => entry?.attachment || '',
    transports: entry => entry?.transports || '',
    keyProtection: entry => entry?.keyProtection || '',
    algorithms: entry => entry?.algorithms || '',
    algorithmInfo: entry => entry?.algorithmInfo || entry?.certificateAlgorithmInfo || '',
    commonName: entry => entry?.commonName || entry?.certificateCommonNames || '',
    dateUpdated: entry => {
        if (entry?.dateTooltip) {
            const timestamp = Date.parse(entry.dateTooltip);
            if (!Number.isNaN(timestamp)) {
                return timestamp;
            }
            return entry.dateTooltip;
        }
        return entry?.dateUpdated || '';
    },
};

const DEFAULT_MIN_COLUMN_WIDTH = 64;

function getMetadataStorage() {
    if (typeof window === 'undefined' || !window.localStorage) {
        return null;
    }
    try {
        return window.localStorage;
    } catch (error) {
        console.warn('Unable to access localStorage for metadata caching:', error);
        return null;
    }
}

function clearMetadataCacheEntry() {
    const storage = getMetadataStorage();
    if (!storage) {
        return;
    }
    try {
        storage.removeItem(METADATA_CACHE_STORAGE_KEY);
    } catch (error) {
        console.warn('Unable to clear cached metadata BLOB:', error);
    }
}

function loadMetadataCacheEntry() {
    const storage = getMetadataStorage();
    if (!storage) {
        return null;
    }
    try {
        const raw = storage.getItem(METADATA_CACHE_STORAGE_KEY);
        if (!raw) {
            return null;
        }
        const parsed = JSON.parse(raw);
        if (!parsed || typeof parsed.jws !== 'string' || !parsed.jws.trim()) {
            return null;
        }
        const fetchedAt = typeof parsed.fetchedAt === 'string' ? parsed.fetchedAt : null;
        return {
            jws: parsed.jws,
            fetchedAt,
            nextUpdate: typeof parsed.nextUpdate === 'string' ? parsed.nextUpdate : null,
        };
    } catch (error) {
        console.warn('Unable to read cached metadata BLOB:', error);
        return null;
    }
}

function storeMetadataCacheEntry(entry) {
    const storage = getMetadataStorage();
    if (!storage || !entry || typeof entry.jws !== 'string') {
        return;
    }
    try {
        const payload = {
            jws: entry.jws,
            fetchedAt: new Date().toISOString(),
        };
        if (entry.nextUpdate) {
            payload.nextUpdate = entry.nextUpdate;
        }
        storage.setItem(METADATA_CACHE_STORAGE_KEY, JSON.stringify(payload));
    } catch (error) {
        console.warn('Unable to persist cached metadata BLOB:', error);
    }
}

function showElement(element) {
    if (!(element instanceof HTMLElement)) {
        return;
    }
    element.hidden = false;
    element.removeAttribute('hidden');
    element.setAttribute('aria-hidden', 'false');
}

function hideElement(element) {
    if (!(element instanceof HTMLElement)) {
        return;
    }
    element.hidden = true;
    element.setAttribute('hidden', '');
    element.setAttribute('aria-hidden', 'true');
}

function scheduleScrollTopButtonUpdate() {
    if (scrollTopButtonUpdateScheduled) {
        return;
    }
    scrollTopButtonUpdateScheduled = true;
    const apply = () => {
        scrollTopButtonUpdateScheduled = false;
        updateScrollTopButtonVisibility();
    };
    if (typeof requestAnimationFrame === 'function') {
        requestAnimationFrame(apply);
    } else {
        setTimeout(apply, 0);
    }
}

function scheduleColumnResizerMetricsUpdate() {
    if (columnResizerMetricsScheduled) {
        return;
    }
    columnResizerMetricsScheduled = true;
    const apply = () => {
        columnResizerMetricsScheduled = false;
        updateColumnResizerMetrics();
    };
    if (typeof requestAnimationFrame === 'function') {
        requestAnimationFrame(apply);
    } else {
        setTimeout(apply, 0);
    }
}

function scheduleRowHeightLock() {
    if (rowHeightLockScheduled) {
        return;
    }
    rowHeightLockScheduled = true;
    const apply = () => {
        rowHeightLockScheduled = false;
        lockRowHeights();
    };
    if (typeof requestAnimationFrame === 'function') {
        requestAnimationFrame(() => {
            if (typeof requestAnimationFrame === 'function') {
                requestAnimationFrame(apply);
            } else {
                setTimeout(apply, 0);
            }
        });
    } else {
        setTimeout(apply, 0);
    }
}

function lockRowHeights() {
    if (!mdsState?.tableBody) {
        return;
    }

    const rows = Array.from(mdsState.tableBody.rows ?? []).filter(row =>
        row instanceof HTMLTableRowElement && !row.classList.contains('mds-empty-row'),
    );

    rows.forEach(row => {
        if (!(row instanceof HTMLTableRowElement)) {
            return;
        }
        if (row.offsetParent === null) {
            return;
        }

        const stored = Number.parseInt(row.dataset.baseHeight || '', 10);
        let baseHeight = Number.isFinite(stored) && stored > 0 ? stored : null;

        if (!baseHeight) {
            const rect = typeof row.getBoundingClientRect === 'function' ? row.getBoundingClientRect() : null;
            const measured = rect && Number.isFinite(rect.height) ? Math.ceil(rect.height) : 0;
            if (!measured) {
                return;
            }
            baseHeight = measured;
            row.dataset.baseHeight = String(baseHeight);
        }

        applyRowHeightLock(row, baseHeight);
    });
}

function applyRowHeightLock(row, height) {
    if (!(row instanceof HTMLTableRowElement) || !Number.isFinite(height) || height <= 0) {
        return;
    }

    const heightPx = `${height}px`;
    row.style.height = heightPx;
    row.style.maxHeight = heightPx;
    row.style.minHeight = heightPx;

    Array.from(row.cells ?? []).forEach(cell => {
        if (!(cell instanceof HTMLTableCellElement)) {
            return;
        }
        cell.style.height = heightPx;
        cell.style.maxHeight = heightPx;
        cell.style.minHeight = heightPx;
        cell.style.overflow = 'hidden';
    });
}

function updateScrollTopButtonVisibility(options = {}) {
    if (!mdsState?.scrollTopButton) {
        return;
    }

    const { forceHidden = false } = options;
    if (forceHidden) {
        hideScrollTopButton();
        return;
    }

    if (!mdsState.root || mdsState.root.offsetParent === null) {
        hideScrollTopButton();
        return;
    }

    if (mdsState.tableContainer?.hidden) {
        hideScrollTopButton();
        return;
    }

    const rows = Array.from(mdsState.tableBody?.rows ?? []).filter(row => !row.classList.contains('mds-empty-row'));
    if (rows.length <= 5) {
        hideScrollTopButton();
        return;
    }

    const markerIndex = Math.min(4, rows.length - 1);
    const markerRow = rows[markerIndex];
    if (!markerRow || typeof markerRow.getBoundingClientRect !== 'function') {
        hideScrollTopButton();
        return;
    }

    const rowRect = markerRow.getBoundingClientRect();
    if (!rowRect || !Number.isFinite(rowRect.top)) {
        hideScrollTopButton();
        return;
    }

    const containerRect = mdsState.tableContainer?.getBoundingClientRect?.();
    const headerRect = mdsState.table?.tHead?.getBoundingClientRect?.();
    const boundaryCandidates = [0];
    if (containerRect && Number.isFinite(containerRect.top)) {
        boundaryCandidates.push(containerRect.top);
    }
    if (headerRect && Number.isFinite(headerRect.bottom)) {
        boundaryCandidates.push(headerRect.bottom);
    }
    const boundary = Math.max(...boundaryCandidates);
    const shouldShow = rowRect.top < boundary;

    if (shouldShow) {
        showScrollTopButton();
    } else {
        hideScrollTopButton();
    }
}

function showScrollTopButton() {
    if (!mdsState?.scrollTopButton) {
        return;
    }
    if (mdsState.scrollTopButtonVisible) {
        return;
    }
    mdsState.scrollTopButton.hidden = false;
    mdsState.scrollTopButton.setAttribute('aria-hidden', 'false');
    mdsState.scrollTopButtonVisible = true;
}

function hideScrollTopButton() {
    if (!mdsState?.scrollTopButton) {
        return;
    }
    if (mdsState.scrollTopButton.hidden) {
        mdsState.scrollTopButtonVisible = false;
        mdsState.scrollTopButton.setAttribute('aria-hidden', 'true');
        return;
    }
    mdsState.scrollTopButton.hidden = true;
    mdsState.scrollTopButton.setAttribute('aria-hidden', 'true');
    mdsState.scrollTopButtonVisible = false;
}

function scrollMdsSectionToTop() {
    if (!mdsState) {
        return;
    }

    const section = mdsState.root?.querySelector('.mds-section');
    if (section && typeof section.scrollIntoView === 'function') {
        section.scrollIntoView({ block: 'start', behavior: 'smooth' });
    } else if (mdsState.root && typeof mdsState.root.scrollIntoView === 'function') {
        mdsState.root.scrollIntoView({ block: 'start', behavior: 'smooth' });
    } else if (typeof window !== 'undefined' && typeof window.scrollTo === 'function') {
        window.scrollTo({ top: 0, left: 0, behavior: 'smooth' });
    }

    scheduleScrollTopButtonUpdate();
}

function handleWindowScroll() {
    scheduleScrollTopButtonUpdate();
    scheduleColumnResizerMetricsUpdate();
}

if (typeof window !== 'undefined') {
    window.addEventListener('scroll', handleWindowScroll, { passive: true });
    window.addEventListener('resize', handleWindowScroll);
}

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
        updateSortButtonState();
        setUpdateButtonMode('update');
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
            updateFilter(key, event.target.value);
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

    const tableContainer = root.querySelector('#mds-table-container');
    if (tableContainer) {
        tableContainer.addEventListener('scroll', () => scheduleScrollTopButtonUpdate());
    }
    const table = root.querySelector('.mds-table');
    const tableBody = root.querySelector('#mds-table-body');

    const sortButtons = new Map();
    root.querySelectorAll('.mds-sort-button[data-sort-key]').forEach(button => {
        const sortKey = button.dataset.sortKey;
        if (!sortKey) {
            return;
        }
        sortButtons.set(sortKey, button);
        button.addEventListener('click', () => handleSortButtonClick(sortKey));
        if (!button.hasAttribute('data-sort-direction')) {
            button.setAttribute('data-sort-direction', SORT_NONE);
        }
    });

    const scrollTopButton = root.querySelector('#mds-scroll-top-button');
    if (scrollTopButton) {
        scrollTopButton.addEventListener('click', event => {
            event.preventDefault();
            scrollMdsSectionToTop();
        });
        scrollTopButton.hidden = true;
        scrollTopButton.setAttribute('aria-hidden', 'true');
    }

    const updateButton = root.querySelector('#mds-update-button');
    if (updateButton) {
        updateButton.addEventListener('click', () => {
            void refreshMetadata();
        });
    }

    const certificateModal = root.querySelector('#mds-certificate-modal');
    const certificateClose = root.querySelector('#mds-certificate-modal-close');
    const certificateBody = root.querySelector('#mds-certificate-modal-body');
    const certificateSummary = root.querySelector('#mds-certificate-summary');
    if (certificateClose) {
        certificateClose.addEventListener('click', () => closeCertificateModal());
    }
    if (certificateModal) {
        certificateModal.addEventListener('click', event => {
            if (event.target === certificateModal) {
                closeCertificateModal();
            }
        });
    }

    const authenticatorModal = root.querySelector('#mds-authenticator-modal');
    const authenticatorClose = root.querySelector('#mds-authenticator-modal-close');
    if (authenticatorClose) {
        authenticatorClose.addEventListener('click', () => closeAuthenticatorModal());
    }
    if (authenticatorModal) {
        authenticatorModal.addEventListener('click', event => {
            if (event.target === authenticatorModal) {
                closeAuthenticatorModal();
            }
        });
    }

    const handleTabChanged = event => {
        if (event?.detail?.tab !== 'mds') {
            clearRowHighlight();
            hideScrollTopButton();
        } else {
            scheduleScrollTopButtonUpdate();
        }
    };
    if (typeof document !== 'undefined') {
        document.addEventListener('tab:changed', handleTabChanged);
    }

    const state = {
        root,
        filters,
        filterInputs,
        dropdowns,
        tableContainer,
        table,
        tableBody,
        sortButtons,
        sort: { key: '', direction: SORT_NONE },
        countEl: root.querySelector('#mds-entry-count'),
        totalEl: root.querySelector('#mds-total-count'),
        statusEl,
        defaultStatus,
        statusResetTimer: null,
        columnWidths: null,
        columnMinWidths: null,
        columnWidthAttempts: 0,
        columnResizers: [],
        columnResizeState: null,
        updateButton,
        updateButtonMode: 'update',
        metadataOverdue: false,
        metadataNextUpdate: null,
        certificateModal,
        certificateModalBody: certificateBody,
        certificateInput: root.querySelector('#mds-certificate-input'),
        certificateOutput: root.querySelector('#mds-certificate-output'),
        certificateTitle: root.querySelector('#mds-certificate-modal-title'),
        certificateSummary,
        authenticatorModal,
        authenticatorModalContent: root.querySelector('#mds-authenticator-modal-content'),
        authenticatorModalTitle: root.querySelector('#mds-authenticator-modal-title'),
        authenticatorModalSubtitle: root.querySelector('#mds-authenticator-modal-subtitle'),
        authenticatorModalBody: root.querySelector('#mds-authenticator-modal-body'),
        authenticatorModalClose: authenticatorClose,
        activeDetailEntry: null,
        highlightedRow: null,
        highlightedRowKey: '',
        tabChangeHandler: handleTabChanged,
        byAaguid: new Map(),
        scrollTopButton,
        scrollTopButtonVisible: false,
    };

    setupColumnResizers(state);
    return state;
}

async function loadMdsData(statusNote, options = {}) {
    if (!mdsState) {
        return;
    }

    if (hasLoaded) {
        return;
    }

    if (isLoading && loadPromise) {
        await loadPromise;
        return;
    }

    const { bypassCache = false } = typeof options === 'object' && options !== null ? options : {};
    const note = typeof statusNote === 'string' ? statusNote.trim() : '';

    if (!bypassCache) {
        const cachedEntry = loadMetadataCacheEntry();
        if (cachedEntry) {
            try {
                await applyMetadataJws(cachedEntry.jws, {
                    statusNote: note,
                    source: 'cache',
                    fetchedAt: cachedEntry.fetchedAt,
                });
                hasLoaded = true;
                return;
            } catch (error) {
                console.error('Failed to parse cached metadata BLOB:', error);
                clearMetadataCacheEntry();
            }
        }
    }

    setStatus('Loading metadata BLOB…', 'info');
    isLoading = true;

    const task = (async () => {
        try {
            const response = await fetch(MDS_JWS_PATH, { cache: 'no-store' });
            if (!response.ok) {
                if (response.status === 404) {
                    const message = MISSING_METADATA_MESSAGE;
                    setUpdateButtonMode('download');
                    setUpdateButtonAttention(false);
                    if (mdsState) {
                        mdsState.metadataOverdue = false;
                        mdsState.metadataNextUpdate = null;
                        mdsState.byAaguid = new Map();
                    }
                    setStatus(message, 'info');
                    if (mdsState) {
                        mdsState.defaultStatus = { html: message, variant: 'info', title: '' };
                    }
                    mdsData = [];
                    filteredData = [];
                    updateCount(0, 0);
                    if (mdsState?.tableBody) {
                        const tbody = mdsState.tableBody;
                        tbody.innerHTML = '';
                        const emptyRow = document.createElement('tr');
                        emptyRow.className = 'mds-empty-row';
                        const cell = document.createElement('td');
                        cell.colSpan = COLUMN_COUNT;
                        cell.textContent = MISSING_METADATA_MESSAGE;
                        emptyRow.appendChild(cell);
                        tbody.appendChild(emptyRow);
                    }
                    hideScrollTopButton();
                    resetSortState();
                    clearMetadataCacheEntry();
                    return;
                }
                throw new Error(`Unexpected response status: ${response.status}`);
            }

            const jws = await response.text();
            const result = await applyMetadataJws(jws, { statusNote: note });
            hasLoaded = true;
            storeMetadataCacheEntry({ jws, nextUpdate: result?.nextUpdate || null });
        } catch (error) {
            console.error('Failed to load FIDO MDS metadata:', error);
            setStatus(
                `Unable to parse the metadata BLOB. Confirm that <code>${MDS_JWS_PATH}</code> is a valid download from ` +
                    `<a href="https://mds3.fidoalliance.org/" target="_blank" rel="noopener">mds3.fidoalliance.org</a>.`,
                'error',
            );
            setUpdateButtonAttention(false);
            if (mdsState) {
                mdsState.metadataOverdue = false;
                mdsState.metadataNextUpdate = null;
            }
            clearMetadataCacheEntry();
        } finally {
            isLoading = false;
        }
    })();

    loadPromise = task;
    try {
        await task;
    } finally {
        if (loadPromise === task) {
            loadPromise = null;
        }
    }
}

async function applyMetadataJws(jws, options = {}) {
    if (!mdsState) {
        return { nextUpdate: null };
    }

    const { statusNote = '', source = 'network', fetchedAt = null } = typeof options === 'object' && options !== null ? options : {};

    const payloadSegment = jws.split('.')[1];
    if (!payloadSegment) {
        throw new Error('Invalid metadata BLOB format.');
    }

    const payload = decodeBase64Url(payloadSegment);
    const metadata = JSON.parse(payload);

    mdsData = Array.isArray(metadata.entries)
        ? metadata.entries.map((entry, index) => transformEntry(entry, index)).filter(Boolean)
        : [];
    setUpdateButtonMode('update');

    resetSortState();

    const map = new Map();
    mdsData.forEach(item => {
        const key = normaliseAaguid(item.aaguid || item.id);
        if (key) {
            map.set(key, item);
        }
    });
    mdsState.byAaguid = map;

    const nextUpdateRaw = typeof metadata.nextUpdate === 'string' ? metadata.nextUpdate : '';
    const nextUpdateDate = parseIsoDate(nextUpdateRaw);
    const nextUpdateFormatted = nextUpdateRaw ? formatDate(nextUpdateRaw) : '';
    const now = Date.now();
    const isOverdue = Boolean(nextUpdateDate && nextUpdateDate.getTime() <= now);

    mdsState.metadataOverdue = isOverdue;
    mdsState.metadataNextUpdate = nextUpdateRaw || null;
    setUpdateButtonAttention(isOverdue);

    const optionSets = collectOptionSets(mdsData);
    updateOptionLists(optionSets);

    certificateCache.clear();
    try {
        await populateCertificateDerivedInfo(mdsData);
    } catch (error) {
        console.error('Failed to derive attestation certificate details:', error);
    }

    applyFilters();

    const statusParts = [`Loaded ${mdsData.length.toLocaleString()} authenticators.`];
    let statusVariant = 'success';

    if (isOverdue) {
        const deadline = nextUpdateFormatted ? ` (${nextUpdateFormatted})` : '';
        statusParts.push(
            `The recommended metadata update date has passed${deadline}. Use the <strong>Update Metadata</strong> button to refresh the local file.`,
        );
        statusVariant = 'error';
    } else if (nextUpdateFormatted) {
        statusParts.push(`Next update recommended by ${nextUpdateFormatted}.`);
    }

    if (source === 'cache') {
        const fetchedDate = fetchedAt ? parseIsoDate(fetchedAt) : null;
        if (fetchedDate) {
            statusParts.push(`Using cached metadata from ${formatDate(fetchedAt)}.`);
        } else {
            statusParts.push('Using cached metadata.');
        }
    }

    if (statusNote) {
        statusParts.push(statusNote);
    }

    const statusMessage = statusParts.join(' ');
    setStatus(statusMessage, statusVariant);

    if (!mdsState.defaultStatus) {
        mdsState.defaultStatus = { html: statusMessage, variant: statusVariant, title: '' };
    } else {
        mdsState.defaultStatus.html = statusMessage;
        mdsState.defaultStatus.variant = statusVariant;
    }

    if (metadata.legalHeader && mdsState.statusEl) {
        mdsState.statusEl.setAttribute('title', metadata.legalHeader);
        if (mdsState.defaultStatus) {
            mdsState.defaultStatus.title = metadata.legalHeader;
        }
    } else if (mdsState?.statusEl) {
        mdsState.statusEl.removeAttribute('title');
        if (mdsState.defaultStatus) {
            mdsState.defaultStatus.title = '';
        }
    }

    return { nextUpdate: nextUpdateRaw || null };
}

function applyFilters() {
    if (!mdsState) {
        return;
    }

    const activeFilters = mdsState.filters;
    const matched = mdsData.filter(entry => matchesFilters(entry, activeFilters));
    const sorted = applySorting(matched);
    filteredData = sorted;
    renderTable(sorted);
    updateCount(sorted.length, mdsData.length);
    updateSortButtonState();
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

function applySorting(entries) {
    if (!Array.isArray(entries)) {
        return [];
    }
    if (!mdsState?.sort) {
        return entries.slice();
    }

    const { key, direction } = mdsState.sort;
    if (!key || direction === SORT_NONE) {
        return entries.slice();
    }

    const accessor = SORT_ACCESSORS[key];
    if (typeof accessor !== 'function') {
        return entries.slice();
    }

    const sorted = entries.slice().sort((a, b) => compareSortValues(a, b, accessor));
    if (direction === SORT_DESCENDING) {
        sorted.reverse();
    }
    return sorted;
}

function compareSortValues(entryA, entryB, accessor) {
    const valueA = accessor(entryA);
    const valueB = accessor(entryB);

    const normalisedA = normaliseSortValue(valueA);
    const normalisedB = normaliseSortValue(valueB);

    if (normalisedA < normalisedB) {
        return -1;
    }
    if (normalisedA > normalisedB) {
        return 1;
    }

    const fallbackA = String(valueA ?? '').toLowerCase();
    const fallbackB = String(valueB ?? '').toLowerCase();
    if (fallbackA < fallbackB) {
        return -1;
    }
    if (fallbackA > fallbackB) {
        return 1;
    }

    const originalA = String(valueA ?? '');
    const originalB = String(valueB ?? '');
    if (originalA < originalB) {
        return -1;
    }
    if (originalA > originalB) {
        return 1;
    }

    const indexA = typeof entryA?.index === 'number' ? entryA.index : 0;
    const indexB = typeof entryB?.index === 'number' ? entryB.index : 0;
    return indexA - indexB;
}

function normaliseSortValue(value) {
    if (value === undefined || value === null) {
        return '';
    }
    if (typeof value === 'number') {
        return value;
    }
    if (value instanceof Date) {
        return value.getTime();
    }

    const text = String(value).trim();
    if (!text || text === '—') {
        return '';
    }

    const numeric = Number(text);
    if (!Number.isNaN(numeric) && text !== '') {
        return numeric;
    }
    return text.toLowerCase();
}

function updateSortButtonState() {
    if (!mdsState?.sortButtons) {
        return;
    }

    const activeKey = mdsState.sort?.key || '';
    const direction = mdsState.sort?.direction || SORT_NONE;

    mdsState.sortButtons.forEach((button, key) => {
        const isActive = key === activeKey && direction !== SORT_NONE;
        const appliedDirection = isActive ? direction : SORT_NONE;
        button.setAttribute('data-sort-direction', appliedDirection);
        button.setAttribute('aria-pressed', isActive ? 'true' : 'false');

        const label = button.getAttribute('data-sort-label') || '';
        if (label) {
            let suffix = ' (no sorting)';
            if (appliedDirection === SORT_ASCENDING) {
                suffix = ' (ascending)';
            } else if (appliedDirection === SORT_DESCENDING) {
                suffix = ' (descending)';
            }
            button.setAttribute('aria-label', `Sort ${label}${suffix}`);
        }

        const headerCell = button.closest('th');
        if (headerCell) {
            headerCell.classList.toggle('mds-sort-active', isActive);
        }
    });
}

function resetSortState() {
    if (!mdsState) {
        return;
    }
    if (!mdsState.sort) {
        mdsState.sort = { key: '', direction: SORT_NONE };
    } else {
        mdsState.sort.key = '';
        mdsState.sort.direction = SORT_NONE;
    }
    updateSortButtonState();
}

function handleSortButtonClick(sortKey) {
    if (!mdsState) {
        return;
    }
    const key = typeof sortKey === 'string' ? sortKey : '';
    if (!key || !Object.prototype.hasOwnProperty.call(SORT_ACCESSORS, key)) {
        return;
    }

    if (!mdsState.sort) {
        mdsState.sort = { key: '', direction: SORT_NONE };
    }

    const currentKey = mdsState.sort.key;
    const currentDirection = mdsState.sort.direction || SORT_NONE;
    let nextDirection = SORT_ASCENDING;
    if (currentKey === key) {
        nextDirection = SORT_SEQUENCE[currentDirection] || SORT_ASCENDING;
    }

    if (nextDirection === SORT_NONE) {
        mdsState.sort.key = '';
        mdsState.sort.direction = SORT_NONE;
    } else {
        mdsState.sort.key = key;
        mdsState.sort.direction = nextDirection;
    }

    updateSortButtonState();
    applyFilters();
}

async function populateCertificateDerivedInfo(entries) {
    if (!Array.isArray(entries) || !entries.length) {
        return;
    }

    const seen = new Set();
    const certificates = [];

    entries.forEach(entry => {
        const list = Array.isArray(entry?.attestationCertificates) ? entry.attestationCertificates : [];
        list.forEach(certificate => {
            const cleaned = normaliseCertificateBase64(certificate);
            if (cleaned && !seen.has(cleaned)) {
                seen.add(cleaned);
                certificates.push(cleaned);
            }
        });
    });

    if (!certificates.length) {
        return;
    }

    const detailMap = new Map();

    const decodeTasks = certificates.map(certificate =>
        decodeCertificate(certificate)
            .then(details => ({ certificate, details, error: null }))
            .catch(error => ({ certificate, details: null, error })),
    );

    const decodedResults = await Promise.all(decodeTasks);
    decodedResults.forEach(result => {
        if (result.error) {
            console.error('Failed to decode attestation root certificate:', result.error);
        }
        detailMap.set(result.certificate, result.details);
    });

    entries.forEach(entry => {
        const algorithmSet = new Set();
        const algorithms = [];
        const commonNameSet = new Set();
        const commonNames = [];
        const list = Array.isArray(entry?.attestationCertificates) ? entry.attestationCertificates : [];

        list.forEach(certificate => {
            const cleaned = normaliseCertificateBase64(certificate);
            if (!cleaned) {
                return;
            }
            const details = detailMap.get(cleaned);
            if (!details || typeof details !== 'object') {
                return;
            }

            const algorithmInfo = typeof details.algorithmInfo === 'string' ? details.algorithmInfo.trim() : '';
            if (algorithmInfo && !algorithmSet.has(algorithmInfo)) {
                algorithmSet.add(algorithmInfo);
                algorithms.push(algorithmInfo);
            }

            const cnValues = Array.isArray(details.subjectCommonNames) ? details.subjectCommonNames : [];
            cnValues.forEach(name => {
                if (typeof name !== 'string') {
                    return;
                }
                const trimmed = name.trim();
                if (trimmed && !commonNameSet.has(trimmed)) {
                    commonNameSet.add(trimmed);
                    commonNames.push(trimmed);
                }
            });
        });

        entry.certificateAlgorithmInfoList = algorithms;
        entry.certificateAlgorithmInfo = algorithms.length ? algorithms.join(', ') : '—';
        entry.algorithmInfo = entry.certificateAlgorithmInfo;
        entry.certificateCommonNameList = commonNames;
        entry.certificateCommonNames = commonNames.length ? commonNames.join(', ') : '—';
        entry.commonName = entry.certificateCommonNames;
    });
}

function resetFilters() {
    if (!mdsState) {
        return;
    }

    let changed = false;
    Object.entries(mdsState.filters || {}).forEach(([key, value]) => {
        if (value) {
            mdsState.filters[key] = '';
            const input = mdsState.filterInputs[key];
            if (input) {
                input.value = '';
            }
            changed = true;
        }
    });

    if (changed || (!filteredData.length && mdsData.length)) {
        applyFilters();
    }
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
        hideScrollTopButton();
        stabiliseColumnWidths();
        scheduleColumnResizerMetricsUpdate();
        return;
    }

    const fragment = document.createDocumentFragment();

    entries.forEach(entry => {
        const row = document.createElement('tr');

        if (typeof entry.index === 'number' && Number.isFinite(entry.index)) {
            row.dataset.entryIndex = String(entry.index);
        }
        const aaguidKey = normaliseAaguid(entry.aaguid);
        if (aaguidKey) {
            row.dataset.aaguid = aaguidKey;
        } else if (entry.id) {
            const idKey = normaliseAaguid(entry.id);
            if (idKey) {
                row.dataset.aaguid = idKey;
            } else {
                row.dataset.entryId = entry.id;
            }
        }

        row.appendChild(createIconCell(entry));
        row.appendChild(createNameCell(entry));
        row.appendChild(createTextCell(entry.protocol || '—'));
        row.appendChild(createTextCell(entry.certification || '—'));
        row.appendChild(createIdCell(entry.id));
        row.appendChild(createTagCell(entry.userVerificationList));
        row.appendChild(createTagCell(entry.attachmentList));
        row.appendChild(createTagCell(entry.transportsList));
        row.appendChild(createTagCell(entry.keyProtectionList));
        row.appendChild(createTagCell(entry.algorithmsList));
        row.appendChild(createTagCell(entry.certificateAlgorithmInfoList));
        row.appendChild(createTagCell(entry.certificateCommonNameList));
        row.appendChild(createTextCell(entry.dateUpdated || '—', entry.dateTooltip));

        fragment.appendChild(row);
    });

    tbody.appendChild(fragment);
    if (mdsState.highlightedRowKey) {
        const restored = applyRowHighlightByKey(mdsState.highlightedRowKey, { scroll: false });
        if (!restored) {
            mdsState.highlightedRow = null;
        }
    }
    stabiliseColumnWidths();
    scheduleScrollTopButtonUpdate();
    scheduleColumnResizerMetricsUpdate();
    scheduleRowHeightLock();
}

function formatDetailSubtitle(entry) {
    if (!entry) {
        return '';
    }

    const parts = [];
    if (entry.aaguid) {
        parts.push(`AAGUID: ${entry.aaguid}`);
    }
    if (entry.id && entry.id !== entry.aaguid) {
        parts.push(`ID: ${entry.id}`);
    }
    if (entry.protocol) {
        parts.push(entry.protocol);
    }
    return parts.join(' • ');
}

function applyDetailHeader(entry, titleEl, subtitleEl) {
    if (titleEl) {
        titleEl.textContent = entry?.name?.trim() ? entry.name : 'Authenticator';
    }
    if (subtitleEl) {
        subtitleEl.textContent = formatDetailSubtitle(entry);
    }
}

function populateDetailContent(target, entry) {
    if (!target) {
        return;
    }
    target.innerHTML = '';
    const content = buildDetailContent(entry);
    if (content) {
        target.appendChild(content);
    }
}

function resetScrollPositions(...elements) {
    const apply = element => {
        if (!element) {
            return;
        }
        if (typeof element.scrollTo === 'function') {
            element.scrollTo({ top: 0, left: 0 });
            return;
        }
        if (typeof element.scrollTop === 'number') {
            element.scrollTop = 0;
        }
        if (typeof element.scrollLeft === 'number') {
            element.scrollLeft = 0;
        }
    };

    elements.forEach(apply);
    if (typeof requestAnimationFrame === 'function') {
        requestAnimationFrame(() => {
            elements.forEach(apply);
        });
    }
}

function notifyGlobalScrollLock() {
    if (typeof window !== 'undefined' && typeof window.updateGlobalScrollLock === 'function') {
        window.updateGlobalScrollLock();
        return;
    }

    if (typeof document === 'undefined') {
        return;
    }

    const overlayActive = document.getElementById('json-editor-overlay')?.classList.contains('active');
    const modalActive = document.querySelector('.modal.open');
    const mdsModalActive = document.querySelector('.mds-modal:not([hidden])');
    const shouldLock = Boolean(overlayActive || modalActive || mdsModalActive);

    const targets = [document.body, document.documentElement].filter(Boolean);
    targets.forEach(target => target.classList.toggle('modal-open', shouldLock));
}

function resizeCertificateTextareas() {
    if (!mdsState) {
        return;
    }

    const fields = [mdsState.certificateInput, mdsState.certificateOutput];
    fields.forEach(field => {
        if (!(field instanceof HTMLTextAreaElement)) {
            return;
        }
        field.style.height = 'auto';
        field.style.overflowY = 'hidden';
        field.style.overflowX = 'hidden';
        const { scrollHeight } = field;
        if (Number.isFinite(scrollHeight)) {
            field.style.height = `${scrollHeight}px`;
        }
    });
}

function scheduleCertificateTextareaResize() {
    const adjust = () => resizeCertificateTextareas();
    if (typeof requestAnimationFrame === 'function') {
        requestAnimationFrame(() => requestAnimationFrame(adjust));
    } else {
        setTimeout(adjust, 0);
    }
}

function resetCertificateTextareaHeights() {
    if (!mdsState) {
        return;
    }
    [mdsState.certificateInput, mdsState.certificateOutput].forEach(field => {
        if (field instanceof HTMLTextAreaElement) {
            field.style.height = '';
        }
    });
}

function clearRowHighlight() {
    if (!mdsState) {
        return;
    }
    if (mdsState.tableBody) {
        mdsState.tableBody.querySelectorAll('tr.mds-row--highlight').forEach(row => {
            row.classList.remove('mds-row--highlight');
        });
    }
    mdsState.highlightedRow = null;
    mdsState.highlightedRowKey = '';
}

function findRowByKey(key) {
    if (!mdsState?.tableBody || !key) {
        return null;
    }
    const normalised = key.toLowerCase();
    const rows = mdsState.tableBody.querySelectorAll('tr[data-aaguid]');
    for (const row of rows) {
        if ((row.dataset.aaguid || '').toLowerCase() === normalised) {
            return row;
        }
    }
    return null;
}

function applyRowHighlightByKey(key, options = {}) {
    if (!mdsState || !key) {
        return false;
    }

    const row = findRowByKey(key);
    if (!row) {
        return false;
    }

    if (mdsState.highlightedRow && mdsState.highlightedRow !== row) {
        mdsState.highlightedRow.classList.remove('mds-row--highlight');
    }

    if (!row.classList.contains('mds-row--highlight')) {
        row.classList.add('mds-row--highlight');
    }

    mdsState.highlightedRow = row;
    mdsState.highlightedRowKey = key;

    if (options.scroll && typeof row.scrollIntoView === 'function') {
        const behavior = options.behavior || 'smooth';
        row.scrollIntoView({ block: 'center', behavior });
    }

    scheduleScrollTopButtonUpdate();
    return true;
}

function scheduleRowHighlight(key, attempt = 0) {
    if (!mdsState || !key) {
        return;
    }

    if (mdsState.highlightedRowKey !== key) {
        return;
    }

    const behavior = attempt === 0 ? 'smooth' : 'auto';
    const applied = applyRowHighlightByKey(key, { scroll: true, behavior });
    if (applied) {
        return;
    }

    if (attempt >= 8) {
        return;
    }

    const schedule = () => scheduleRowHighlight(key, attempt + 1);
    if (typeof requestAnimationFrame === 'function') {
        requestAnimationFrame(schedule);
    } else {
        setTimeout(schedule, attempt < 4 ? 16 : 64);
    }
}

function showAuthenticatorDetail(entry, options = {}) {
    if (!mdsState || !entry) {
        return;
    }

    clearRowHighlight();

    const sourceEntry = typeof entry.index === 'number' && mdsData[entry.index]
        ? mdsData[entry.index]
        : entry;

    mdsState.activeDetailEntry = sourceEntry;

    const { scrollIntoView = true } = options;
    if (scrollIntoView) {
        const key = normaliseAaguid(sourceEntry.aaguid || sourceEntry.id);
        const row = key ? findRowByKey(key) : null;
        if (row && typeof row.scrollIntoView === 'function') {
            requestAnimationFrame(() => {
                row.scrollIntoView({ block: 'center', behavior: 'smooth' });
            });
        }
    }

    openAuthenticatorModal(sourceEntry);
}

function hideAuthenticatorDetail() {
    if (!mdsState) {
        return;
    }

    closeAuthenticatorModal();
}

function buildDetailContent(entry) {
    const fragment = document.createDocumentFragment();
    const metadata = entry?.metadataStatement ?? {};

    const overviewSection = createDetailSection('Overview');
    const overviewItems = [];
    overviewItems.push({ label: 'Identifier', value: entry.id || '—' });
    if (entry.aaguid) {
        overviewItems.push({ label: 'AAGUID', value: entry.aaguid });
    }
    if (entry.protocol) {
        overviewItems.push({ label: 'Protocol', value: entry.protocol });
    }
    if (entry.certification) {
        overviewItems.push({ label: 'Certification', value: entry.certification });
    }
    if (metadata.authenticatorVersion !== undefined && metadata.authenticatorVersion !== null) {
        overviewItems.push({ label: 'Authenticator Version', value: String(metadata.authenticatorVersion) });
    }
    if (entry.dateUpdated) {
        overviewItems.push({ label: 'Date Updated', value: entry.dateUpdated });
    }
    appendDetailGrid(overviewSection, overviewItems);
    fragment.appendChild(overviewSection);

    const metadataSection = createDetailSection('Metadata Statement');
    const metadataItems = [];
    if (metadata.description) {
        metadataItems.push({ label: 'Description', value: String(metadata.description) });
    }
    if (metadata.legalHeader) {
        metadataItems.push({ label: 'Legal Header', value: String(metadata.legalHeader) });
    }
    if (metadata.schema !== undefined && metadata.schema !== null) {
        metadataItems.push({ label: 'Schema', value: String(metadata.schema) });
    }
    if (metadata.cryptoStrength !== undefined && metadata.cryptoStrength !== null) {
        metadataItems.push({ label: 'Crypto Strength', value: String(metadata.cryptoStrength) });
    }
    const keyIdentifierNode = createCodeValueList(entry.attestationKeyIdentifiers);
    if (keyIdentifierNode) {
        metadataItems.push({ label: 'Attestation Certificate Key IDs', node: keyIdentifierNode });
    }
    const upvValues = formatUpv(metadata.upv);
    if (upvValues.length) {
        metadataItems.push({ label: 'UPV', value: upvValues.join(', ') });
    }
    appendDetailGrid(metadataSection, metadataItems);

    const algorithmChips = createChipList('Authentication Algorithms', formatListValues(metadata.authenticationAlgorithms));
    if (algorithmChips) {
        metadataSection.appendChild(algorithmChips);
    }
    const encodingChips = createChipList('Public Key Algorithms', formatListValues(metadata.publicKeyAlgAndEncodings));
    if (encodingChips) {
        metadataSection.appendChild(encodingChips);
    }
    const attestationChips = createChipList('Attestation Types', formatListValues(metadata.attestationTypes));
    if (attestationChips) {
        metadataSection.appendChild(attestationChips);
    }
    const keyProtectionChips = createChipList('Key Protection', formatListValues(metadata.keyProtection));
    if (keyProtectionChips) {
        metadataSection.appendChild(keyProtectionChips);
    }
    const matcherChips = createChipList('Matcher Protection', formatListValues(metadata.matcherProtection));
    if (matcherChips) {
        metadataSection.appendChild(matcherChips);
    }
    const attachmentChips = createChipList('Attachment Hints', formatListValues(metadata.attachmentHint));
    if (attachmentChips) {
        metadataSection.appendChild(attachmentChips);
    }
    const displayChips = createChipList('TC Display', formatListValues(metadata.tcDisplay));
    if (displayChips) {
        metadataSection.appendChild(displayChips);
    }
    fragment.appendChild(metadataSection);

    const userVerificationContent = renderUserVerificationDetails(metadata.userVerificationDetails);
    if (userVerificationContent) {
        const userSection = createDetailSection('User Verification Details');
        userSection.appendChild(userVerificationContent);
        fragment.appendChild(userSection);
    }

    const certificatesContent = renderAttestationCertificates(entry.attestationCertificates);
    if (certificatesContent) {
        const certificateSection = createDetailSection('Attestation Root Certificates');
        certificateSection.appendChild(certificatesContent);
        fragment.appendChild(certificateSection);
    }

    const authenticatorInfoSection = renderAuthenticatorInfo(metadata.authenticatorGetInfo);
    if (authenticatorInfoSection) {
        fragment.appendChild(authenticatorInfoSection);
    }

    const statusContent = renderStatusReports(entry.statusReports);
    if (statusContent) {
        const statusSection = createDetailSection('Status Reports');
        statusSection.appendChild(statusContent);
        fragment.appendChild(statusSection);
    }

    return fragment;
}

function createDetailSection(title) {
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

function appendDetailGrid(section, items) {
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

function createChipList(label, values) {
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

function createCodeValueList(values) {
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

function renderUserVerificationDetails(details) {
    const groups = Array.isArray(details) ? details : [];
    if (!groups.length) {
        return null;
    }

    const container = document.createElement('div');
    container.className = 'mds-detail-groups';

    groups.forEach((group, index) => {
        const entries = Array.isArray(group) ? group : [group];
        const validEntries = entries.filter(item => item && typeof item === 'object');
        if (!validEntries.length) {
            return;
        }

        const card = document.createElement('div');
        card.className = 'mds-detail-card';
        const title = document.createElement('div');
        title.className = 'mds-detail-card__title';
        title.textContent = `Combination ${index + 1}`;
        card.appendChild(title);

        const content = document.createElement('div');
        content.className = 'mds-detail-card__content';

        validEntries.forEach(item => {
            const method = item.userVerificationMethod ? formatEnum(item.userVerificationMethod) : '';
            if (method) {
                const methodEl = document.createElement('div');
                methodEl.textContent = method;
                content.appendChild(methodEl);
            }

            const caDesc = item.caDesc && typeof item.caDesc === 'object' ? item.caDesc : null;
            if (caDesc) {
                const parts = [];
                if (caDesc.base !== undefined) {
                    parts.push(`Base: ${caDesc.base}`);
                }
                if (caDesc.minLength !== undefined) {
                    parts.push(`Min length: ${caDesc.minLength}`);
                }
                if (caDesc.maxRetries !== undefined) {
                    parts.push(`Max retries: ${caDesc.maxRetries}`);
                }
                if (caDesc.blockSlowdown !== undefined) {
                    parts.push(`Block slowdown: ${caDesc.blockSlowdown}`);
                }
                if (parts.length) {
                    const info = document.createElement('small');
                    info.textContent = parts.join(' • ');
                    content.appendChild(info);
                }
            }
        });

        if (content.childElementCount) {
            card.appendChild(content);
            container.appendChild(card);
        }
    });

    return container.childElementCount ? container : null;
}

function renderAttestationCertificates(certificates) {
    const values = Array.isArray(certificates) ? certificates.filter(Boolean) : [];
    if (!values.length) {
        return null;
    }

    const container = document.createElement('div');
    container.className = 'mds-certificates';

    values.forEach((certificate, index) => {
        const button = document.createElement('button');
        button.type = 'button';
        button.className = 'mds-certificate-button';
        button.textContent = `Certificate ${index + 1}`;
        button.addEventListener('click', () => openCertificateModal(certificate));
        container.appendChild(button);
        void updateCertificateButtonLabel(button, certificate);
    });

    return container;
}

function renderAuthenticatorInfo(info) {
    if (!info || typeof info !== 'object') {
        return null;
    }

    const section = createDetailSection('Authenticator Get Info');
    const gridItems = [];

    if (info.aaguid) {
        gridItems.push({ label: 'AAGUID', value: formatGuidCandidate(info.aaguid) || String(info.aaguid) });
    }
    const numericKeys = [
        ['maxMsgSize', 'Max Message Size'],
        ['maxCredentialCountInList', 'Max Credential Count'],
        ['maxCredentialIdLength', 'Max Credential ID Length'],
        ['maxSerializedLargeBlobArray', 'Max Serialized Large Blob Array'],
        ['minPINLength', 'Min PIN Length'],
        ['firmwareVersion', 'Firmware Version'],
        ['maxCredBlobLength', 'Max Cred Blob Length'],
        ['maxRPIDsForSetMinPINLength', 'Max RP IDs for Set Min PIN Length'],
        ['remainingDiscoverableCredentials', 'Remaining Discoverable Credentials'],
    ];
    numericKeys.forEach(([key, label]) => {
        if (info[key] !== undefined && info[key] !== null) {
            gridItems.push({ label, value: String(info[key]) });
        }
    });
    appendDetailGrid(section, gridItems);

    const versionChips = createChipList('Versions', formatListValues(info.versions));
    if (versionChips) {
        section.appendChild(versionChips);
    }
    const extensionChips = createChipList('Extensions', formatListValues(info.extensions));
    if (extensionChips) {
        section.appendChild(extensionChips);
    }
    const transportChips = createChipList('Transports', formatListValues(info.transports));
    if (transportChips) {
        section.appendChild(transportChips);
    }
    const algorithmChips = createChipList('Algorithms', formatAuthenticatorAlgorithms(info.algorithms));
    if (algorithmChips) {
        section.appendChild(algorithmChips);
    }
    const pinProtocols = Array.isArray(info.pinUvAuthProtocols)
        ? info.pinUvAuthProtocols.map(protocol => String(protocol)).filter(Boolean)
        : [];
    if (pinProtocols.length) {
        const chip = createChipList('pinUvAuth Protocols', pinProtocols);
        if (chip) {
            section.appendChild(chip);
        }
    }

    const optionEntries = info.options && typeof info.options === 'object'
        ? Object.entries(info.options).filter(([, value]) => value !== undefined && value !== null)
        : [];
    if (optionEntries.length) {
        const optionChips = createChipList(
            'Options',
            optionEntries.map(([key, value]) => `${key}: ${formatDetailValue(value)}`),
        );
        if (optionChips) {
            section.appendChild(optionChips);
        }
    }

    return section;
}

function renderStatusReports(reports) {
    const list = Array.isArray(reports) ? reports : [];
    if (!list.length) {
        return null;
    }

    const table = document.createElement('table');
    table.className = 'mds-status-table';
    const thead = document.createElement('thead');
    const headRow = document.createElement('tr');
    ['Status', 'Effective Date', 'Authenticator Version', 'Certificate Number', 'Descriptor'].forEach(label => {
        const th = document.createElement('th');
        th.textContent = label;
        headRow.appendChild(th);
    });
    thead.appendChild(headRow);
    table.appendChild(thead);

    const tbody = document.createElement('tbody');
    list.forEach(report => {
        if (!report || typeof report !== 'object') {
            return;
        }
        const row = document.createElement('tr');

        const statusCell = document.createElement('td');
        statusCell.textContent = report.status ? formatEnum(report.status) : '—';
        row.appendChild(statusCell);

        const dateCell = document.createElement('td');
        dateCell.textContent = report.effectiveDate ? formatDate(report.effectiveDate) : '—';
        row.appendChild(dateCell);

        const versionCell = document.createElement('td');
        versionCell.textContent = report.authenticatorVersion !== undefined && report.authenticatorVersion !== null
            ? String(report.authenticatorVersion)
            : '—';
        row.appendChild(versionCell);

        const certificateCell = document.createElement('td');
        certificateCell.textContent = report.certificateNumber ? String(report.certificateNumber) : '—';
        row.appendChild(certificateCell);

        const descriptorCell = document.createElement('td');
        const descriptorContainer = document.createElement('div');
        descriptorContainer.className = 'mds-status-descriptor';

        const descriptorParts = [];
        if (report.certificationDescriptor) {
            descriptorParts.push(String(report.certificationDescriptor));
        }
        if (report.url) {
            descriptorParts.push(String(report.url));
        }
        if (descriptorParts.length) {
            const descriptorLine = document.createElement('div');
            descriptorLine.textContent = descriptorParts.join(' • ');
            descriptorContainer.appendChild(descriptorLine);
        }

        const metadataLines = [];
        if (report.certificationPolicyVersion) {
            metadataLines.push(`Policy: ${report.certificationPolicyVersion}`);
        }
        if (report.certificationRequirementsVersion) {
            metadataLines.push(`Requirements: ${report.certificationRequirementsVersion}`);
        }
        if (report.timeOfLastStatusChange) {
            metadataLines.push(`Changed: ${formatDate(report.timeOfLastStatusChange)}`);
        }
        if (metadataLines.length) {
            const metaLine = document.createElement('div');
            metaLine.className = 'mds-status-meta';
            metaLine.textContent = metadataLines.join(' • ');
            descriptorContainer.appendChild(metaLine);
        }

        if (!descriptorContainer.childElementCount) {
            descriptorContainer.textContent = '—';
        }

        descriptorCell.appendChild(descriptorContainer);
        row.appendChild(descriptorCell);

        tbody.appendChild(row);
    });

    table.appendChild(tbody);
    return table;
}

function normaliseCertificateBase64(value) {
    if (typeof value !== 'string') {
        return '';
    }
    return value.replace(/\s+/g, '').trim();
}

async function decodeCertificate(certificateBase64) {
    const cleaned = normaliseCertificateBase64(certificateBase64);
    if (!cleaned) {
        throw new Error('No certificate data available.');
    }
    if (certificateCache.has(cleaned)) {
        return certificateCache.get(cleaned);
    }

    const response = await fetch('/api/mds/decode-certificate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
        body: JSON.stringify({ certificate: cleaned }),
        cache: 'no-store',
    });

    if (!response.ok) {
        const message = `Certificate decode failed with status ${response.status}`;
        throw new Error(message);
    }

    const payload = await response.json();
    const details = payload?.details ?? null;
    certificateCache.set(cleaned, details);
    return details;
}

function formatCertificateInput(value) {
    return typeof value === 'string' ? value : '';
}

function formatCertificateOutput(details) {
    if (!details || typeof details !== 'object') {
        return 'No decoded certificate details available.';
    }
    if (typeof details.summary === 'string' && details.summary.trim()) {
        return details.summary.trim();
    }
    return JSON.stringify(details, null, 2);
}


function setCertificateSummaryContent(content) {
    if (!mdsState?.certificateSummary) {
        return;
    }
    const container = mdsState.certificateSummary;
    container.innerHTML = '';
    if (content instanceof Node) {
        container.appendChild(content);
    } else if (typeof content === 'string' && content.trim()) {
        const message = document.createElement('div');
        message.className = 'mds-certificate-summary__value';
        message.textContent = content;
        container.appendChild(message);
    }
}

async function updateCertificateButtonLabel(button, certificate) {
    if (!(button instanceof HTMLElement)) {
        return;
    }
    try {
        const details = await decodeCertificate(certificate);
        const subject = details && typeof details.subject === 'string' ? details.subject.trim() : '';
        if (subject) {
            button.textContent = subject;
            button.title = subject;
        }
    } catch (error) {
        // Leave default label on failure.
    }
}

async function openCertificateModal(certificate) {
    if (!mdsState?.certificateModal) {
        return;
    }

    const cleaned = normaliseCertificateBase64(certificate);
    if (!cleaned) {
        return;
    }

    if (mdsState.certificateInput) {
        mdsState.certificateInput.value = formatCertificateInput(cleaned);
        mdsState.certificateInput.scrollTop = 0;
        mdsState.certificateInput.scrollLeft = 0;
    }
    if (mdsState.certificateOutput) {
        mdsState.certificateOutput.value = 'Decoding certificate…';
        mdsState.certificateOutput.scrollTop = 0;
        mdsState.certificateOutput.scrollLeft = 0;
    }
    if (mdsState.certificateTitle) {
        mdsState.certificateTitle.textContent = 'Attestation Certificate';
    }

    setCertificateSummaryContent('Decoding certificate…');

    mdsState.certificateModal.hidden = false;
    mdsState.certificateModal.setAttribute('aria-hidden', 'false');
    resetScrollPositions(
        mdsState.certificateModalBody,
        mdsState.certificateModal,
        mdsState.certificateSummary,
        mdsState.certificateInput,
        mdsState.certificateOutput,
    );
    scheduleCertificateTextareaResize();
    notifyGlobalScrollLock();

    try {
        const details = await decodeCertificate(cleaned);
        if (mdsState.certificateOutput) {
            mdsState.certificateOutput.value = formatCertificateOutput(details);
            mdsState.certificateOutput.scrollTop = 0;
            mdsState.certificateOutput.scrollLeft = 0;
        }
        const summaryContent = renderCertificateSummary(details);
        if (summaryContent) {
            setCertificateSummaryContent(summaryContent);
        } else {
            setCertificateSummaryContent('No decoded certificate details available.');
        }
        const subject = details && typeof details.subject === 'string' ? details.subject.trim() : '';
        if (subject && mdsState.certificateTitle) {
            mdsState.certificateTitle.textContent = subject;
        }
        scheduleCertificateTextareaResize();
    } catch (error) {
        const message = error instanceof Error ? error.message : 'Unable to decode certificate.';
        if (mdsState.certificateOutput) {
            mdsState.certificateOutput.value = message;
            mdsState.certificateOutput.scrollTop = 0;
            mdsState.certificateOutput.scrollLeft = 0;
        }
        setCertificateSummaryContent(message);
        scheduleCertificateTextareaResize();
    }
}

function closeCertificateModal() {
    if (!mdsState?.certificateModal) {
        return;
    }
    mdsState.certificateModal.hidden = true;
    mdsState.certificateModal.setAttribute('aria-hidden', 'true');
    resetScrollPositions(
        mdsState.certificateModalBody,
        mdsState.certificateSummary,
        mdsState.certificateInput,
        mdsState.certificateOutput,
    );
    resetCertificateTextareaHeights();
    notifyGlobalScrollLock();
}

function openAuthenticatorModal(entry) {
    if (!mdsState?.authenticatorModal) {
        return;
    }

    if (entry) {
        mdsState.activeDetailEntry = entry;
    }
    hideScrollTopButton();

    applyDetailHeader(entry, mdsState.authenticatorModalTitle, mdsState.authenticatorModalSubtitle);
    populateDetailContent(mdsState.authenticatorModalContent, entry);

    mdsState.authenticatorModal.hidden = false;
    mdsState.authenticatorModal.setAttribute('aria-hidden', 'false');
    resetScrollPositions(
        mdsState.authenticatorModalBody,
        mdsState.authenticatorModal,
        mdsState.authenticatorModalContent,
    );
    notifyGlobalScrollLock();

    const focusTarget = mdsState.authenticatorModalClose instanceof HTMLElement
        ? mdsState.authenticatorModalClose
        : mdsState.authenticatorModal;
    if (focusTarget instanceof HTMLElement) {
        requestAnimationFrame(() => {
            focusTarget.focus();
        });
    }
}

function closeAuthenticatorModal() {
    if (!mdsState?.authenticatorModal) {
        return;
    }
    mdsState.authenticatorModal.hidden = true;
    mdsState.authenticatorModal.setAttribute('aria-hidden', 'true');
    resetScrollPositions(
        mdsState.authenticatorModalBody,
        mdsState.authenticatorModal,
        mdsState.authenticatorModalContent,
    );
    notifyGlobalScrollLock();
    mdsState.activeDetailEntry = null;
    scheduleScrollTopButtonUpdate();
}

async function resolveEntryByAaguid(aaguid) {
    if (!mdsState) {
        return null;
    }

    const targetKey = normaliseAaguid(aaguid);
    if (!targetKey) {
        return null;
    }

    if (!hasLoaded) {
        await loadMdsData();
    } else if (isLoading && loadPromise) {
        await loadPromise;
    }

    if (!mdsState) {
        return null;
    }

    const cached = mdsState.byAaguid?.get(targetKey) || null;
    if (cached) {
        return cached;
    }

    const fallback = mdsData.find(item => {
        const key = normaliseAaguid(item?.aaguid || item?.id);
        return key === targetKey;
    }) || null;

    if (fallback && mdsState.byAaguid) {
        mdsState.byAaguid.set(targetKey, fallback);
    }

    return fallback;
}

async function openAuthenticatorModalByAaguid(aaguid) {
    const entry = await resolveEntryByAaguid(aaguid);
    if (!entry) {
        return null;
    }
    openAuthenticatorModal(entry);
    return entry;
}

async function focusAuthenticatorByAaguid(aaguid) {
    const entry = await resolveEntryByAaguid(aaguid);
    if (!entry) {
        return null;
    }

    resetFilters();
    showAuthenticatorDetail(entry, { scrollIntoView: true });
    return entry;
}

async function highlightAuthenticatorRowByAaguid(aaguid) {
    const entry = await resolveEntryByAaguid(aaguid);
    if (!entry || !mdsState) {
        return entry || null;
    }

    const key = normaliseAaguid(entry.aaguid || entry.id);
    if (!key) {
        return entry;
    }

    mdsState.highlightedRowKey = key;

    if (mdsState.authenticatorModal && !mdsState.authenticatorModal.hidden) {
        hideAuthenticatorDetail();
    }

    resetFilters();
    applyFilters();

    scheduleRowHighlight(key);

    return entry;
}

if (typeof window !== 'undefined') {
    window.openMdsAuthenticatorModal = openAuthenticatorModalByAaguid;
    window.focusMdsAuthenticator = focusAuthenticatorByAaguid;
    window.highlightMdsAuthenticatorRow = highlightAuthenticatorRowByAaguid;
}

function stabiliseColumnWidths() {
    if (!mdsState?.table) {
        return;
    }
    if (mdsState.root instanceof HTMLElement && mdsState.root.offsetParent === null) {
        return;
    }
    const updateMinWidths = () => {
        const measured = computeColumnMinWidths();
        if (measured.length) {
            mdsState.columnMinWidths = measured;
        }
    };

    updateMinWidths();

    if (!Array.isArray(mdsState.columnWidths) || !mdsState.columnWidths.length) {
        requestAnimationFrame(() => {
            if (!mdsState?.table) {
                return;
            }

            updateMinWidths();

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
            const normalised = normaliseColumnWidths(widths);
            mdsState.columnWidths = normalised;
            mdsState.columnWidthAttempts = 0;
            applyColumnWidths(normalised);
        });
        return;
    }

    const adjusted = normaliseColumnWidths(mdsState.columnWidths);
    mdsState.columnWidths = adjusted;
    applyColumnWidths(adjusted);
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

    scheduleColumnResizerMetricsUpdate();
    scheduleRowHeightLock();
}

function updateColumnResizerMetrics() {
    if (!mdsState?.table || !(mdsState.table instanceof HTMLElement)) {
        return;
    }

    const table = mdsState.table;
    if (table.offsetParent === null) {
        table.style.setProperty('--mds-resizer-extend', '0px');
        return;
    }

    const headerRow = table.tHead?.rows?.[0];
    if (!headerRow) {
        table.style.setProperty('--mds-resizer-extend', '0px');
        return;
    }

    let headerHeight = 0;
    if (typeof headerRow.getBoundingClientRect === 'function') {
        const rect = headerRow.getBoundingClientRect();
        if (rect && Number.isFinite(rect.height)) {
            headerHeight = rect.height;
        }
    }
    if (!headerHeight && headerRow instanceof HTMLElement) {
        headerHeight = headerRow.offsetHeight || 0;
    }

    const tableHeight = table.offsetHeight || 0;
    const extend = Math.max(Math.round(tableHeight - headerHeight), 0);
    table.style.setProperty('--mds-resizer-extend', `${extend}px`);
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

function normaliseColumnWidths(widths) {
    if (!Array.isArray(widths)) {
        return [];
    }
    return widths.map(value => {
        if (!Number.isFinite(value) || value <= 0) {
            return DEFAULT_MIN_COLUMN_WIDTH;
        }
        return Math.max(Math.round(value), DEFAULT_MIN_COLUMN_WIDTH);
    });
}

function computeColumnMinWidths(state = mdsState) {
    if (!state?.table?.tHead) {
        return [];
    }

    const headerRow = state.table.tHead.rows[0];
    if (!headerRow) {
        return [];
    }

    const columnCount = headerRow.cells.length;
    if (!columnCount) {
        return [];
    }

    return new Array(columnCount).fill(DEFAULT_MIN_COLUMN_WIDTH);
}

function ensureColumnMetrics(state = mdsState) {
    if (!state?.table?.tHead) {
        return false;
    }
    const headerRow = state.table.tHead.rows[0];
    if (!headerRow) {
        return false;
    }

    const columnCount = headerRow.cells.length;
    if (!columnCount) {
        return false;
    }

    const minWidths = computeColumnMinWidths(state);
    if (minWidths.length) {
        state.columnMinWidths = minWidths;
    }
    if (!Array.isArray(state.columnMinWidths) || state.columnMinWidths.length < columnCount) {
        const fallback = new Array(columnCount).fill(DEFAULT_MIN_COLUMN_WIDTH);
        if (Array.isArray(state.columnMinWidths)) {
            state.columnMinWidths.forEach((value, index) => {
                fallback[index] = Math.max(DEFAULT_MIN_COLUMN_WIDTH, Math.round(value || 0));
            });
        }
        state.columnMinWidths = fallback;
    } else {
        state.columnMinWidths = state.columnMinWidths.map(value =>
            Math.max(DEFAULT_MIN_COLUMN_WIDTH, Math.round(value || 0)),
        );
    }

    let widths;
    if (!Array.isArray(state.columnWidths) || state.columnWidths.length < columnCount) {
        widths = Array.from(headerRow.cells).map(cell => {
            const rect = cell.getBoundingClientRect();
            const rectWidth = Number.isFinite(rect?.width) ? Math.round(rect.width) : DEFAULT_MIN_COLUMN_WIDTH;
            return Math.max(rectWidth, DEFAULT_MIN_COLUMN_WIDTH);
        });
    } else {
        widths = state.columnWidths.slice();
    }

    state.columnWidths = normaliseColumnWidths(widths);
    return true;
}

function setupColumnResizers(state = mdsState) {
    if (!state?.table?.tHead) {
        return;
    }
    const headerRow = state.table.tHead.rows[0];
    if (!headerRow) {
        return;
    }

    state.columnResizers = Array.isArray(state.columnResizers) ? state.columnResizers : [];

    Array.from(headerRow.cells).forEach((cell, index) => {
        if (!cell || index === headerRow.cells.length - 1) {
            return;
        }
        if (cell.querySelector('.mds-column-resizer')) {
            return;
        }
        const resizer = document.createElement('div');
        resizer.className = 'mds-column-resizer';
        resizer.dataset.columnIndex = String(index);
        resizer.setAttribute('aria-hidden', 'true');
        resizer.setAttribute('role', 'presentation');
        resizer.tabIndex = -1;
        resizer.title = 'Drag to resize column';
        resizer.addEventListener('pointerdown', handleColumnResizeStart);
        resizer.addEventListener('click', event => {
            event.preventDefault();
            event.stopPropagation();
        });
        cell.appendChild(resizer);
        state.columnResizers.push(resizer);
    });

    scheduleColumnResizerMetricsUpdate();
}

function handleColumnResizeStart(event) {
    if (!mdsState) {
        return;
    }
    if (event.button !== undefined && event.button !== 0) {
        return;
    }
    const target = event.currentTarget;
    if (!(target instanceof HTMLElement)) {
        return;
    }
    const columnIndex = Number.parseInt(target.dataset.columnIndex || '', 10);
    if (!Number.isFinite(columnIndex)) {
        return;
    }

    if (!ensureColumnMetrics()) {
        return;
    }

    const widths = Array.isArray(mdsState.columnWidths) ? mdsState.columnWidths.slice() : [];
    if (columnIndex >= widths.length - 1) {
        return;
    }

    const startLeft = widths[columnIndex];
    if (!Number.isFinite(startLeft)) {
        return;
    }

    const minWidths = Array.isArray(mdsState.columnMinWidths) ? mdsState.columnMinWidths : [];
    let minLeft = Number.isFinite(minWidths[columnIndex]) ? Math.round(minWidths[columnIndex]) : DEFAULT_MIN_COLUMN_WIDTH;
    if (!Number.isFinite(minLeft) || minLeft <= 0) {
        minLeft = DEFAULT_MIN_COLUMN_WIDTH;
    }
    minLeft = Math.max(minLeft, DEFAULT_MIN_COLUMN_WIDTH);

    event.preventDefault();
    event.stopPropagation();

    const resizeState = {
        activeResizer: target,
        columnIndex,
        pointerId: event.pointerId,
        startX: event.clientX,
        startLeft,
        minLeft,
        listenerTarget: target,
    };

    mdsState.columnResizeState = resizeState;

    if (mdsState.tableContainer) {
        mdsState.tableContainer.classList.add('mds-table-container--resizing');
    }

    target.classList.add('is-active');

    let useDocumentListeners = false;
    if (typeof target.setPointerCapture === 'function') {
        try {
            target.setPointerCapture(event.pointerId);
        } catch (error) {
            useDocumentListeners = true;
        }
    } else {
        useDocumentListeners = true;
    }

    if (useDocumentListeners && typeof document !== 'undefined') {
        resizeState.listenerTarget = document;
    }

    const listenerTarget = resizeState.listenerTarget;
    if (listenerTarget) {
        listenerTarget.addEventListener('pointermove', handleColumnResizeMove);
        listenerTarget.addEventListener('pointerup', handleColumnResizeEnd);
        listenerTarget.addEventListener('pointercancel', handleColumnResizeEnd);
    }
}

function handleColumnResizeMove(event) {
    if (!mdsState?.columnResizeState) {
        return;
    }
    const state = mdsState.columnResizeState;
    if (state.pointerId !== undefined && event.pointerId !== undefined && state.pointerId !== event.pointerId) {
        return;
    }

    const widths = Array.isArray(mdsState.columnWidths) ? mdsState.columnWidths.slice() : [];
    if (!widths.length) {
        return;
    }

    const leftIndex = state.columnIndex;
    if (!Number.isFinite(leftIndex) || leftIndex < 0 || leftIndex >= widths.length) {
        return;
    }

    const minLeft = state.minLeft || DEFAULT_MIN_COLUMN_WIDTH;

    let delta = event.clientX - state.startX;
    if (!Number.isFinite(delta)) {
        delta = 0;
    }
    const maxNegativeDelta = state.startLeft - minLeft;
    if (Number.isFinite(maxNegativeDelta) && maxNegativeDelta >= 0) {
        delta = Math.max(delta, -maxNegativeDelta);
    }

    let newLeft = state.startLeft + delta;
    if (!Number.isFinite(newLeft)) {
        newLeft = state.startLeft;
    }

    widths[leftIndex] = Math.max(minLeft, Math.round(newLeft));

    mdsState.columnWidths = widths;
    const normalised = normaliseColumnWidths(widths);
    mdsState.columnWidths = normalised;
    applyColumnWidths(normalised);

    if (typeof window !== 'undefined' && window.getSelection) {
        const selection = window.getSelection();
        if (selection && typeof selection.removeAllRanges === 'function') {
            selection.removeAllRanges();
        }
    }

    event.preventDefault();
    event.stopPropagation();
}

function handleColumnResizeEnd(event) {
    const state = mdsState?.columnResizeState;
    if (!state) {
        return;
    }

    const target = state.activeResizer;
    if (target instanceof HTMLElement) {
        target.classList.remove('is-active');
        if (typeof target.releasePointerCapture === 'function' && state.pointerId !== undefined) {
            try {
                target.releasePointerCapture(state.pointerId);
            } catch (error) {
                // Ignore errors when releasing capture.
            }
        }
    }

    const listenerTarget = state.listenerTarget || target;
    if (listenerTarget) {
        listenerTarget.removeEventListener('pointermove', handleColumnResizeMove);
        listenerTarget.removeEventListener('pointerup', handleColumnResizeEnd);
        listenerTarget.removeEventListener('pointercancel', handleColumnResizeEnd);
    }

    if (mdsState.tableContainer) {
        mdsState.tableContainer.classList.remove('mds-table-container--resizing');
    }

    mdsState.columnResizeState = null;
    if (event) {
        event.preventDefault();
        event.stopPropagation();
    }

    const minWidths = computeColumnMinWidths();
    if (minWidths.length) {
        mdsState.columnMinWidths = minWidths;
    }
    if (Array.isArray(mdsState.columnWidths)) {
        const normalised = normaliseColumnWidths(mdsState.columnWidths);
        mdsState.columnWidths = normalised;
        applyColumnWidths(normalised);
    }
}

function createTextCell(text, title) {
    const cell = document.createElement('td');
    cell.textContent = text;
    if (title) {
        cell.title = title;
    }
    return cell;
}

function createNameCell(entry) {
    const cell = document.createElement('td');
    cell.classList.add('mds-cell-name');
    const label = entry?.name || '—';
    const trimmed = label.trim();

    if (!entry || !trimmed || trimmed === '—') {
        cell.textContent = label || '—';
        return cell;
    }

    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'mds-name-button';
    button.textContent = label;
    button.addEventListener('click', () => showAuthenticatorDetail(entry));
    cell.appendChild(button);
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
        button.disabled = true;
        button.classList.add('is-busy');
        button.setAttribute('aria-busy', 'true');
        const mode = mdsState?.updateButtonMode || 'update';
        const config = UPDATE_BUTTON_STATES[mode] || UPDATE_BUTTON_STATES.update;
        button.textContent = config.busyLabel;
        return;
    }

    button.disabled = false;
    button.classList.remove('is-busy');
    button.removeAttribute('aria-busy');
    const mode = mdsState?.updateButtonMode || 'update';
    const config = UPDATE_BUTTON_STATES[mode] || UPDATE_BUTTON_STATES.update;
    button.textContent = config.label;
    button.blur();
}

function setUpdateButtonMode(mode) {
    const button = mdsState?.updateButton;
    if (!button) {
        return;
    }

    const action = mode === 'download' ? 'download' : 'update';
    const config = UPDATE_BUTTON_STATES[action] || UPDATE_BUTTON_STATES.update;

    mdsState.updateButtonMode = action;
    if (action === 'download') {
        setUpdateButtonAttention(false);
        if (mdsState) {
            mdsState.metadataOverdue = false;
            mdsState.metadataNextUpdate = null;
        }
    }

    button.dataset.action = action;
    button.dataset.idleLabel = config.label;
    button.dataset.busyLabel = config.busyLabel;

    if (!button.classList.contains('is-busy')) {
        button.textContent = config.label;
    }
}

function setUpdateButtonAttention(active) {
    const button = mdsState?.updateButton;
    if (!button) {
        return;
    }

    const shouldHighlight = Boolean(active);
    button.classList.toggle('mds-update-button--attention', shouldHighlight);
    if (shouldHighlight) {
        button.setAttribute('title', 'Metadata update recommended');
    } else if (button.title === 'Metadata update recommended') {
        button.removeAttribute('title');
    }
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
        const action = mdsState?.updateButtonMode === 'download' ? 'download' : 'update';
        const inProgressMessage =
            action === 'download' ? 'Downloading metadata BLOB…' : 'Updating metadata BLOB…';
        setStatus(inProgressMessage, 'info');

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

        const payloadMessage =
            (payload && typeof payload.message === 'string' && payload.message.trim()) || '';
        const shouldReload = (payload && payload.updated) || !hasLoaded;
        const note =
            action === 'download' && shouldReload
                ? ['Download complete.', payloadMessage].filter(Boolean).join(' ')
                : payloadMessage;

        if (shouldReload) {
            hasLoaded = false;
            await loadMdsData(note, { bypassCache: true });
        } else {
            const overdue = Boolean(mdsState?.metadataOverdue);
            let message = note || 'Metadata already up to date.';
            let variant = 'info';

            if (overdue) {
                const formattedDeadline = mdsState?.metadataNextUpdate
                    ? formatDate(mdsState.metadataNextUpdate)
                    : '';
                const deadlineSuffix = formattedDeadline ? ` (${formattedDeadline})` : '';
                const overdueMessage = `Metadata is still older than the recommended refresh date${deadlineSuffix}. The published file may not have been updated yet.`;
                message = note ? `${note} ${overdueMessage}` : overdueMessage;
                variant = 'error';
                setUpdateButtonAttention(true);
            }

            setStatus(message, variant, { restoreDefault: true, delay: 5000 });
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

if (typeof window !== 'undefined') {
    window.focusMdsAuthenticator = focusAuthenticatorByAaguid;
}
