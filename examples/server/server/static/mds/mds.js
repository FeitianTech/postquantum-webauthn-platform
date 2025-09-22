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

    const detailView = root.querySelector('#mds-detail-view');
    const detailBack = root.querySelector('#mds-detail-back');
    if (detailBack) {
        detailBack.addEventListener('click', () => hideAuthenticatorDetail());
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

    return {
        root,
        filters,
        filterInputs,
        dropdowns,
        tableContainer,
        table,
        tableBody,
        countEl: root.querySelector('#mds-entry-count'),
        totalEl: root.querySelector('#mds-total-count'),
        statusEl,
        defaultStatus,
        statusResetTimer: null,
        columnWidths: null,
        columnWidthAttempts: 0,
        updateButton,
        updateButtonMode: 'update',
        metadataOverdue: false,
        metadataNextUpdate: null,
        detailView,
        detailContent: root.querySelector('#mds-detail-content'),
        detailTitle: root.querySelector('#mds-detail-title'),
        detailSubtitle: root.querySelector('#mds-detail-subtitle'),
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
        previousDocumentScrollTop: null,
        previousTableScrollTop: null,
        highlightedRow: null,
        highlightedRowKey: '',
        tabChangeHandler: handleTabChanged,
        byAaguid: new Map(),
        scrollTopButton,
        scrollTopButtonVisible: false,
    };
}

async function loadMdsData(statusNote) {
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

    const note = typeof statusNote === 'string' ? statusNote.trim() : '';
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
                ? metadata.entries.map((entry, index) => transformEntry(entry, index)).filter(Boolean)
                : [];
            hasLoaded = true;
            setUpdateButtonMode('update');

            if (mdsState) {
                const map = new Map();
                mdsData.forEach(item => {
                    const key = normaliseAaguid(item.aaguid || item.id);
                    if (key) {
                        map.set(key, item);
                    }
                });
                mdsState.byAaguid = map;
            }

            const nextUpdateRaw = typeof metadata.nextUpdate === 'string' ? metadata.nextUpdate : '';
            const nextUpdateDate = parseIsoDate(nextUpdateRaw);
            const nextUpdateFormatted = nextUpdateRaw ? formatDate(nextUpdateRaw) : '';
            const now = Date.now();
            const isOverdue = Boolean(nextUpdateDate && nextUpdateDate.getTime() <= now);

            if (mdsState) {
                mdsState.metadataOverdue = isOverdue;
                mdsState.metadataNextUpdate = nextUpdateRaw || null;
            }
            setUpdateButtonAttention(isOverdue);

            const optionSets = collectOptionSets(mdsData);
            updateOptionLists(optionSets);
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
            if (note) {
                statusParts.push(note);
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
    hideScrollTopButton();

    const sourceEntry = typeof entry.index === 'number' && mdsData[entry.index]
        ? mdsData[entry.index]
        : entry;

    mdsState.activeDetailEntry = sourceEntry;

    if (typeof window !== 'undefined') {
        const doc = document.documentElement;
        const body = document.body;
        const scrollTop = typeof window.pageYOffset === 'number'
            ? window.pageYOffset
            : (doc?.scrollTop ?? body?.scrollTop ?? 0);
        mdsState.previousDocumentScrollTop = scrollTop;
    }

    if (mdsState.tableContainer) {
        if (typeof mdsState.tableContainer.scrollTop === 'number') {
            mdsState.previousTableScrollTop = mdsState.tableContainer.scrollTop;
        }
        mdsState.tableContainer.hidden = true;
    }
    if (mdsState.detailView) {
        mdsState.detailView.hidden = false;
    }

    if (mdsState.root) {
        mdsState.root.classList.add('mds-section--detail-active');
    }

    applyDetailHeader(sourceEntry, mdsState.detailTitle, mdsState.detailSubtitle);
    populateDetailContent(mdsState.detailContent, sourceEntry);
    resetScrollPositions(mdsState.detailView, mdsState.detailContent);

    const { scrollIntoView = true } = options;
    if (scrollIntoView && mdsState.detailView && typeof mdsState.detailView.scrollIntoView === 'function') {
        requestAnimationFrame(() => {
            mdsState.detailView.scrollIntoView({ block: 'start' });
        });
    }
}

function hideAuthenticatorDetail() {
    if (!mdsState) {
        return;
    }

    if (mdsState.root) {
        mdsState.root.classList.remove('mds-section--detail-active');
    }

    if (mdsState.detailView) {
        mdsState.detailView.hidden = true;
    }
    if (mdsState.tableContainer) {
        mdsState.tableContainer.hidden = false;
        if (typeof mdsState.previousTableScrollTop === 'number') {
            const target = mdsState.previousTableScrollTop;
            mdsState.tableContainer.scrollTop = target;
            if (typeof requestAnimationFrame === 'function') {
                requestAnimationFrame(() => {
                    requestAnimationFrame(() => {
                        mdsState.tableContainer.scrollTop = target;
                    });
                });
            } else {
                setTimeout(() => {
                    mdsState.tableContainer.scrollTop = target;
                }, 0);
            }
        }
    }

    const previousScrollTop = typeof mdsState.previousDocumentScrollTop === 'number'
        ? mdsState.previousDocumentScrollTop
        : null;
    mdsState.previousDocumentScrollTop = null;
    mdsState.previousTableScrollTop = null;

    if (previousScrollTop !== null && typeof window !== 'undefined') {
        const restore = () => {
            if (typeof window.scrollTo === 'function') {
                window.scrollTo({ top: previousScrollTop, left: 0, behavior: 'auto' });
            } else {
                window.scrollTo(0, previousScrollTop);
            }
        };
        if (typeof requestAnimationFrame === 'function') {
            requestAnimationFrame(() => requestAnimationFrame(restore));
        } else {
            setTimeout(restore, 0);
        }
    }
    if (mdsState.updateButton instanceof HTMLElement) {
        requestAnimationFrame(() => {
            mdsState.updateButton.focus();
        });
    }
    mdsState.activeDetailEntry = null;
    scheduleScrollTopButtonUpdate();
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

    if (mdsState.authenticatorModalClose instanceof HTMLElement) {
        requestAnimationFrame(() => {
            mdsState.authenticatorModalClose.focus();
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

    if (mdsState.detailView && !mdsState.detailView.hidden) {
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
            await loadMdsData(note);
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
