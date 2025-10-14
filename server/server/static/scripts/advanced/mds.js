import {
    MDS_HTML_PATH,
    MDS_JWS_PATH,
    CUSTOM_METADATA_LIST_PATH,
    CUSTOM_METADATA_UPLOAD_PATH,
    CUSTOM_METADATA_DELETE_PATH,
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
    formatDetailValue,
    formatGuidCandidate,
    formatUpv,
    extractList,
    renderCertificateSummary,
} from './mds-utils.js';
import {
    loaderIsActive,
    loaderSetPhase,
    loaderSetProgress,
    loaderSetMetadataCount,
    loaderComplete,
} from '../shared/loader.js';

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
let horizontalScrollMetricsScheduled = false;
let initialMdsJws = null;
let initialMdsInfo = null;
const MDS_METADATA_STORAGE_KEY = 'fido.mds.metadataPayload';
const MDS_METADATA_INFO_KEY = 'fido.mds.metadataInfo';
let sessionStorageWarningShown = false;
let isSyncingHorizontalScroll = false;

const SORT_NONE = 'none';
const SORT_ASCENDING = 'asc';
const SORT_DESCENDING = 'desc';

const SORT_SEQUENCE = {
    [SORT_NONE]: SORT_ASCENDING,
    [SORT_ASCENDING]: SORT_DESCENDING,
    [SORT_DESCENDING]: SORT_NONE,
};

const DEFAULT_SORT_KEY = 'dateUpdated';
const DEFAULT_SORT_DIRECTION = SORT_DESCENDING;

const SORT_SEQUENCE_OVERRIDES = {
    [DEFAULT_SORT_KEY]: {
        [SORT_NONE]: DEFAULT_SORT_DIRECTION,
        [SORT_ASCENDING]: SORT_DESCENDING,
        [SORT_DESCENDING]: SORT_ASCENDING,
    },
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
const FLOATING_SCROLL_BOTTOM_MARGIN = 24;
const FLOATING_SCROLL_SIDE_MARGIN = 16;

let customMetadataCache = null;
let customMetadataPromise = null;
let customMetadataItems = [];

function cloneJsonValue(value) {
    if (value === undefined) {
        return undefined;
    }
    if (value === null || typeof value !== 'object') {
        return value;
    }
    try {
        return JSON.parse(JSON.stringify(value));
    } catch (error) {
        console.warn('Failed to clone metadata value.', error);
        return value;
    }
}

function cloneMetadataEntry(entry) {
    if (!entry || typeof entry !== 'object') {
        return null;
    }
    try {
        return JSON.parse(JSON.stringify(entry));
    } catch (error) {
        console.warn('Failed to clone metadata entry.', error);
        return entry;
    }
}

function cloneCustomMetadataItem(item) {
    if (!item || typeof item !== 'object') {
        return null;
    }

    const cloned = { ...item };
    cloned.entry = cloneMetadataEntry(item.entry);
    if (!cloned.entry) {
        return null;
    }
    if (item.source && typeof item.source === 'object') {
        cloned.source = { ...item.source };
    }
    if (typeof item.legalHeader === 'string' && item.legalHeader.trim()) {
        cloned.legalHeader = item.legalHeader.trim();
    } else {
        delete cloned.legalHeader;
    }
    return cloned;
}

function cloneCustomMetadataItems(items) {
    if (!Array.isArray(items)) {
        return [];
    }
    return items.map(item => cloneCustomMetadataItem(item)).filter(Boolean);
}

function setButtonBusy(button, busy) {
    if (!(button instanceof HTMLButtonElement)) {
        return;
    }
    if (busy) {
        button.disabled = true;
        button.setAttribute('aria-disabled', 'true');
        button.classList.add('is-busy');
    } else {
        button.disabled = false;
        button.removeAttribute('aria-disabled');
        button.classList.remove('is-busy');
    }
}

async function fetchCustomMetadataItems() {
    try {
        const response = await fetch(CUSTOM_METADATA_LIST_PATH, { cache: 'no-store' });
        if (!response.ok) {
            if (response.status !== 404) {
                console.warn(
                    `Failed to load ${CUSTOM_METADATA_LIST_PATH}: ${response.status}`,
                );
            }
            return [];
        }
        const payload = await response.json();
        const rawItems = Array.isArray(payload?.items) ? payload.items : [];
        return cloneCustomMetadataItems(rawItems);
    } catch (error) {
        console.warn('Failed to load custom metadata entries.', error);
        return [];
    }
}

async function getCustomMetadataItems(options = {}) {
    const opts = options && typeof options === 'object' ? options : {};
    const forceReload = Boolean(opts.forceReload);

    if (forceReload) {
        customMetadataCache = null;
    }

    if (customMetadataCache) {
        return cloneCustomMetadataItems(customMetadataCache);
    }

    if (!customMetadataPromise) {
        customMetadataPromise = (async () => {
            const items = await fetchCustomMetadataItems();
            customMetadataCache = items;
            return items;
        })();
    }

    try {
        const loaded = await customMetadataPromise;
        return cloneCustomMetadataItems(loaded);
    } finally {
        customMetadataPromise = null;
    }
}

function extractCustomEntries(items) {
    return items
        .map(item => cloneMetadataEntry(item.entry))
        .filter(entry => entry && typeof entry === 'object');
}

function mergeCustomEntriesIntoMetadata(metadata, entries, items) {
    const base = metadata && typeof metadata === 'object' ? metadata : {};
    const result = { ...base };
    const existingEntries = Array.isArray(base.entries) ? base.entries.slice() : [];

    if (!entries.length) {
        result.entries = existingEntries;
        return result;
    }

    const seen = new Set(
        entries
            .map(entry => normaliseAaguid(entry?.aaguid || entry?.metadataStatement?.aaguid))
            .filter(Boolean),
    );

    const filteredExisting = existingEntries.filter(existing => {
        const existingAaguid = normaliseAaguid(
            existing?.aaguid || existing?.metadataStatement?.aaguid,
        );
        return !existingAaguid || !seen.has(existingAaguid);
    });

    const combined = entries.map(entry => cloneMetadataEntry(entry)).concat(filteredExisting);
    result.entries = combined.filter(Boolean);

    if (!result.legalHeader) {
        const header = items
            .map(item => (typeof item.legalHeader === 'string' ? item.legalHeader : ''))
            .map(value => value.trim())
            .find(value => value);
        if (header) {
            result.legalHeader = header;
        }
    }

    return result;
}

async function ensureCustomMetadata(metadata, options = {}) {
    const items = await getCustomMetadataItems(options);
    customMetadataItems = cloneCustomMetadataItems(items);
    updateCustomMetadataList(customMetadataItems);
    const entries = extractCustomEntries(customMetadataItems);
    return mergeCustomEntriesIntoMetadata(metadata, entries, customMetadataItems);
}

function setCustomMetadataMessage(message, variant = 'info', targetState = mdsState) {
    const container = targetState?.customPanelMessages;
    if (!container) {
        return;
    }

    const variants = ['info', 'success', 'error', 'warning'];
    container.classList.remove(
        ...variants.map(name => `mds-custom-panel__messages--${name}`),
    );

    const safeVariant = variants.includes(variant) ? variant : 'info';
    container.classList.add(`mds-custom-panel__messages--${safeVariant}`);

    if (typeof message === 'string' && message.trim()) {
        container.textContent = message.trim();
        container.hidden = false;
        container.removeAttribute('hidden');
    } else {
        container.textContent = '';
        container.hidden = true;
        container.setAttribute('hidden', '');
    }
}

function updateCustomMetadataList(items, targetState = mdsState) {
    const list = targetState?.customList;
    if (!list) {
        return;
    }

    list.innerHTML = '';

    const entries = Array.isArray(items) ? items : [];
    if (!entries.length) {
        const emptyItem = document.createElement('li');
        emptyItem.className = 'mds-custom-panel__list-item mds-custom-panel__list-item--empty';
        emptyItem.textContent = 'No custom metadata has been added yet.';
        list.appendChild(emptyItem);
        return;
    }

    entries.forEach(item => {
        const listItem = document.createElement('li');
        listItem.className = 'mds-custom-panel__list-item';

        const name =
            (item?.source?.originalFilename && String(item.source.originalFilename).trim()) ||
            (item?.source?.storedFilename && String(item.source.storedFilename).trim()) ||
            'metadata.json';

        const storedFilename =
            (item?.source?.storedFilename && String(item.source.storedFilename).trim()) || '';

        if (storedFilename) {
            listItem.dataset.filename = storedFilename;
        }

        const headerEl = document.createElement('div');
        headerEl.className = 'mds-custom-panel__item-header';

        const nameEl = document.createElement('span');
        nameEl.className = 'mds-custom-panel__item-name';
        nameEl.textContent = name;
        headerEl.appendChild(nameEl);

        if (storedFilename) {
            const actionsEl = document.createElement('div');
            actionsEl.className = 'mds-custom-panel__item-actions';

            const deleteButton = document.createElement('button');
            deleteButton.type = 'button';
            deleteButton.className = 'mds-custom-panel__delete-button';
            deleteButton.textContent = 'Delete';
            deleteButton.setAttribute('aria-label', `Delete ${name}`);
            deleteButton.title = `Delete ${name}`;
            deleteButton.addEventListener('click', event => {
                event.preventDefault();
                event.stopPropagation();
                if (deleteButton.disabled) {
                    return;
                }
                setButtonBusy(deleteButton, true);
                void deleteCustomMetadata(storedFilename, {
                    trigger: deleteButton,
                    itemName: name,
                });
            });

            actionsEl.appendChild(deleteButton);
            headerEl.appendChild(actionsEl);
        }

        listItem.appendChild(headerEl);

        const details = [];
        const uploadedAtRaw = item?.source?.uploadedAt;
        if (typeof uploadedAtRaw === 'string' && uploadedAtRaw) {
            const parsed = new Date(uploadedAtRaw);
            if (!Number.isNaN(parsed.getTime())) {
                details.push(`Uploaded ${parsed.toLocaleString()}`);
            }
        }
        if (item?.legalHeader) {
            details.push('Includes legal header');
        }

        if (details.length) {
            const detailEl = document.createElement('span');
            detailEl.className = 'mds-custom-panel__item-details';
            detailEl.textContent = details.join(' · ');
            listItem.appendChild(detailEl);
        }

        list.appendChild(listItem);
    });
}

function handleCustomPanelKeydown(event) {
    if (event.key === 'Escape') {
        event.stopPropagation();
        closeCustomMetadataPanel();
    }
}

function openCustomMetadataPanel() {
    if (!mdsState?.customPanel) {
        return;
    }

    if (!mdsState.customPanelIsOpen) {
        const panel = mdsState.customPanel;
        panel.hidden = false;
        panel.removeAttribute('hidden');
        panel.classList.add('is-open');
        mdsState.customPanelIsOpen = true;
        mdsState.customPanelReturnFocus =
            document.activeElement instanceof HTMLElement ? document.activeElement : null;
        if (mdsState.addMetadataButton) {
            mdsState.addMetadataButton.setAttribute('aria-expanded', 'true');
        }
        if (mdsState.customDropzone instanceof HTMLElement) {
            mdsState.customDropzone.focus();
        }
    }
}

function closeCustomMetadataPanel() {
    if (!mdsState?.customPanel) {
        return;
    }

    const panel = mdsState.customPanel;
    panel.classList.remove('is-open');
    panel.hidden = true;
    panel.setAttribute('hidden', '');
    mdsState.customPanelIsOpen = false;

    if (mdsState.addMetadataButton) {
        mdsState.addMetadataButton.setAttribute('aria-expanded', 'false');
    }

    if (mdsState.customDropzone instanceof HTMLElement) {
        mdsState.customDropzone.classList.remove('is-active');
    }

    if (mdsState.customPanelReturnFocus instanceof HTMLElement) {
        try {
            mdsState.customPanelReturnFocus.focus();
        } catch (error) {
            /* ignore focus errors */
        }
    }
    mdsState.customPanelReturnFocus = null;
}

function handleCustomDropzoneDragEnter(event) {
    if (!mdsState?.customDropzone) {
        return;
    }
    event.preventDefault();
    event.stopPropagation();
    if (event.dataTransfer) {
        event.dataTransfer.dropEffect = 'copy';
    }
    mdsState.customDropzone.classList.add('is-active');
}

function handleCustomDropzoneDragLeave(event) {
    if (!mdsState?.customDropzone) {
        return;
    }
    event.preventDefault();
    event.stopPropagation();
    if (event.target === mdsState.customDropzone || event.currentTarget === mdsState.customDropzone) {
        mdsState.customDropzone.classList.remove('is-active');
    }
}

function normaliseFileList(list) {
    if (!list) {
        return [];
    }
    return Array.from(list).filter(file => file instanceof File);
}

function splitAcceptedFiles(files) {
    const accepted = [];
    const rejected = [];
    files.forEach(file => {
        if (!file) {
            return;
        }
        const name = typeof file.name === 'string' ? file.name : '';
        if (name.toLowerCase().endsWith('.json')) {
            accepted.push(file);
        } else {
            rejected.push(name || 'Unnamed file');
        }
    });
    return { accepted, rejected };
}

async function handleCustomFileSelection(files) {
    const { accepted, rejected } = splitAcceptedFiles(files);

    if (rejected.length) {
        setCustomMetadataMessage(
            `Ignored non-JSON files: ${rejected.join(', ')}`,
            'warning',
        );
    }

    if (!accepted.length) {
        if (!rejected.length) {
            setCustomMetadataMessage('Please select one or more JSON files.', 'warning');
        }
        return;
    }

    await uploadCustomMetadataFiles(accepted);
}

function handleCustomDrop(event) {
    if (!mdsState?.customDropzone) {
        return;
    }
    event.preventDefault();
    event.stopPropagation();
    mdsState.customDropzone.classList.remove('is-active');
    const files = normaliseFileList(event.dataTransfer?.files);
    void handleCustomFileSelection(files);
}

function handleCustomFileInputChange(event) {
    const files = normaliseFileList(event.target?.files);
    if (mdsState?.customFileInput) {
        mdsState.customFileInput.value = '';
    }
    void handleCustomFileSelection(files);
}

async function uploadCustomMetadataFiles(files) {
    if (!files.length) {
        setCustomMetadataMessage('Please choose one or more JSON files.', 'warning');
        return;
    }

    const formData = new FormData();
    files.forEach(file => {
        const name = typeof file.name === 'string' && file.name ? file.name : 'metadata.json';
        formData.append('files', file, name);
    });

    setCustomMetadataMessage('Uploading metadata…', 'info');

    try {
        const response = await fetch(CUSTOM_METADATA_UPLOAD_PATH, {
            method: 'POST',
            body: formData,
        });

        let payload = null;
        try {
            payload = await response.json();
        } catch (error) {
            payload = null;
        }

        const errors = Array.isArray(payload?.errors) ? payload.errors : [];
        if (!response.ok) {
            const message =
                (payload && typeof payload.error === 'string' && payload.error.trim()) ||
                errors.join(' ') ||
                'Failed to upload metadata files.';
            setCustomMetadataMessage(message, 'error');
            return;
        }

        customMetadataCache = null;
        const successMessage =
            errors.length > 0
                ? `Metadata uploaded with warnings: ${errors.join(' ')}`
                : 'Metadata uploaded successfully.';
        setCustomMetadataMessage(successMessage, errors.length ? 'warning' : 'success');

        await loadMdsData('Custom metadata updated.', { forceReload: true });
    } catch (error) {
        console.error('Failed to upload custom metadata files.', error);
        setCustomMetadataMessage('Failed to upload metadata files.', 'error');
    }
}

async function deleteCustomMetadata(storedFilename, options = {}) {
    const opts = options && typeof options === 'object' ? options : {};
    const triggerButton = opts.trigger instanceof HTMLButtonElement ? opts.trigger : null;
    const itemName =
        typeof opts.itemName === 'string' && opts.itemName.trim()
            ? opts.itemName.trim()
            : 'metadata file';

    if (!storedFilename) {
        setCustomMetadataMessage('Unable to delete the metadata file.', 'error');
        if (triggerButton) {
            setButtonBusy(triggerButton, false);
        }
        return;
    }

    setCustomMetadataMessage(`Removing ${itemName}…`, 'info');

    try {
        const response = await fetch(
            `${CUSTOM_METADATA_DELETE_PATH}/${encodeURIComponent(storedFilename)}`,
            { method: 'DELETE' },
        );

        let payload = null;
        try {
            payload = await response.json();
        } catch (error) {
            payload = null;
        }

        if (!response.ok) {
            const errorMessage =
                (payload && typeof payload.error === 'string' && payload.error.trim()) ||
                (payload && typeof payload.message === 'string' && payload.message.trim()) ||
                'Failed to delete metadata file.';
            const variant = response.status === 404 ? 'warning' : 'error';
            setCustomMetadataMessage(errorMessage, variant);
            if (triggerButton) {
                setButtonBusy(triggerButton, false);
            }
            return;
        }

        customMetadataCache = null;
        customMetadataPromise = null;

        await loadMdsData('Custom metadata updated.', { forceReload: true });
        setCustomMetadataMessage(`${itemName} removed.`, 'success');
    } catch (error) {
        console.error('Failed to delete custom metadata file.', error);
        setCustomMetadataMessage('Failed to delete metadata file.', 'error');
        if (triggerButton) {
            setButtonBusy(triggerButton, false);
        }
    }
}

if (typeof window !== 'undefined') {
    if (typeof window.__INITIAL_MDS_JWS__ === 'string' && window.__INITIAL_MDS_JWS__) {
        initialMdsJws = window.__INITIAL_MDS_JWS__;
    }
    if (window.__INITIAL_MDS_INFO__ && typeof window.__INITIAL_MDS_INFO__ === 'object') {
        initialMdsInfo = window.__INITIAL_MDS_INFO__;
    }
    try {
        delete window.__INITIAL_MDS_JWS__;
        delete window.__INITIAL_MDS_INFO__;
    } catch (error) {
        window.__INITIAL_MDS_JWS__ = undefined;
        window.__INITIAL_MDS_INFO__ = undefined;
    }
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

function scheduleHorizontalScrollMetricsUpdate() {
    if (horizontalScrollMetricsScheduled) {
        return;
    }
    horizontalScrollMetricsScheduled = true;
    const apply = () => {
        horizontalScrollMetricsScheduled = false;
        updateHorizontalScrollMetrics();
    };
    if (typeof requestAnimationFrame === 'function') {
        requestAnimationFrame(apply);
    } else {
        setTimeout(apply, 0);
    }
}

function clearHorizontalFloatingStyles(horizontal) {
    if (!horizontal) {
        return;
    }
    horizontal.style.left = '';
    horizontal.style.right = '';
    horizontal.style.bottom = '';
    horizontal.style.top = '';
    horizontal.style.width = '';
    horizontal.style.transform = '';
}

function hideHorizontalScroll(state = mdsState) {
    if (!state) {
        return;
    }

    const horizontal =
        state.horizontalScrollContainer instanceof HTMLElement ? state.horizontalScrollContainer : null;

    if (!horizontal) {
        return;
    }

    clearHorizontalFloatingStyles(horizontal);
    horizontal.hidden = true;
    horizontal.setAttribute('hidden', '');
    horizontal.setAttribute('aria-hidden', 'true');
    horizontal.classList.remove('is-ready');
    horizontal.classList.remove('is-overflowing');
    horizontal.classList.remove('is-floating');
}

function updateFloatingHorizontalScrollPosition(state = mdsState, metrics = {}) {
    if (!state) {
        return;
    }

    const horizontal =
        state.horizontalScrollContainer instanceof HTMLElement ? state.horizontalScrollContainer : null;
    const container = state.tableContainer instanceof HTMLElement ? state.tableContainer : null;

    if (!horizontal || !container) {
        return;
    }

    const rect = metrics.containerRect || container.getBoundingClientRect();
    if (!rect) {
        clearHorizontalFloatingStyles(horizontal);
        horizontal.classList.remove('is-floating');
        return;
    }

    const viewportHeight =
        typeof metrics.viewportHeight === 'number'
            ? metrics.viewportHeight
            : typeof window !== 'undefined'
              ? window.innerHeight || document.documentElement?.clientHeight || 0
              : 0;
    const viewportWidth =
        typeof metrics.viewportWidth === 'number'
            ? metrics.viewportWidth
            : typeof window !== 'undefined'
              ? window.innerWidth || document.documentElement?.clientWidth || 0
              : 0;

    if (!viewportHeight || !viewportWidth) {
        clearHorizontalFloatingStyles(horizontal);
        horizontal.classList.remove('is-floating');
        return;
    }

    const sideMargin = FLOATING_SCROLL_SIDE_MARGIN;
    const bottomMargin = FLOATING_SCROLL_BOTTOM_MARGIN;

    const rawWidth = Number.isFinite(rect.width) ? rect.width : viewportWidth;
    const maxWidth = viewportWidth - sideMargin * 2;
    let width = rawWidth;
    if (maxWidth > 0) {
        width = Math.min(width, maxWidth);
    }
    width = Math.max(0, width);
    if (!width) {
        clearHorizontalFloatingStyles(horizontal);
        horizontal.classList.remove('is-floating');
        return;
    }
    horizontal.style.width = `${Math.round(width)}px`;

    const maxLeft = viewportWidth - sideMargin - width;
    const preferredLeft = Number.isFinite(rect.left) ? rect.left : sideMargin;
    let left;
    if (maxLeft >= sideMargin) {
        left = Math.min(Math.max(preferredLeft, sideMargin), maxLeft);
    } else {
        left = Math.max(preferredLeft, sideMargin);
    }
    horizontal.style.left = `${Math.round(left)}px`;
    horizontal.style.right = 'auto';

    const offsetFromBottom = viewportHeight - rect.bottom;
    const bottomOffset = Math.max(bottomMargin, offsetFromBottom);
    horizontal.style.bottom = `${Math.round(bottomOffset)}px`;
    horizontal.style.top = 'auto';
    horizontal.classList.add('is-floating');
}

function updateHorizontalScrollMetrics(state = mdsState) {
    if (!state) {
        return;
    }

    const table = state.table instanceof HTMLElement ? state.table : null;
    const container = state.tableContainer instanceof HTMLElement ? state.tableContainer : null;
    const horizontal =
        state.horizontalScrollContainer instanceof HTMLElement ? state.horizontalScrollContainer : null;
    const content =
        state.horizontalScrollContent instanceof HTMLElement ? state.horizontalScrollContent : null;

    if (!horizontal) {
        return;
    }

    const tableWidth = table ? table.scrollWidth : 0;
    const containerWidth = container ? container.clientWidth : 0;
    const targetWidth = Math.max(tableWidth, containerWidth);
    const safeWidth = Number.isFinite(targetWidth) ? targetWidth : 0;

    if (content) {
        content.style.width = `${safeWidth}px`;
    }

    const overflowing = table && container ? tableWidth > containerWidth + 1 : false;
    horizontal.classList.toggle('is-overflowing', Boolean(overflowing));

    const viewportHeight =
        typeof window !== 'undefined'
            ? window.innerHeight || document.documentElement?.clientHeight || 0
            : 0;
    const viewportWidth =
        typeof window !== 'undefined'
            ? window.innerWidth || document.documentElement?.clientWidth || 0
            : 0;
    const containerRect = container ? container.getBoundingClientRect() : null;

    const containerVisible =
        containerRect &&
        viewportHeight > 0 &&
        containerRect.bottom > 0 &&
        containerRect.top < viewportHeight;

    if (!containerVisible) {
        hideHorizontalScroll(state);
        return;
    }

    if (horizontal.hidden) {
        horizontal.hidden = false;
        horizontal.removeAttribute('hidden');
    }
    horizontal.setAttribute('aria-hidden', 'false');
    horizontal.classList.add('is-ready');

    if (container && !isSyncingHorizontalScroll) {
        isSyncingHorizontalScroll = true;
        horizontal.scrollLeft = container.scrollLeft;
        isSyncingHorizontalScroll = false;
    }

    updateFloatingHorizontalScrollPosition(state, {
        containerRect,
        viewportHeight,
        viewportWidth,
    });
}

function syncHorizontalScrollPositions(source, target) {
    if (!source || !target) {
        return;
    }
    if (isSyncingHorizontalScroll) {
        return;
    }
    isSyncingHorizontalScroll = true;
    try {
        target.scrollLeft = source.scrollLeft;
    } finally {
        isSyncingHorizontalScroll = false;
    }
}

function nextAnimationFrame() {
    return new Promise(resolve => {
        if (typeof requestAnimationFrame === 'function') {
            requestAnimationFrame(() => resolve());
        } else {
            setTimeout(() => resolve(), 16);
        }
    });
}

async function waitForLayoutSettled() {
    await nextAnimationFrame();
    await nextAnimationFrame();
}

function waitForStateReady({ timeout = 5000 } = {}) {
    if (mdsState) {
        return Promise.resolve(true);
    }

    return new Promise(resolve => {
        const start = Date.now();
        const check = () => {
            if (mdsState) {
                resolve(true);
                return;
            }
            if (Date.now() - start >= timeout) {
                resolve(false);
                return;
            }
            if (typeof requestAnimationFrame === 'function') {
                requestAnimationFrame(check);
            } else {
                setTimeout(check, 32);
            }
        };
        check();
    });
}

function waitForRowByKey(key, { attempts = 60 } = {}) {
    if (!key) {
        return Promise.resolve(null);
    }

    return new Promise(resolve => {
        const attemptLookup = attempt => {
            if (!mdsState || mdsState.highlightedRowKey !== key) {
                resolve(null);
                return;
            }
            const row = findRowByKey(key);
            if (row) {
                resolve(row);
                return;
            }
            if (attempt >= attempts) {
                resolve(null);
                return;
            }
            const schedule = () => attemptLookup(attempt + 1);
            if (typeof requestAnimationFrame === 'function') {
                requestAnimationFrame(schedule);
            } else {
                setTimeout(schedule, attempt < 20 ? 16 : 64);
            }
        };
        attemptLookup(0);
    });
}

function scrollRowIntoView(row, { behavior = 'smooth' } = {}) {
    if (!(row instanceof HTMLElement)) {
        return;
    }

    if (typeof window === 'undefined' || typeof window.scrollTo !== 'function') {
        if (typeof row.scrollIntoView === 'function') {
            row.scrollIntoView({ behavior, block: 'center' });
        }
        return;
    }

    const rect = row.getBoundingClientRect();
    const viewportHeight = window.innerHeight || document.documentElement?.clientHeight || 0;
    const rowHeight = rect.height || row.offsetHeight || 0;
    const centerOffset = Math.max((viewportHeight - rowHeight) / 2, 0);
    const targetTop = rect.top + window.pageYOffset - centerOffset;
    const top = Math.max(Math.round(targetTop), 0);

    try {
        window.scrollTo({ top, behavior });
    } catch (error) {
        window.scrollTo(0, top);
    }
}

function focusRowButton(row) {
    if (!(row instanceof HTMLElement)) {
        return;
    }
    const button = row.querySelector('.mds-name-button');
    if (!(button instanceof HTMLElement) || typeof button.focus !== 'function') {
        return;
    }

    const focusButton = () => {
        try {
            button.focus({ preventScroll: true });
        } catch (error) {
            button.focus();
        }
    };

    if (typeof requestAnimationFrame === 'function') {
        requestAnimationFrame(focusButton);
    } else {
        setTimeout(focusButton, 0);
    }
}

function setHighlightedRow(row, key, { scroll = false, behavior = 'smooth', focus = false } = {}) {
    if (!mdsState || !(row instanceof HTMLElement)) {
        return false;
    }

    if (mdsState.highlightedRow && mdsState.highlightedRow !== row) {
        mdsState.highlightedRow.classList.remove('mds-row--highlight');
    }

    if (!row.classList.contains('mds-row--highlight')) {
        row.classList.add('mds-row--highlight');
    }

    mdsState.highlightedRow = row;
    if (key) {
        mdsState.highlightedRowKey = key;
    }

    if (scroll) {
        scrollRowIntoView(row, { behavior });
    }

    if (focus) {
        focusRowButton(row);
    }

    scheduleScrollTopButtonUpdate();
    return true;
}

function getSessionStorage() {
    if (typeof window === 'undefined') {
        return null;
    }
    try {
        return window.sessionStorage || null;
    } catch (error) {
        if (!sessionStorageWarningShown) {
            console.warn('Session storage unavailable:', error);
            sessionStorageWarningShown = true;
        }
        return null;
    }
}

function readMetadataCache() {
    const storage = getSessionStorage();
    if (!storage) {
        return null;
    }

    let payload = null;
    try {
        payload = storage.getItem(MDS_METADATA_STORAGE_KEY);
    } catch (error) {
        console.warn('Failed to read cached metadata payload:', error);
        return null;
    }

    if (!payload) {
        return null;
    }

    let metadata = null;
    try {
        metadata = JSON.parse(payload);
    } catch (error) {
        console.warn('Failed to parse cached metadata payload:', error);
        clearMetadataCache();
        return null;
    }

    let info = null;
    try {
        const infoRaw = storage.getItem(MDS_METADATA_INFO_KEY);
        if (infoRaw) {
            info = JSON.parse(infoRaw);
        }
    } catch (error) {
        info = null;
    }

    return { metadata, info };
}

function storeMetadataCache(payload, info) {
    const storage = getSessionStorage();
    if (!storage) {
        return;
    }

    try {
        if (typeof payload !== 'string' || !payload) {
            storage.removeItem(MDS_METADATA_STORAGE_KEY);
        } else {
            storage.setItem(MDS_METADATA_STORAGE_KEY, payload);
        }
        if (info && typeof info === 'object') {
            storage.setItem(MDS_METADATA_INFO_KEY, JSON.stringify(info));
        } else {
            storage.removeItem(MDS_METADATA_INFO_KEY);
        }
    } catch (error) {
        console.warn('Failed to cache metadata payload:', error);
    }
}

function clearMetadataCache() {
    const storage = getSessionStorage();
    if (!storage) {
        return;
    }
    try {
        storage.removeItem(MDS_METADATA_STORAGE_KEY);
        storage.removeItem(MDS_METADATA_INFO_KEY);
    } catch (error) {
        console.warn('Failed to clear cached metadata payload:', error);
    }

    customMetadataCache = null;
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
    scheduleHorizontalScrollMetricsUpdate();
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

    void loadMdsData();
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

    const addMetadataButton = root.querySelector('#mds-add-metadata-button');
    const customPanel = root.querySelector('#mds-custom-metadata-panel');
    const customPanelClose = root.querySelector('#mds-custom-panel-close');
    const customMessages = root.querySelector('#mds-custom-messages');
    const customList = root.querySelector('#mds-custom-list');
    const customDropzone = root.querySelector('#mds-custom-dropzone');
    const customFileInput = root.querySelector('#mds-custom-file-input');
    const customBackdrop = customPanel?.querySelector('[data-action="close"]');

    if (customPanel) {
        customPanel.addEventListener('keydown', handleCustomPanelKeydown);
    }

    if (customBackdrop instanceof HTMLElement) {
        customBackdrop.addEventListener('click', event => {
            event.preventDefault();
            closeCustomMetadataPanel();
        });
    }

    if (customPanelClose instanceof HTMLElement) {
        customPanelClose.addEventListener('click', event => {
            event.preventDefault();
            closeCustomMetadataPanel();
        });
    }

    if (addMetadataButton instanceof HTMLButtonElement) {
        addMetadataButton.type = 'button';
        addMetadataButton.setAttribute('aria-haspopup', 'dialog');
        addMetadataButton.setAttribute('aria-expanded', 'false');
        addMetadataButton.addEventListener('click', event => {
            event.preventDefault();
            openCustomMetadataPanel();
        });
        addMetadataButton.addEventListener('keydown', event => {
            if (event.key === 'Enter' || event.key === ' ') {
                event.preventDefault();
                openCustomMetadataPanel();
            }
        });
    }

    if (customDropzone instanceof HTMLElement) {
        const activateFileInput = () => {
            if (customFileInput instanceof HTMLInputElement) {
                customFileInput.click();
            }
        };

        customDropzone.addEventListener('click', event => {
            event.preventDefault();
            activateFileInput();
        });
        customDropzone.addEventListener('keydown', event => {
            if (event.key === 'Enter' || event.key === ' ') {
                event.preventDefault();
                activateFileInput();
            }
        });
        customDropzone.addEventListener('dragenter', handleCustomDropzoneDragEnter);
        customDropzone.addEventListener('dragover', handleCustomDropzoneDragEnter);
        customDropzone.addEventListener('dragleave', handleCustomDropzoneDragLeave);
        customDropzone.addEventListener('drop', handleCustomDrop);
    }

    if (customFileInput instanceof HTMLInputElement) {
        customFileInput.addEventListener('change', handleCustomFileInputChange);
    }

    const tableContainer = root.querySelector('#mds-table-container');
    const table = root.querySelector('.mds-table');
    const tableBody = root.querySelector('#mds-table-body');
    const horizontalScrollContainer = root.querySelector('#mds-horizontal-scroll');
    const horizontalScrollContent = horizontalScrollContainer
        ? horizontalScrollContainer.querySelector('.mds-horizontal-scroll__content')
        : null;

    if (horizontalScrollContainer) {
        horizontalScrollContainer.hidden = true;
        horizontalScrollContainer.setAttribute('hidden', '');
    }

    if (tableContainer) {
        const handleScroll = () => {
            scheduleScrollTopButtonUpdate();
            if (horizontalScrollContainer) {
                syncHorizontalScrollPositions(tableContainer, horizontalScrollContainer);
            }
        };
        tableContainer.addEventListener('scroll', handleScroll, { passive: true });
    }

    if (horizontalScrollContainer) {
        horizontalScrollContainer.addEventListener(
            'scroll',
            () => {
                if (tableContainer) {
                    syncHorizontalScrollPositions(horizontalScrollContainer, tableContainer);
                }
            },
            { passive: true },
        );
    }

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

    const listSection = root.querySelector('#mds-list-section');
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
    const authenticatorRawButton = root.querySelector('#mds-authenticator-modal-raw');
    if (authenticatorRawButton instanceof HTMLButtonElement) {
        authenticatorRawButton.addEventListener('click', event => {
            event.preventDefault();
            openAuthenticatorRawWindow();
        });
        authenticatorRawButton.disabled = true;
        authenticatorRawButton.setAttribute('aria-disabled', 'true');
        authenticatorRawButton.setAttribute('tabindex', '-1');
        authenticatorRawButton.setAttribute('title', 'Raw authenticator data unavailable');
    }

    const handleTabChanged = event => {
        if (event?.detail?.tab !== 'mds') {
            clearRowHighlight();
            hideScrollTopButton();
            hideHorizontalScroll(state);
        } else {
            scheduleScrollTopButtonUpdate();
            scheduleHorizontalScrollMetricsUpdate();
        }
    };
    if (typeof document !== 'undefined') {
        document.addEventListener('tab:changed', handleTabChanged);
    }

    const state = {
        root,
        listSection,
        listScrollTop: null,
        filters,
        filterInputs,
        dropdowns,
        tableContainer,
        table,
        tableBody,
        horizontalScrollContainer,
        horizontalScrollContent,
        sortButtons,
        sort: { key: DEFAULT_SORT_KEY, direction: DEFAULT_SORT_DIRECTION },
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
        columnResizersEnabled: false,
        addMetadataButton,
        customPanel,
        customPanelClose,
        customPanelMessages: customMessages,
        customList,
        customDropzone,
        customFileInput,
        customPanelIsOpen: false,
        customPanelReturnFocus: null,
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
        authenticatorModalRawButton: authenticatorRawButton,
        authenticatorRawWindow: null,
        activeDetailEntry: null,
        highlightedRow: null,
        highlightedRowKey: '',
        tabChangeHandler: handleTabChanged,
        byAaguid: new Map(),
        scrollTopButton,
        scrollTopButtonVisible: false,
    };

    updateCustomMetadataList(customMetadataItems, state);
    setCustomMetadataMessage('', 'info', state);

    setupColumnResizers(state);
    setColumnResizersEnabled(false, state);
    scheduleHorizontalScrollMetricsUpdate();
    return state;
}

async function applyMetadataEntries(metadata, { note = '' } = {}) {
    if (!mdsState) {
        return;
    }

    const rawEntries = Array.isArray(metadata?.entries) ? metadata.entries : [];
    const totalEntries = rawEntries.length;
    const shouldReportProgress = loaderIsActive() && !hasLoaded;
    const entries = [];

    if (shouldReportProgress) {
        const initialProgress = totalEntries ? 58 : 72;
        loaderSetPhase('Processing authenticator metadata…', { progress: initialProgress });
        loaderSetMetadataCount(0);
    }

    if (totalEntries) {
        const progressBase = 58;
        const progressRange = 32;
        let processedCount = 0;

        rawEntries.forEach((entry, index) => {
            processedCount += 1;
            const transformed = transformEntry(entry, index);
            if (transformed) {
                entries.push(transformed);
                if (shouldReportProgress) {
                    loaderSetMetadataCount(entries.length);
                }
            }

            if (shouldReportProgress) {
                const ratio = processedCount / totalEntries;
                const progress = progressBase + Math.min(progressRange, ratio * progressRange);
                loaderSetProgress(progress);
            }
        });
    } else {
        if (shouldReportProgress) {
            loaderSetProgress(88);
        }
    }

    mdsData = entries;
    setUpdateButtonMode('update');
    resetSortState();

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

    const nextUpdateRaw = typeof metadata?.nextUpdate === 'string' ? metadata.nextUpdate : '';
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

    try {
        await populateCertificateDerivedInfo(mdsData);
    } catch (error) {
        console.error('Failed to derive attestation certificate details:', error);
    }

    applyFilters();
    scheduleHorizontalScrollMetricsUpdate();

    hasLoaded = true;

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

    if (metadata?.legalHeader && mdsState.statusEl) {
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

    setColumnResizersEnabled(true);

    if (shouldReportProgress) {
        loaderSetMetadataCount(entries.length);
        loaderSetPhase('Finalising interface…', { progress: 94 });
        loaderComplete({ message: 'Application ready!', delay: 720 });
    }
}

async function applyInitialMetadataPayload(note) {
    if (initialMdsJws === null || typeof initialMdsJws !== 'string') {
        initialMdsJws = null;
        initialMdsInfo = initialMdsInfo && typeof initialMdsInfo === 'object' ? initialMdsInfo : null;
        return false;
    }

    const snapshotJws = initialMdsJws;
    const snapshotInfo = initialMdsInfo && typeof initialMdsInfo === 'object' ? initialMdsInfo : null;
    initialMdsJws = null;
    initialMdsInfo = null;

    try {
        const payloadSegment = snapshotJws.split('.')[1];
        if (!payloadSegment) {
            throw new Error('Invalid metadata BLOB format.');
        }
        const payload = decodeBase64Url(payloadSegment);
        const metadata = JSON.parse(payload);

        const enhancedMetadata = await ensureCustomMetadata(metadata);
        await applyMetadataEntries(enhancedMetadata, { note });
        storeMetadataCache(JSON.stringify(enhancedMetadata), snapshotInfo);
        return true;
    } catch (error) {
        console.error('Failed to apply initial metadata payload:', error);
        return false;
    }
}

async function loadMdsData(statusNote, options = {}) {
    if (!mdsState) {
        return;
    }

    const opts = options && typeof options === 'object' ? options : {};
    const forceReload = Boolean(opts.forceReload);

    if (hasLoaded && !forceReload) {
        return;
    }

    if (isLoading && loadPromise) {
        await loadPromise;
        return;
    }

    const note = typeof statusNote === 'string' ? statusNote.trim() : '';
    const previousHasLoaded = hasLoaded;
    const trackProgress = loaderIsActive() && !hasLoaded;

    if (trackProgress) {
        loaderSetPhase('Loading authenticator metadata…', { progress: 46 });
        loaderSetMetadataCount(0);
    }

    if (forceReload) {
        initialMdsJws = null;
        initialMdsInfo = null;
    }

    if (!forceReload) {
        if (!hasLoaded) {
            try {
                if (trackProgress && typeof initialMdsJws === 'string' && initialMdsJws) {
                    loaderSetPhase('Applying server metadata snapshot…', { progress: 52 });
                }
                const applied = await applyInitialMetadataPayload(note);
                if (applied) {
                    setColumnResizersEnabled(hasLoaded);
                    return;
                }
            } catch (error) {
                console.warn('Failed to apply server-provided metadata payload:', error);
            }
        }

        const cached = readMetadataCache();
        if (cached?.metadata) {
            try {
                if (trackProgress) {
                    loaderSetPhase('Restoring cached authenticator metadata…', { progress: 52 });
                }
                const enhanced = await ensureCustomMetadata(cached.metadata);
                await applyMetadataEntries(enhanced, { note });
                storeMetadataCache(JSON.stringify(enhanced), cached.info || null);
                setColumnResizersEnabled(hasLoaded);
                return;
            } catch (error) {
                console.warn('Failed to apply cached metadata payload:', error);
                clearMetadataCache();
            }
        }
    }

    setStatus('Loading metadata BLOB…', 'info');
    setColumnResizersEnabled(false);
    isLoading = true;
    let stateUpdated = false;

    const task = (async () => {
        try {
            const fetchOptions = forceReload ? { cache: 'reload' } : { cache: 'no-cache' };
            if (trackProgress) {
                const phaseLabel = forceReload
                    ? 'Refreshing authenticator metadata…'
                    : 'Downloading authenticator metadata…';
                loaderSetPhase(phaseLabel, { progress: 52 });
            }
            const response = await fetch(MDS_JWS_PATH, fetchOptions);
            if (!response.ok) {
                if (response.status === 404) {
                    const fallbackMetadata = await ensureCustomMetadata(null);
                    if (Array.isArray(fallbackMetadata.entries) && fallbackMetadata.entries.length) {
                        if (trackProgress) {
                            loaderSetPhase('Loading custom authenticator metadata…', { progress: 54 });
                        }
                        const fallbackNoteParts = [note, 'Using uploaded session metadata.'].filter(Boolean);
                        await applyMetadataEntries(fallbackMetadata, {
                            note: fallbackNoteParts.join(' '),
                        });
                        setUpdateButtonMode('download');
                        setUpdateButtonAttention(false);
                        storeMetadataCache(JSON.stringify(fallbackMetadata), {
                            cachedAt: new Date().toISOString(),
                            source: 'session-custom',
                        });
                        stateUpdated = true;
                        return;
                    }

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
                        cell.textContent = message;
                        emptyRow.appendChild(cell);
                        tbody.appendChild(emptyRow);
                    }
                    hideScrollTopButton();
                    resetSortState();
                    scheduleHorizontalScrollMetricsUpdate();
                    clearMetadataCache();
                    stateUpdated = true;
                    hasLoaded = false;
                    if (trackProgress) {
                        loaderSetPhase('Metadata unavailable. Continuing without authenticator data.', { progress: 92 });
                        loaderComplete({ message: 'Application ready!', delay: 720 });
                    }
                    return;
                }
                throw new Error(`Unexpected response status: ${response.status}`);
            }

            if (trackProgress) {
                loaderSetPhase('Decoding metadata payload…', { progress: 56 });
            }
            const jws = await response.text();
            const payloadSegment = jws.split('.')[1];
            if (!payloadSegment) {
                throw new Error('Invalid metadata BLOB format.');
            }

            const payload = decodeBase64Url(payloadSegment);
            const metadata = JSON.parse(payload);

            const enhanced = await ensureCustomMetadata(metadata);
            await applyMetadataEntries(enhanced, { note });
            stateUpdated = true;

            const lastModified = response.headers?.get('Last-Modified') || null;
            const etag = response.headers?.get('ETag') || null;
            storeMetadataCache(JSON.stringify(enhanced), {
                lastModified,
                etag,
                cachedAt: new Date().toISOString(),
            });
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
            if (!previousHasLoaded) {
                clearMetadataCache();
            }
            if (trackProgress) {
                loaderSetPhase('Unable to load authenticator metadata. Continuing with limited data.', { progress: 92 });
                loaderComplete({ message: 'Application ready!', delay: 720 });
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
        if (!stateUpdated && previousHasLoaded) {
            hasLoaded = true;
        }
        setColumnResizersEnabled(hasLoaded);
    }
}

async function waitForMetadataLoad() {
    const ready = await waitForStateReady();
    if (!ready || !mdsState) {
        return false;
    }
    if (hasLoaded && !isLoading) {
        return true;
    }
    if (isLoading && loadPromise) {
        await loadPromise;
        return hasLoaded;
    }
    await loadMdsData();
    return hasLoaded;
}

function getMdsLoadStateSnapshot() {
    return {
        hasLoaded,
        isLoading,
    };
}

function applyFilters(options = {}) {
    if (!mdsState) {
        return;
    }

    const { preserveTableScroll = false } = options;

    const activeFilters = mdsState.filters;
    const matched = mdsData.filter(entry => matchesFilters(entry, activeFilters));
    const sorted = applySorting(matched);
    filteredData = sorted;
    renderTable(sorted, { preserveTableScroll });
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

function getNextSortDirection(sortKey, currentDirection) {
    const key = typeof sortKey === 'string' ? sortKey : '';
    const direction = currentDirection || SORT_NONE;
    const override = key && SORT_SEQUENCE_OVERRIDES[key];
    if (override && Object.prototype.hasOwnProperty.call(override, direction)) {
        return override[direction];
    }
    return SORT_SEQUENCE[direction] || SORT_ASCENDING;
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
        mdsState.sort = { key: DEFAULT_SORT_KEY, direction: DEFAULT_SORT_DIRECTION };
    } else {
        mdsState.sort.key = DEFAULT_SORT_KEY;
        mdsState.sort.direction = DEFAULT_SORT_DIRECTION;
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
        mdsState.sort = { key: DEFAULT_SORT_KEY, direction: DEFAULT_SORT_DIRECTION };
    }

    const currentKey = mdsState.sort.key;
    const currentDirection = mdsState.sort.direction || SORT_NONE;
    const baseDirection = currentKey === key ? currentDirection : SORT_NONE;
    const nextDirection = getNextSortDirection(key, baseDirection);

    if (nextDirection === SORT_NONE) {
        resetSortState();
    } else {
        mdsState.sort.key = key;
        mdsState.sort.direction = nextDirection;
    }

    if (nextDirection !== SORT_NONE) {
        updateSortButtonState();
    }
    applyFilters({ preserveTableScroll: true });
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

function renderTable(entries, options = {}) {
    if (!mdsState?.tableBody) {
        return;
    }

    const { preserveTableScroll = false } = options;
    const container =
        mdsState.tableContainer instanceof HTMLElement ? mdsState.tableContainer : null;
    const horizontal =
        mdsState.horizontalScrollContainer instanceof HTMLElement ? mdsState.horizontalScrollContainer : null;

    let preservedScroll = null;
    if (preserveTableScroll && container) {
        const left = Number.isFinite(container.scrollLeft) ? container.scrollLeft : null;
        const top = Number.isFinite(container.scrollTop) ? container.scrollTop : null;
        if (left !== null || top !== null) {
            preservedScroll = { left, top };
        }
    }

    const adjustScrollPosition = () => {
        if (!container) {
            return;
        }
        if (preservedScroll) {
            const restore = () => {
                if (typeof preservedScroll.left === 'number') {
                    container.scrollLeft = preservedScroll.left;
                    if (horizontal) {
                        horizontal.scrollLeft = preservedScroll.left;
                    }
                }
                if (typeof preservedScroll.top === 'number') {
                    container.scrollTop = preservedScroll.top;
                }
            };
            restore();
            if (typeof requestAnimationFrame === 'function') {
                requestAnimationFrame(restore);
            }
            return;
        }
        resetScrollPositions(container, horizontal);
    };

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
        adjustScrollPosition();
        scheduleHorizontalScrollMetricsUpdate();
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
    adjustScrollPosition();
    if (mdsState.highlightedRowKey) {
        const restored = applyRowHighlightByKey(mdsState.highlightedRowKey, { scroll: false });
        if (!restored) {
            mdsState.highlightedRow = null;
        }
    }
    stabiliseColumnWidths();
    scheduleScrollTopButtonUpdate();
    scheduleHorizontalScrollMetricsUpdate();
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
        if (!(field instanceof HTMLElement)) {
            return;
        }
        if (field instanceof HTMLTextAreaElement) {
            field.style.height = 'auto';
            field.style.overflowY = 'hidden';
            field.style.overflowX = 'hidden';
            const { scrollHeight } = field;
            if (Number.isFinite(scrollHeight)) {
                field.style.height = `${scrollHeight}px`;
            }
            return;
        }

        field.style.removeProperty('height');
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
        if (field instanceof HTMLElement) {
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

    const applied = setHighlightedRow(row, key, options);
    return applied ? row : false;
}

function isElementVisible(element) {
    if (!(element instanceof HTMLElement)) {
        return false;
    }
    if (element.offsetParent !== null) {
        return true;
    }
    const style = window.getComputedStyle ? window.getComputedStyle(element) : null;
    if (!style) {
        return false;
    }
    return style.display !== 'none' && style.visibility !== 'hidden' && style.opacity !== '0';
}

function waitForElementVisible(element, { timeout = 2000, interval = 32 } = {}) {
    if (isElementVisible(element)) {
        return Promise.resolve(true);
    }

    return new Promise(resolve => {
        const start = Date.now();
        const check = () => {
            if (isElementVisible(element)) {
                resolve(true);
                return;
            }
            if (Date.now() - start >= timeout) {
                resolve(false);
                return;
            }
            if (typeof requestAnimationFrame === 'function') {
                requestAnimationFrame(check);
            } else {
                setTimeout(check, interval);
            }
        };
        check();
    });
}

function showAuthenticatorDetail(entry, options = {}) {
    if (!mdsState || !entry) {
        return;
    }

    clearRowHighlight();

    const key = normaliseAaguid(entry.aaguid || entry.id);
    let sourceEntry = entry;
    if (key && mdsState.byAaguid?.has(key)) {
        sourceEntry = mdsState.byAaguid.get(key);
    } else if (typeof entry.index === 'number' && mdsData[entry.index]) {
        sourceEntry = mdsData[entry.index];
    }

    mdsState.activeDetailEntry = sourceEntry;

    const { scrollIntoView = false } = options;
    if (scrollIntoView && key) {
        const row = findRowByKey(key);
        if (row) {
            const scroll = () => scrollRowIntoView(row, { behavior: 'smooth' });
            if (typeof requestAnimationFrame === 'function') {
                requestAnimationFrame(scroll);
            } else {
                scroll();
            }
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

    const algorithmChips = createChipList('Authentication Algorithms', formatRawListValues(metadata.authenticationAlgorithms));
    if (algorithmChips) {
        metadataSection.appendChild(algorithmChips);
    }
    const encodingChips = createChipList('Public Key Algorithms', formatRawListValues(metadata.publicKeyAlgAndEncodings));
    if (encodingChips) {
        metadataSection.appendChild(encodingChips);
    }
    const attestationChips = createChipList('Attestation Types', formatRawListValues(metadata.attestationTypes));
    if (attestationChips) {
        metadataSection.appendChild(attestationChips);
    }
    const keyProtectionChips = createChipList('Key Protection', formatRawListValues(metadata.keyProtection));
    if (keyProtectionChips) {
        metadataSection.appendChild(keyProtectionChips);
    }
    const matcherChips = createChipList('Matcher Protection', formatRawListValues(metadata.matcherProtection));
    if (matcherChips) {
        metadataSection.appendChild(matcherChips);
    }
    const attachmentChips = createChipList('Attachment Hints', formatRawListValues(metadata.attachmentHint));
    if (attachmentChips) {
        metadataSection.appendChild(attachmentChips);
    }
    const displayChips = createChipList('TC Display', formatRawListValues(metadata.tcDisplay));
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
            const method = item.userVerificationMethod !== undefined && item.userVerificationMethod !== null
                ? String(item.userVerificationMethod)
                : '';
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

function formatRawListValues(value) {
    return extractList(value)
        .map(item => toRawDisplayString(item))
        .filter(text => text !== '');
}

function formatAuthenticatorInfoValues(value) {
    return formatRawListValues(value);
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

    const versionChips = createChipList('Versions', formatAuthenticatorInfoValues(info.versions));
    if (versionChips) {
        section.appendChild(versionChips);
    }
    const extensionChips = createChipList('Extensions', formatAuthenticatorInfoValues(info.extensions));
    if (extensionChips) {
        section.appendChild(extensionChips);
    }
    const transportChips = createChipList('Transports', formatAuthenticatorInfoValues(info.transports));
    if (transportChips) {
        section.appendChild(transportChips);
    }
    const algorithmChips = createChipList('Algorithms', formatAuthenticatorInfoValues(info.algorithms));
    if (algorithmChips) {
        section.appendChild(algorithmChips);
    }
    const pinProtocols = formatAuthenticatorInfoValues(info.pinUvAuthProtocols);
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

function getAuthenticatorRawData(entry) {
    if (!entry || typeof entry !== 'object') {
        return null;
    }

    const rawEntry = entry.rawEntry;
    const base = rawEntry && typeof rawEntry === 'object' && !Array.isArray(rawEntry)
        ? { ...rawEntry }
        : {};

    const metadata = entry.metadataStatement && typeof entry.metadataStatement === 'object'
        ? entry.metadataStatement
        : null;
    if (metadata && base.metadataStatement === undefined) {
        base.metadataStatement = metadata;
    }

    if (base.attestationCertificateKeyIdentifiers === undefined) {
        const identifiers = Array.isArray(entry.attestationKeyIdentifiers)
            ? entry.attestationKeyIdentifiers
            : [];
        if (identifiers.length) {
            base.attestationCertificateKeyIdentifiers = identifiers;
        }
    }

    if (base.statusReports === undefined && Array.isArray(entry.statusReports) && entry.statusReports.length) {
        base.statusReports = entry.statusReports;
    }

    if (base.aaguid === undefined && entry.aaguid) {
        base.aaguid = entry.aaguid;
    }

    if (base.id === undefined && entry.id) {
        base.id = entry.id;
    }

    if (base.timeOfLastStatusChange === undefined) {
        if (rawEntry && typeof rawEntry === 'object' && rawEntry.timeOfLastStatusChange) {
            base.timeOfLastStatusChange = rawEntry.timeOfLastStatusChange;
        } else if (entry.timeOfLastStatusChange) {
            base.timeOfLastStatusChange = entry.timeOfLastStatusChange;
        }
    }

    return Object.keys(base).length ? base : null;
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
        statusCell.textContent = report.status !== undefined && report.status !== null
            ? String(report.status)
            : '—';
        row.appendChild(statusCell);

        const dateCell = document.createElement('td');
        dateCell.textContent = report.effectiveDate !== undefined && report.effectiveDate !== null
            ? String(report.effectiveDate)
            : '—';
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

function setCertificateFieldContent(field, value) {
    if (!(field instanceof HTMLElement)) {
        return;
    }

    const content = typeof value === 'string' ? value : '';
    if ('value' in field) {
        field.value = content;
    } else {
        field.textContent = content;
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
        setCertificateFieldContent(mdsState.certificateInput, formatCertificateInput(cleaned));
        mdsState.certificateInput.scrollTop = 0;
        mdsState.certificateInput.scrollLeft = 0;
    }
    if (mdsState.certificateOutput) {
        setCertificateFieldContent(mdsState.certificateOutput, 'Decoding certificate…');
        mdsState.certificateOutput.scrollTop = 0;
        mdsState.certificateOutput.scrollLeft = 0;
    }
    if (mdsState.certificateTitle) {
        mdsState.certificateTitle.textContent = 'Attestation Certificate';
    }

    setCertificateSummaryContent('Decoding certificate…');

    mdsState.certificateModal.classList.remove('is-closing');
    mdsState.certificateModal.hidden = false;
    mdsState.certificateModal.setAttribute('aria-hidden', 'false');
    if (typeof requestAnimationFrame === 'function') {
        requestAnimationFrame(() => {
            if (mdsState?.certificateModal?.hidden) {
                return;
            }
            mdsState.certificateModal.classList.add('is-open');
        });
    } else {
        mdsState.certificateModal.classList.add('is-open');
    }
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
            setCertificateFieldContent(mdsState.certificateOutput, formatCertificateOutput(details));
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
            setCertificateFieldContent(mdsState.certificateOutput, message);
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

    const modal = mdsState.certificateModal;

    let completed = false;
    let fallbackTimeout;
    const finishClose = () => {
        if (completed) {
            return;
        }
        completed = true;
        if (fallbackTimeout) {
            clearTimeout(fallbackTimeout);
            fallbackTimeout = undefined;
        }
        modal.classList.remove('is-open');
        modal.classList.remove('is-closing');
        modal.hidden = true;
        modal.setAttribute('aria-hidden', 'true');
        resetScrollPositions(
            mdsState.certificateModalBody,
            mdsState.certificateSummary,
            mdsState.certificateInput,
            mdsState.certificateOutput,
        );
        resetCertificateTextareaHeights();
        notifyGlobalScrollLock();
    };

    if (!modal.classList.contains('is-open')) {
        finishClose();
        return;
    }

    modal.classList.remove('is-open');
    modal.classList.add('is-closing');

    const handleTransitionEnd = event => {
        if (event.target !== modal || event.propertyName !== 'opacity') {
            return;
        }
        modal.removeEventListener('transitionend', handleTransitionEnd);
        finishClose();
    };

    modal.addEventListener('transitionend', handleTransitionEnd);
    fallbackTimeout = setTimeout(() => {
        modal.removeEventListener('transitionend', handleTransitionEnd);
        finishClose();
    }, 280);
}

function openAuthenticatorRawWindow() {
    if (!mdsState) {
        return;
    }

    const entry = mdsState.activeDetailEntry;
    const rawData = getAuthenticatorRawData(entry);
    if (!rawData) {
        return;
    }

    const rawText = stringifyAuthenticatorRawData(rawData);
    if (!rawText || typeof window === 'undefined') {
        return;
    }

    const viewportWidth = Number.isFinite(window.innerWidth) && window.innerWidth > 0
        ? window.innerWidth
        : (window.screen && Number.isFinite(window.screen.availWidth) ? window.screen.availWidth : 1280);
    const viewportHeight = Number.isFinite(window.innerHeight) && window.innerHeight > 0
        ? window.innerHeight
        : (window.screen && Number.isFinite(window.screen.availHeight) ? window.screen.availHeight : 720);

    const width = Math.max(Math.round(viewportWidth * 0.8), 640);
    const height = Math.max(Math.round(viewportHeight * 0.8), 480);
    const features = `popup=yes,width=${width},height=${height},resizable=yes,scrollbars=yes`;
    const viewerName = 'mdsAuthenticatorRawViewer';

    let viewer = mdsState.authenticatorRawWindow;
    if (!viewer || viewer.closed) {
        viewer = window.open('', viewerName, features);
    } else {
        viewer.focus();
        try {
            viewer.resizeTo(width, height);
        } catch (error) {
            // Ignore resize errors caused by browser restrictions.
        }
    }

    if (!viewer) {
        return;
    }

    mdsState.authenticatorRawWindow = viewer;

    let doc;
    try {
        doc = viewer.document;
    } catch (error) {
        return;
    }

    if (!doc) {
        return;
    }

    const titleParts = [];
    if (entry?.name && typeof entry.name === 'string' && entry.name.trim()) {
        titleParts.push(entry.name.trim());
    }
    titleParts.push('Authenticator Raw Data');
    const titleText = titleParts.join(' – ');
    const subtitleText = formatDetailSubtitle(entry);

    const template = `<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <title>Authenticator Raw Data</title>
    <style>
        :root { color-scheme: light; }
        body {
            margin: 0;
            font-family: 'SFMono-Regular', 'JetBrains Mono', 'Fira Code', monospace;
            background: #f4f7fb;
            color: #0f2740;
        }
        .raw-window {
            display: flex;
            flex-direction: column;
            height: 100vh;
        }
        header {
            padding: 1rem 1.5rem;
            background: #ffffff;
            border-bottom: 1px solid rgba(15, 39, 64, 0.12);
            box-shadow: 0 6px 18px rgba(15, 39, 64, 0.05);
        }
        h1 {
            margin: 0;
            font-size: 1.1rem;
            font-weight: 700;
        }
        p {
            margin: 0.35rem 0 0;
            font-size: 0.85rem;
            color: #48607a;
        }
        textarea {
            flex: 1;
            width: 100%;
            border: none;
            resize: none;
            padding: 1.25rem;
            background: #ffffff;
            font-family: 'SFMono-Regular', 'JetBrains Mono', 'Fira Code', monospace;
            font-size: 0.85rem;
            line-height: 1.5;
            color: inherit;
            box-sizing: border-box;
            outline: none;
        }
        textarea:focus {
            outline: none;
        }
    </style>
</head>
<body>
    <div class="raw-window">
        <header>
            <h1 id="mds-raw-title">Authenticator Raw Data</h1>
            <p id="mds-raw-subtitle" style="display: none;"></p>
        </header>
        <textarea id="mds-raw-textarea" readonly spellcheck="false" wrap="off" aria-label="Raw authenticator metadata"></textarea>
    </div>
</body>
</html>`;

    doc.open();
    doc.write(template);
    doc.close();

    doc.title = titleText;

    const titleEl = doc.getElementById('mds-raw-title');
    if (titleEl) {
        titleEl.textContent = titleText;
    }

    const subtitleEl = doc.getElementById('mds-raw-subtitle');
    if (subtitleEl) {
        if (subtitleText) {
            subtitleEl.textContent = subtitleText;
            subtitleEl.style.display = '';
        } else {
            subtitleEl.textContent = '';
            subtitleEl.style.display = 'none';
        }
    }

    const textarea = doc.getElementById('mds-raw-textarea');
    if (textarea) {
        textarea.value = rawText;
        textarea.scrollTop = 0;
        textarea.scrollLeft = 0;
        if (typeof textarea.setSelectionRange === 'function') {
            try {
                textarea.setSelectionRange(0, 0);
            } catch (error) {
                // Ignore selection errors in unsupported browsers.
            }
        }
        if (typeof textarea.focus === 'function') {
            textarea.focus();
        }
    }

    try {
        viewer.focus();
    } catch (error) {
        // Some browsers may block programmatic focus; ignore.
    }

    try {
        viewer.onbeforeunload = () => {
            if (mdsState && mdsState.authenticatorRawWindow === viewer) {
                mdsState.authenticatorRawWindow = null;
            }
        };
    } catch (error) {
        // Ignore if the viewer does not permit assigning event handlers.
    }
}

const RAW_TEXT_INDENT = '    ';

function stringifyAuthenticatorRawData(value) {
    const seen = typeof WeakSet === 'function' ? new WeakSet() : null;
    const replacer = (key, currentValue) => {
        if (typeof currentValue === 'bigint') {
            return currentValue.toString();
        }
        if (typeof Map !== 'undefined' && currentValue instanceof Map) {
            return Object.fromEntries(currentValue);
        }
        if (typeof Set !== 'undefined' && currentValue instanceof Set) {
            return Array.from(currentValue);
        }
        if (typeof ArrayBuffer !== 'undefined') {
            if (currentValue instanceof ArrayBuffer) {
                return Array.from(new Uint8Array(currentValue));
            }
            if (typeof ArrayBuffer.isView === 'function' && ArrayBuffer.isView(currentValue)) {
                const view = new Uint8Array(
                    currentValue.buffer,
                    currentValue.byteOffset || 0,
                    currentValue.byteLength || currentValue.length || 0,
                );
                return Array.from(view);
            }
        }
        if (currentValue && typeof currentValue === 'object' && seen) {
            if (seen.has(currentValue)) {
                return '[Circular]';
            }
            seen.add(currentValue);
        }
        return currentValue;
    };

    try {
        return JSON.stringify(value, replacer, 4);
    } catch (error) {
        const lines = buildAuthenticatorRawLines(value);
        return lines.join('\n');
    }
}

function buildAuthenticatorRawLines(value, depth = 0, label) {
    const indent = RAW_TEXT_INDENT.repeat(depth);
    const lines = [];

    const addLine = text => {
        if (text !== undefined && text !== null) {
            lines.push(text);
        }
    };

    if (label !== undefined) {
        if (Array.isArray(value)) {
            addLine(`${indent}${label}:`);
            if (!value.length) {
                addLine(`${indent}${RAW_TEXT_INDENT}[]`);
                return lines;
            }
            value.forEach(item => {
                if (Array.isArray(item) || isPlainObject(item)) {
                    const childLines = buildAuthenticatorRawLines(item, depth + 1);
                    lines.push(...childLines);
                } else {
                    addLine(`${indent}${RAW_TEXT_INDENT}${formatRawPrimitive(item)}`);
                }
            });
            return lines;
        }

        if (isPlainObject(value)) {
            addLine(`${indent}${label}:`);
            const keys = Object.keys(value);
            if (!keys.length) {
                addLine(`${indent}${RAW_TEXT_INDENT}{}`);
                return lines;
            }
            keys.forEach(key => {
                const childLines = buildAuthenticatorRawLines(value[key], depth + 1, key);
                lines.push(...childLines);
            });
            return lines;
        }

        addLine(`${indent}${label}: ${formatRawPrimitive(value)}`);
        return lines;
    }

    if (Array.isArray(value)) {
        if (!value.length) {
            addLine(`${indent}[]`);
            return lines;
        }
        value.forEach(item => {
            if (Array.isArray(item) || isPlainObject(item)) {
                const childLines = buildAuthenticatorRawLines(item, depth + 1);
                lines.push(...childLines);
            } else {
                addLine(`${indent}${RAW_TEXT_INDENT}${formatRawPrimitive(item)}`);
            }
        });
        return lines;
    }

    if (isPlainObject(value)) {
        const keys = Object.keys(value);
        if (!keys.length) {
            addLine(`${indent}{}`);
            return lines;
        }
        keys.forEach(key => {
            const childLines = buildAuthenticatorRawLines(value[key], depth, key);
            lines.push(...childLines);
        });
        return lines;
    }

    addLine(`${indent}${formatRawPrimitive(value)}`);
    return lines;
}

function formatRawPrimitive(value) {
    if (value === undefined) {
        return 'undefined';
    }
    if (value === null) {
        return 'null';
    }
    if (typeof value === 'string') {
        try {
            return JSON.stringify(value);
        } catch (error) {
            return `"${value.replace(/"/g, '\\"')}"`;
        }
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

function isPlainObject(value) {
    return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

function updateAuthenticatorRawButton(entry) {
    const button = mdsState?.authenticatorModalRawButton;
    if (!(button instanceof HTMLButtonElement)) {
        return;
    }

    const rawData = getAuthenticatorRawData(entry);
    const hasRawData = rawData && typeof rawData === 'object' && Object.keys(rawData).length > 0;

    button.disabled = !hasRawData;
    button.setAttribute('aria-disabled', hasRawData ? 'false' : 'true');
    button.setAttribute('title', hasRawData ? 'View raw authenticator data' : 'Raw authenticator data unavailable');
    if (hasRawData) {
        button.removeAttribute('tabindex');
    } else {
        button.setAttribute('tabindex', '-1');
    }
}

function suppressListSection(section) {
    if (!section) {
        return;
    }
    if (!('mdsDetailVisibility' in section.dataset)) {
        section.dataset.mdsDetailVisibility = section.style.visibility || '';
    }
    if (!('mdsDetailPointerEvents' in section.dataset)) {
        section.dataset.mdsDetailPointerEvents = section.style.pointerEvents || '';
    }
    if (!('mdsDetailUserSelect' in section.dataset)) {
        section.dataset.mdsDetailUserSelect = section.style.userSelect || '';
    }
    section.setAttribute('aria-hidden', 'true');
    section.style.visibility = 'hidden';
    section.style.pointerEvents = 'none';
    section.style.userSelect = 'none';
}

function restoreListSection(section) {
    if (!section) {
        return;
    }
    section.removeAttribute('aria-hidden');
    const toCssProperty = name => name.replace(/[A-Z]/g, match => `-${match.toLowerCase()}`);
    const apply = (property, key) => {
        const value = section.dataset[key];
        if (value !== undefined && value !== null && value !== '') {
            section.style[property] = value;
        } else {
            section.style[property] = '';
            section.style.removeProperty(toCssProperty(property));
        }
        delete section.dataset[key];
    };
    apply('visibility', 'mdsDetailVisibility');
    apply('pointerEvents', 'mdsDetailPointerEvents');
    apply('userSelect', 'mdsDetailUserSelect');
}

function openAuthenticatorModal(entry) {
    if (!mdsState?.authenticatorModal) {
        return;
    }

    const modal = mdsState.authenticatorModal;

    if (entry) {
        mdsState.activeDetailEntry = entry;
    }
    const detailEntry = mdsState.activeDetailEntry || entry || null;
    hideScrollTopButton();

    updateAuthenticatorRawButton(detailEntry);

    applyDetailHeader(detailEntry, mdsState.authenticatorModalTitle, mdsState.authenticatorModalSubtitle);
    populateDetailContent(mdsState.authenticatorModalContent, detailEntry);

    let currentScroll = 0;
    if (typeof window !== 'undefined') {
        currentScroll =
            window.pageYOffset ||
            document.documentElement?.scrollTop ||
            document.body?.scrollTop ||
            0;
    }
    mdsState.listScrollTop = currentScroll;

    suppressListSection(mdsState.listSection);

    modal.classList.remove('mds-detail-page--open');
    modal.classList.remove('mds-detail-page--open');
    modal.hidden = false;
    modal.setAttribute('aria-hidden', 'false');
    const activateModal = () => {
        if (modal.hidden) {
            return;
        }
        modal.classList.add('mds-detail-page--open');
        notifyGlobalScrollLock();
    };
    if (typeof requestAnimationFrame === 'function') {
        requestAnimationFrame(activateModal);
    } else {
        activateModal();
    }

    resetScrollPositions(mdsState.authenticatorModalBody, modal, mdsState.authenticatorModalContent);

    const focusTarget = mdsState.authenticatorModalClose instanceof HTMLElement
        ? mdsState.authenticatorModalClose
        : null;
    if (focusTarget) {
        requestAnimationFrame(() => {
            focusTarget.focus();
        });
    }
}

function closeAuthenticatorModal() {
    if (!mdsState?.authenticatorModal) {
        return;
    }

    const modal = mdsState.authenticatorModal;

    if (modal.hidden) {
        return;
    }

    const previousScroll =
        typeof mdsState.listScrollTop === 'number' ? mdsState.listScrollTop : null;

    const finishClose = () => {
        modal.classList.remove('mds-detail-page--open');
        modal.hidden = true;
        modal.setAttribute('aria-hidden', 'true');

        restoreListSection(mdsState.listSection);

        resetScrollPositions(mdsState.authenticatorModalBody, modal, mdsState.authenticatorModalContent);
        notifyGlobalScrollLock();
        mdsState.activeDetailEntry = null;
        updateAuthenticatorRawButton(null);
        scheduleScrollTopButtonUpdate();
        if (previousScroll !== null && typeof window !== 'undefined') {
            requestAnimationFrame(() => {
                window.scrollTo(0, previousScroll);
            });
        }
        mdsState.listScrollTop = null;
    };

    finishClose();
}

async function resolveEntryByAaguid(aaguid) {
    const ready = await waitForStateReady();
    if (!ready || !mdsState) {
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
    if (!mdsState) {
        return { entry: entry || null, highlighted: false };
    }

    if (!entry) {
        return { entry: null, highlighted: false };
    }

    const key = normaliseAaguid(entry.aaguid || entry.id);
    if (!key) {
        return { entry, highlighted: false };
    }

    mdsState.highlightedRowKey = key;

    if (mdsState.authenticatorModal && !mdsState.authenticatorModal.hidden) {
        hideAuthenticatorDetail();
    }

    if (mdsState.root) {
        await waitForElementVisible(mdsState.root);
    }

    resetFilters();
    applyFilters();
    await waitForLayoutSettled();

    const row = await waitForRowByKey(key, { attempts: 80 });
    if (!row || mdsState.highlightedRowKey !== key) {
        if (mdsState.highlightedRowKey === key) {
            mdsState.highlightedRowKey = '';
        }
        return { entry, highlighted: false };
    }

    await waitForLayoutSettled();

    const applied = setHighlightedRow(row, key, { scroll: true, behavior: 'smooth', focus: true });
    if (!applied && mdsState.highlightedRowKey === key) {
        mdsState.highlightedRowKey = '';
    }

    return { entry, highlighted: Boolean(applied), row: applied ? row : null };
}

if (typeof window !== 'undefined') {
    window.openMdsAuthenticatorModal = openAuthenticatorModalByAaguid;
    window.focusMdsAuthenticator = focusAuthenticatorByAaguid;
    window.highlightMdsAuthenticatorRow = highlightAuthenticatorRowByAaguid;
    window.waitForMdsLoad = waitForMetadataLoad;
    window.getMdsLoadState = getMdsLoadStateSnapshot;
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
    scheduleHorizontalScrollMetricsUpdate();
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

function setColumnResizersEnabled(enabled, state = mdsState) {
    if (!state) {
        return;
    }

    const allow = Boolean(enabled);
    state.columnResizersEnabled = allow;

    if (!allow && state.columnResizeState) {
        handleColumnResizeEnd();
    }

    const resizers = Array.isArray(state.columnResizers) ? state.columnResizers : [];
    resizers.forEach(resizer => {
        if (!(resizer instanceof HTMLElement)) {
            return;
        }
        resizer.classList.toggle('is-disabled', !allow);
        if (allow) {
            resizer.removeAttribute('aria-disabled');
        } else {
            resizer.setAttribute('aria-disabled', 'true');
        }
    });

    if (allow) {
        scheduleColumnResizerMetricsUpdate();
    }
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
    if (isLoading || !hasLoaded || !mdsState.columnResizersEnabled) {
        event.preventDefault();
        event.stopPropagation();
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
    button.addEventListener('click', event => {
        event.preventDefault();
        event.stopPropagation();
        showAuthenticatorDetail(entry);
    });
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

        let payload;
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
            clearMetadataCache();
            await loadMdsData(note, { forceReload: true });
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
