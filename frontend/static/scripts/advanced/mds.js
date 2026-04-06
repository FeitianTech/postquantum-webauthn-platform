import {
    MDS_EXPLORER_PATH,
    MDS_EXPLORER_FULL_PATH,
    MDS_RESOLVE_PATH,
    MDS_VERIFIED_META_PATH,
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
    transformEntryLightweight,
    upgradeEntryToFull,
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
    loaderSetMetadataCount,
    loaderSetPhase,
    loaderSetProgress,
} from '../shared/loader.js';
import { initializeStickyHeaderForElement } from '../shared/ui.js';
import { createMdsLazyLoader } from './mds-lazy-loader.js';

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
let initialMdsInfo = null;
let initialMdsSnapshot = null;
let explorerPreloadPromise = null;
const resolvedEntryCache = new Map();
let lazyLoader = null;
let backgroundLoadingInProgress = false;
let certificateCursorRequestCount = 0;

const MDS_CERTIFICATE_LOADING_CURSOR_CLASS = 'mds-certificate-loading-cursor';


function normaliseSnapshotInfo(info) {
    if (!info || typeof info !== 'object') {
        return null;
    }

    const normalised = {};
    for (const [key, value] of Object.entries(info)) {
        if (typeof value === 'string') {
            normalised[key] = value.trim();
        } else {
            normalised[key] = value;
        }
    }
    return normalised;
}

function extractSnapshotTimestamp(info) {
    if (!info || typeof info !== 'object') {
        return null;
    }

    for (const key of [
        'generatedAt',
        'generated_at',
        'fetchedAt',
        'fetched_at',
        'lastModifiedIso',
        'last_modified_iso',
        'lastModified',
        'last_modified',
    ]) {
        const value = info[key];
        if (typeof value === 'string' && value.trim()) {
            return value.trim();
        }
    }
    return null;
}

function formatSnapshotTimestamp(info) {
    const raw = extractSnapshotTimestamp(info);
    if (!raw) {
        return null;
    }

    const date = new Date(raw);
    if (Number.isNaN(date.getTime())) {
        return raw;
    }

    return new Intl.DateTimeFormat(undefined, {
        dateStyle: 'medium',
        timeStyle: 'short',
    }).format(date);
}

function formatInitialExplorerStatus(info) {
    if (!info || typeof info !== 'object') {
        return 'Packaged FIDO metadata is available. Explorer data is loading in the background.';
    }

    const parts = [];
    const entryCount = Number.isFinite(info.entryCount) ? Number(info.entryCount) : null;
    const snapshotNo = Number.isFinite(info.no) ? Number(info.no) : null;
    const lastUpdated = formatSnapshotTimestamp(info);

    if (snapshotNo !== null) {
        parts.push(`Snapshot ${snapshotNo}`);
    }
    if (entryCount !== null) {
        parts.push(`${entryCount.toLocaleString()} authenticators`);
    }
    if (lastUpdated) {
        parts.push(`last updated ${lastUpdated}`);
    }

    if (!parts.length) {
        return 'Packaged FIDO metadata is available. Explorer data is loading in the background.';
    }

    return `${parts.join(' • ')}. Explorer data is loading in the background.`;
}

function hasInlineDetail(entry) {
    return Boolean(
        entry
        && typeof entry === 'object'
        && entry.isLightweightEntry !== true
        && entry.metadataStatement
        && typeof entry.metadataStatement === 'object',
    );
}

function getInitialSnapshotPayload() {
    if (!initialMdsSnapshot || typeof initialMdsSnapshot !== 'object') {
        return null;
    }
    if (!Array.isArray(initialMdsSnapshot.entries)) {
        return null;
    }
    if (!initialMdsSnapshot.meta || typeof initialMdsSnapshot.meta !== 'object') {
        return null;
    }
    const snapshot = initialMdsSnapshot;
    initialMdsSnapshot = null;
    return snapshot;
}

function setRetryButtonVisible(visible) {
    const button = mdsState?.retryButton;
    if (!(button instanceof HTMLButtonElement)) {
        return;
    }

    button.hidden = !visible;
    button.setAttribute('aria-hidden', visible ? 'false' : 'true');
}


let metadataStorageWarningShown = false;
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

function createAbortError() {
    try {
        return new DOMException('Operation aborted', 'AbortError');
    } catch (error) {
        const abortError = new Error('Operation aborted');
        abortError.name = 'AbortError';
        return abortError;
    }
}

function isAbortSignal(value) {
    return Boolean(value && typeof value === 'object' && 'aborted' in value);
}

function getAbortSignal(options) {
    if (!options || typeof options !== 'object') {
        return null;
    }
    if (isAbortSignal(options)) {
        return options;
    }
    const signal = options.signal;
    if (isAbortSignal(signal)) {
        return signal;
    }
    return null;
}

function throwIfAborted(signal) {
    if (signal && signal.aborted) {
        throw createAbortError();
    }
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

function showMetadataUpdateOverlay(message, options = {}) {
    const overlay = mdsState?.updateOverlay;
    const messageEl = mdsState?.updateOverlayMessage;
    const cancelButton = mdsState?.updateOverlayCancel;
    const actionsEl = mdsState?.updateOverlayActions;
    const allowCancel = options && Object.prototype.hasOwnProperty.call(options, 'cancelable')
        ? Boolean(options.cancelable)
        : true;
    const onCancel = allowCancel && typeof options.onCancel === 'function' ? options.onCancel : null;

    if (!overlay || !messageEl) {
        return {
            updateMessage() {},
            setCancelable() {},
            close() {},
        };
    }

    if (cancelButton && mdsState.updateOverlayCancelHandler) {
        cancelButton.removeEventListener('click', mdsState.updateOverlayCancelHandler);
    }

    let handleCancel = null;
    if (allowCancel && cancelButton instanceof HTMLButtonElement) {
        handleCancel = event => {
            event.preventDefault();
            if (cancelButton.disabled) {
                return;
            }
            cancelButton.blur();
            if (onCancel) {
                onCancel();
            }
        };

        cancelButton.addEventListener('click', handleCancel);
        mdsState.updateOverlayCancelHandler = handleCancel;
    } else {
        mdsState.updateOverlayCancelHandler = null;
    }

    overlay.hidden = false;
    overlay.removeAttribute('hidden');
    overlay.classList.add('is-visible');
    overlay.setAttribute('aria-hidden', 'false');
    overlay.setAttribute('aria-busy', 'true');

    const initialMessage = typeof message === 'string' && message.trim()
        ? message.trim()
        : 'MDS is updating…';
    messageEl.textContent = initialMessage;

    if (cancelButton instanceof HTMLButtonElement) {
        cancelButton.hidden = !allowCancel;
        cancelButton.setAttribute('aria-hidden', allowCancel ? 'false' : 'true');
        cancelButton.disabled = !allowCancel;
        if (allowCancel) {
            cancelButton.removeAttribute('aria-disabled');
        } else {
            cancelButton.setAttribute('aria-disabled', 'true');
        }
    }

    if (actionsEl instanceof HTMLElement) {
        actionsEl.hidden = !allowCancel;
    }

    mdsState.updateOverlayAllowCancel = allowCancel;

    return {
        updateMessage(text) {
            if (messageEl) {
                messageEl.textContent = typeof text === 'string' && text.trim() ? text.trim() : '';
            }
        },
        setCancelable(isCancelable) {
            if (!allowCancel || !(cancelButton instanceof HTMLButtonElement)) {
                return;
            }
            const enable = Boolean(isCancelable);
            cancelButton.disabled = !enable;
            if (enable) {
                cancelButton.removeAttribute('aria-disabled');
            } else {
                cancelButton.setAttribute('aria-disabled', 'true');
            }
        },
        close({ delay = 0 } = {}) {
            const hide = () => {
                overlay.classList.remove('is-visible');
                overlay.hidden = true;
                overlay.setAttribute('aria-hidden', 'true');
                overlay.removeAttribute('aria-busy');
                if (cancelButton instanceof HTMLButtonElement) {
                    if (handleCancel && mdsState.updateOverlayCancelHandler === handleCancel) {
                        cancelButton.removeEventListener('click', handleCancel);
                        mdsState.updateOverlayCancelHandler = null;
                    }
                    cancelButton.hidden = true;
                    cancelButton.setAttribute('aria-hidden', 'true');
                    cancelButton.disabled = true;
                    cancelButton.setAttribute('aria-disabled', 'true');
                } else {
                    mdsState.updateOverlayCancelHandler = null;
                }
                if (actionsEl instanceof HTMLElement) {
                    actionsEl.hidden = true;
                }
                mdsState.updateOverlayAllowCancel = false;
            };

            if (delay > 0) {
                setTimeout(hide, delay);
            } else {
                hide();
            }
        },
    };
}

async function runWithMetadataUpdateOverlay(task, options = {}) {
    const startMessage = typeof options.startMessage === 'string' && options.startMessage.trim()
        ? options.startMessage.trim()
        : 'MDS is updating…';
    const successMessage = typeof options.successMessage === 'string' && options.successMessage.trim()
        ? options.successMessage.trim()
        : '';
    const cancelMessage = typeof options.cancelMessage === 'string' && options.cancelMessage.trim()
        ? options.cancelMessage.trim()
        : 'Metadata update cancelled.';
    const failureMessage = typeof options.failureMessage === 'string' && options.failureMessage.trim()
        ? options.failureMessage.trim()
        : '';
    const closeDelay = Number.isFinite(options.closeDelay) ? Number(options.closeDelay) : 520;
    const allowCancel = options && Object.prototype.hasOwnProperty.call(options, 'cancelable')
        ? Boolean(options.cancelable)
        : true;

    const controller = new AbortController();
    const overlayControls = showMetadataUpdateOverlay(startMessage, {
        onCancel: allowCancel ? () => controller.abort() : null,
        cancelable: allowCancel,
    });

    const context = {
        signal: controller.signal,
        updateStatus: text => overlayControls.updateMessage(text),
        setCancelable: value => overlayControls.setCancelable(value),
        throwIfAborted: () => {
            throwIfAborted(controller.signal);
        },
    };

    try {
        const result = await task(context);
        if (controller.signal.aborted) {
            overlayControls.updateMessage(cancelMessage);
            overlayControls.setCancelable(false);
            overlayControls.close({ delay: 320 });
        } else {
            if (successMessage) {
                overlayControls.updateMessage(successMessage);
            }
            overlayControls.setCancelable(false);
            overlayControls.close({ delay: closeDelay });
        }
        return result;
    } catch (error) {
        if (controller.signal.aborted) {
            overlayControls.updateMessage(cancelMessage);
            overlayControls.setCancelable(false);
            overlayControls.close({ delay: 320 });
        } else {
            if (failureMessage) {
                overlayControls.updateMessage(failureMessage);
            }
            overlayControls.setCancelable(false);
            overlayControls.close({ delay: 720 });
        }
        throw error;
    }
}

async function fetchCustomMetadataItems(options = {}) {
    const signal = getAbortSignal(options);
    try {
        const fetchOptions = { cache: 'no-store' };
        if (signal) {
            fetchOptions.signal = signal;
        }
        const response = await fetch(CUSTOM_METADATA_LIST_PATH, fetchOptions);
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
        if (!(error && error.name === 'AbortError')) {
            console.warn('Failed to load custom metadata entries.', error);
        }
        return [];
    }
}

async function getCustomMetadataItems(options = {}) {
    const opts = options && typeof options === 'object' ? options : {};
    const forceReload = Boolean(opts.forceReload);
    const signal = getAbortSignal(opts);
    const useSharedPromise = !forceReload && !signal;

    if (forceReload) {
        customMetadataCache = null;
    }

    if (customMetadataCache && !forceReload) {
        return cloneCustomMetadataItems(customMetadataCache);
    }

    const loadItems = async () => {
        const items = await fetchCustomMetadataItems({ signal });
        throwIfAborted(signal);
        customMetadataCache = items;
        return items;
    };

    if (!useSharedPromise) {
        const loaded = await loadItems();
        return cloneCustomMetadataItems(loaded);
    }

    if (!customMetadataPromise) {
        customMetadataPromise = loadItems();
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
    const signal = getAbortSignal(options);
    throwIfAborted(signal);

    const items = await getCustomMetadataItems(options);
    throwIfAborted(signal);

    customMetadataItems = cloneCustomMetadataItems(items);
    updateCustomMetadataList(customMetadataItems);
    throwIfAborted(signal);

    const entries = extractCustomEntries(customMetadataItems);
    throwIfAborted(signal);

    return mergeCustomEntriesIntoMetadata(metadata, entries, customMetadataItems);
}

async function refreshCustomMetadataAfterUpload(note, options = {}) {
    const signal = getAbortSignal(options);
    customMetadataCache = null;

    const cached = readMetadataCache();
    const baseMetadata = cached && typeof cached.metadata === 'object' ? cached.metadata : null;

    if (!baseMetadata) {
        return false;
    }

    try {
        const enhanced = await ensureCustomMetadata(baseMetadata, { forceReload: true, signal });
        if (!enhanced || typeof enhanced !== 'object') {
            throw new Error('No metadata available for refresh.');
        }

        throwIfAborted(signal);

        await applyMetadataEntries(enhanced, { note, signal });
        throwIfAborted(signal);

        const infoSource =
            cached && cached.info && typeof cached.info === 'object' ? { ...cached.info } : {};
        infoSource.cachedAt = new Date().toISOString();
        if (!infoSource.source) {
            infoSource.source = 'session-custom';
        }
        storeMetadataCache(JSON.stringify(enhanced), infoSource);
        return true;
    } catch (error) {
        console.warn('Fast custom metadata refresh failed. Falling back to full reload.', error);
        return false;
    }
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
        event.preventDefault();
    }
}

function createCustomPanelScrollGuard(panel) {
    const dialog = panel?.querySelector?.('.mds-custom-panel__dialog');
    if (!(dialog instanceof HTMLElement)) {
        return null;
    }

    const shouldPreventScroll = deltaY => {
        if (!Number.isFinite(deltaY) || deltaY === 0) {
            return false;
        }
        const scrollableHeight = dialog.scrollHeight - dialog.clientHeight;
        if (scrollableHeight <= 0) {
            return true;
        }
        const threshold = 1;
        if (deltaY < 0 && dialog.scrollTop <= threshold) {
            return true;
        }
        if (deltaY > 0 && dialog.scrollTop >= scrollableHeight - threshold) {
            return true;
        }
        return false;
    };

    const handleWheel = event => {
        if (shouldPreventScroll(event.deltaY)) {
            event.preventDefault();
        }
    };

    let lastTouchY = null;
    const handleTouchStart = event => {
        if (event.touches && event.touches.length > 0) {
            lastTouchY = event.touches[0].clientY;
        }
    };

    const handleTouchMove = event => {
        if (!event.touches || event.touches.length === 0) {
            return;
        }
        const currentY = event.touches[0].clientY;
        if (lastTouchY === null) {
            lastTouchY = currentY;
        }
        const deltaY = lastTouchY - currentY;
        lastTouchY = currentY;
        if (shouldPreventScroll(deltaY)) {
            event.preventDefault();
        }
    };

    const handleTouchEnd = () => {
        lastTouchY = null;
    };

    dialog.addEventListener('wheel', handleWheel, { passive: false });
    dialog.addEventListener('touchstart', handleTouchStart, { passive: true });
    dialog.addEventListener('touchmove', handleTouchMove, { passive: false });
    dialog.addEventListener('touchend', handleTouchEnd);
    dialog.addEventListener('touchcancel', handleTouchEnd);

    return () => {
        dialog.removeEventListener('wheel', handleWheel);
        dialog.removeEventListener('touchstart', handleTouchStart);
        dialog.removeEventListener('touchmove', handleTouchMove);
        dialog.removeEventListener('touchend', handleTouchEnd);
        dialog.removeEventListener('touchcancel', handleTouchEnd);
        lastTouchY = null;
    };
}

function openCustomMetadataPanel() {
    if (!mdsState?.customPanel) {
        return;
    }

    if (!mdsState.customPanelIsOpen) {
        const panel = mdsState.customPanel;
        panel.hidden = false;
        panel.removeAttribute('hidden');
        panel.classList.remove('is-closing');
        void panel.offsetWidth; // Force reflow before toggling transition class.
        panel.classList.add('is-open');
        if (typeof mdsState.customPanelScrollCleanup === 'function') {
            mdsState.customPanelScrollCleanup();
        }
        mdsState.customPanelScrollCleanup = createCustomPanelScrollGuard(panel);
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
    const finalizeClose = () => {
        panel.classList.remove('is-open');
        panel.classList.remove('is-closing');
        panel.hidden = true;
        panel.setAttribute('hidden', '');
        if (typeof mdsState.customPanelScrollCleanup === 'function') {
            mdsState.customPanelScrollCleanup();
            mdsState.customPanelScrollCleanup = null;
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
    };

    if (mdsState.addMetadataButton) {
        mdsState.addMetadataButton.setAttribute('aria-expanded', 'false');
    }

    if (!panel.classList.contains('is-open')) {
        mdsState.customPanelIsOpen = false;
        finalizeClose();
        return;
    }

    mdsState.customPanelIsOpen = false;
    panel.classList.add('is-closing');
    panel.classList.remove('is-open');

    const dialog = panel.querySelector('.mds-custom-panel__dialog');
    if (!(dialog instanceof HTMLElement)) {
        finalizeClose();
        return;
    }

    let hasClosed = false;
    const completeClose = () => {
        if (hasClosed) {
            return;
        }
        hasClosed = true;
        finalizeClose();
    };

    const handleTransitionEnd = event => {
        if (event.target !== dialog) {
            return;
        }
        dialog.removeEventListener('transitionend', handleTransitionEnd);
        completeClose();
    };

    dialog.addEventListener('transitionend', handleTransitionEnd);
    setTimeout(completeClose, 400);
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
        await runWithMetadataUpdateOverlay(async context => {
            context.updateStatus('Uploading metadata…');
            const response = await fetch(CUSTOM_METADATA_UPLOAD_PATH, {
                method: 'POST',
                body: formData,
                signal: context.signal,
            });

            let payload;
            try {
                payload = await response.json();
            } catch (error) {
                payload = null;
            }

            context.throwIfAborted();

            const errors = Array.isArray(payload?.errors) ? payload.errors : [];
            if (!response.ok) {
                const message =
                    (payload && typeof payload.error === 'string' && payload.error.trim()) ||
                    errors.join(' ') ||
                    'Failed to upload metadata files.';
                setCustomMetadataMessage(message, 'error');
                throw new Error(message);
            }

            customMetadataCache = null;
            const successMessage =
                errors.length > 0
                    ? `Metadata uploaded with warnings: ${errors.join(' ')}`
                    : 'Metadata uploaded successfully.';
            setCustomMetadataMessage(successMessage, errors.length ? 'warning' : 'success');

            const refreshNote = 'Custom metadata updated.';
            if (payload?.snapshot && typeof payload.snapshot === 'object') {
                context.updateStatus('Applying metadata…');
                applyExplorerSnapshot(payload.snapshot, refreshNote);
            } else {
                context.updateStatus('Reloading metadata…');
                await loadMdsData(refreshNote, { forceReload: true, signal: context.signal });
            }
            context.throwIfAborted();
        }, {
            startMessage: 'Updating Metadata...',
            successMessage: 'Completing metadata update...',
            cancelMessage: 'Metadata update cancelled.',
            failureMessage: 'Metadata update failed.',
            cancelable: false,
        });
    } catch (error) {
        if (error && error.name === 'AbortError') {
            setCustomMetadataMessage('Metadata update cancelled.', 'warning');
            return;
        }
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

    if (triggerButton) {
        setButtonBusy(triggerButton, true);
    }

    setCustomMetadataMessage(`Removing ${itemName}…`, 'info');

    try {
        await runWithMetadataUpdateOverlay(async context => {
            context.updateStatus('Removing metadata…');
            const response = await fetch(
                `${CUSTOM_METADATA_DELETE_PATH}/${encodeURIComponent(storedFilename)}`,
                {
                    method: 'DELETE',
                    signal: context.signal,
                },
            );

            let payload;
            try {
                payload = await response.json();
            } catch (error) {
                payload = null;
            }

            context.throwIfAborted();

            if (!response.ok) {
                const errorMessage =
                    (payload && typeof payload.error === 'string' && payload.error.trim()) ||
                    (payload && typeof payload.message === 'string' && payload.message.trim()) ||
                    'Failed to delete metadata file.';
                const variant = response.status === 404 ? 'warning' : 'error';
                setCustomMetadataMessage(errorMessage, variant);
                if (variant === 'error') {
                    throw new Error(errorMessage);
                }
                context.updateStatus('No metadata changes detected.');
                return;
            }

            customMetadataCache = null;
            customMetadataPromise = null;

            if (payload?.snapshot && typeof payload.snapshot === 'object') {
                context.updateStatus('Applying metadata…');
                applyExplorerSnapshot(payload.snapshot, 'Custom metadata updated.');
            } else {
                context.updateStatus('Refreshing metadata…');
                await loadMdsData('Custom metadata updated.', { forceReload: true, signal: context.signal });
            }
            context.throwIfAborted();
            setCustomMetadataMessage(`${itemName} removed.`, 'success');
        }, {
            startMessage: 'Removing metadata...',
            successMessage: 'Completing metadata removal...',
            cancelMessage: 'Metadata removal cancelled.',
            failureMessage: 'Metadata removal failed.',
            cancelable: false,
        });
    } catch (error) {
        if (error && error.name === 'AbortError') {
            setCustomMetadataMessage('Metadata update cancelled.', 'warning');
        } else {
            console.error('Failed to delete custom metadata file.', error);
            setCustomMetadataMessage('Failed to delete metadata file.', 'error');
        }
    } finally {
        if (triggerButton) {
            setButtonBusy(triggerButton, false);
        }
    }
}

if (typeof window !== 'undefined') {
    if (window.__INITIAL_MDS_INFO__ && typeof window.__INITIAL_MDS_INFO__ === 'object') {
        initialMdsInfo = window.__INITIAL_MDS_INFO__;
    }
    if (window.__INITIAL_MDS_SNAPSHOT__ && typeof window.__INITIAL_MDS_SNAPSHOT__ === 'object') {
        initialMdsSnapshot = window.__INITIAL_MDS_SNAPSHOT__;
    }
    try {
        delete window.__INITIAL_MDS_INFO__;
    } catch (error) {
        window.__INITIAL_MDS_INFO__ = undefined;
    }
    try {
        delete window.__INITIAL_MDS_SNAPSHOT__;
    } catch (error) {
        window.__INITIAL_MDS_SNAPSHOT__ = undefined;
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

function readMetadataCache() {
    return null;
}

function storeMetadataCache() {
    // Disabled to minimise localStorage usage.
}

function clearMetadataCache() {
    customMetadataCache = null;
    resolvedEntryCache.clear();
    explorerPreloadPromise = null;
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
    if (typeof window !== 'undefined' && typeof window.scrollTo === 'function') {
        window.scrollTo({ top: 0, left: 0, behavior: 'smooth' });
    } else if (mdsState?.root && typeof mdsState.root.scrollIntoView === 'function') {
        mdsState.root.scrollIntoView({ block: 'start', behavior: 'smooth' });
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

document.addEventListener('DOMContentLoaded', () => {
    const tabElement = document.getElementById('mds-tab');
    if (!tabElement) {
        return;
    }

    try {
        mdsState = initializeState(tabElement);
        updateSortButtonState();
        setUpdateButtonMode('update');
        const initialStatus = formatInitialExplorerStatus(mdsState?.metadataSnapshotInfo);
        if (initialStatus) {
            setStatus(initialStatus, 'info');
            if (mdsState) {
                mdsState.defaultStatus = {
                    html: initialStatus,
                    variant: 'info',
                    title: '',
                };
            }
        }
    } catch (error) {
        console.error('Failed to initialise the FIDO MDS tab:', error);
        tabElement.innerHTML = `
            <div class="section mds-section">
                <div class="mds-status mds-status-error">Unable to load authenticator explorer. Check the console for details.</div>
            </div>`;
        return;
    }

    const bootstrapSnapshot = getInitialSnapshotPayload();
    if (bootstrapSnapshot) {
        applyExplorerSnapshot(bootstrapSnapshot);
    } else {
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

    const addMetadataButton = root.querySelector('#mds-add-metadata-button');
    const customPanel = root.querySelector('#mds-custom-metadata-panel');
    const customPanelClose = root.querySelector('#mds-custom-panel-close');
    const customMessages = root.querySelector('#mds-custom-messages');
    const customList = root.querySelector('#mds-custom-list');
    const customDropzone = root.querySelector('#mds-custom-dropzone');
    const customFileInput = root.querySelector('#mds-custom-file-input');

    const overlay = document.createElement('div');
    overlay.id = 'mds-update-overlay';
    overlay.className = 'mds-update-overlay';
    overlay.setAttribute('role', 'alertdialog');
    overlay.setAttribute('aria-modal', 'true');
    overlay.setAttribute('aria-hidden', 'true');
    overlay.hidden = true;

    const overlayDialog = document.createElement('div');
    overlayDialog.className = 'mds-update-overlay__dialog';
    overlayDialog.setAttribute('tabindex', '-1');
    overlay.appendChild(overlayDialog);

    const overlayToast = document.createElement('div');
    overlayToast.className = 'mds-update-overlay__toast';
    overlayDialog.appendChild(overlayToast);

    const overlaySpinner = document.createElement('div');
    overlaySpinner.className = 'mds-update-overlay__spinner';
    overlaySpinner.setAttribute('aria-hidden', 'true');
    overlayToast.appendChild(overlaySpinner);

    const overlayMessage = document.createElement('span');
    overlayMessage.className = 'mds-update-overlay__message';
    overlayMessage.id = 'mds-update-overlay-message';
    overlayMessage.textContent = 'MDS is updating…';
    overlayToast.appendChild(overlayMessage);
    overlay.setAttribute('aria-labelledby', overlayMessage.id);

    const overlayActions = document.createElement('div');
    overlayActions.className = 'mds-update-overlay__actions';
    overlayActions.hidden = true;
    overlayDialog.appendChild(overlayActions);

    const overlayCancel = document.createElement('button');
    overlayCancel.type = 'button';
    overlayCancel.className = 'mds-update-overlay__cancel';
    overlayCancel.textContent = 'Cancel update';
    overlayCancel.hidden = true;
    overlayCancel.disabled = true;
    overlayCancel.setAttribute('aria-hidden', 'true');
    overlayCancel.setAttribute('aria-disabled', 'true');
    overlayActions.appendChild(overlayCancel);

    root.appendChild(overlay);

    if (customPanel) {
        customPanel.addEventListener('keydown', handleCustomPanelKeydown);
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

    const retryButton = root.querySelector('#mds-retry-button');
    if (retryButton instanceof HTMLButtonElement) {
        retryButton.addEventListener('click', event => {
            event.preventDefault();
            void refreshMetadata();
        });
        retryButton.hidden = true;
        retryButton.setAttribute('aria-hidden', 'true');
    }

    const updateButton = root.querySelector('#mds-update-button');
    if (updateButton) {
        updateButton.addEventListener('click', () => {
            void refreshMetadata();
        });
    }

    const listSection = root.querySelector('#mds-list-section');
    const certificatePage = root.querySelector('#mds-certificate-page');
    const certificateClose = root.querySelector('#mds-certificate-page-close');
    const certificateBody = root.querySelector('#mds-certificate-page-body');
    const certificateSummary = root.querySelector('#mds-certificate-summary');
    const certificateHeader = certificatePage?.querySelector('.mds-detail-page__header') || null;
    if (certificateClose) {
        certificateClose.addEventListener('click', () => closeCertificatePage());
    }

    const authenticatorModal = root.querySelector('#mds-authenticator-modal');
    const authenticatorClose = root.querySelector('#mds-authenticator-modal-close');
    const authenticatorHeader = authenticatorModal?.querySelector('.mds-detail-page__header') || null;
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
        retryButton,
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
        customPanelScrollCleanup: null,
        updateButton,
        updateButtonMode: 'update',
        metadataSnapshotInfo: normaliseSnapshotInfo(initialMdsInfo),
        updateOverlay: overlay,
        updateOverlayMessage: overlayMessage,
        updateOverlayCancel: overlayCancel,
        updateOverlayActions: overlayActions,
        updateOverlayCancelHandler: null,
        updateOverlayAllowCancel: false,
        certificatePage,
        certificateHeader,
        certificatePageBody: certificateBody,
        certificateInput: root.querySelector('#mds-certificate-input'),
        certificateOutput: root.querySelector('#mds-certificate-output'),
        certificateTitle: root.querySelector('#mds-certificate-page-title'),
        certificateSubtitle: root.querySelector('#mds-certificate-page-subtitle'),
        certificateSummary,
        certificateClose,
        authenticatorModal,
        authenticatorHeader,
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
        certificateStickyHeader: null,
        authenticatorStickyHeader: null,
    };

    if (certificatePage && certificateHeader) {
        state.certificateStickyHeader = createDetailStickyHeader(certificatePage, certificateHeader, {
            defaultTitle: 'Attestation Certificate',
            type: 'certificate',
            onBack: () => closeCertificatePage(),
        });
    }

    if (authenticatorModal && authenticatorHeader) {
        state.authenticatorStickyHeader = createDetailStickyHeader(authenticatorModal, authenticatorHeader, {
            defaultTitle: 'Authenticator',
            type: 'authenticator',
            onBack: () => closeAuthenticatorModal(),
        });
    }

    state.certificateStickyHeader?.sync();
    state.authenticatorStickyHeader?.sync();

    updateCustomMetadataList(customMetadataItems, state);
    setCustomMetadataMessage('', 'info', state);

    setupColumnResizers(state);
    setColumnResizersEnabled(false, state);
    scheduleHorizontalScrollMetricsUpdate();
    return state;
}

async function applyMetadataEntries(metadata, options = {}) {
    const opts = options && typeof options === 'object' ? options : {};
    const noteText = typeof opts.note === 'string' ? opts.note : '';
    const signal = getAbortSignal(opts);
    const useLazyLoading = opts.useLazyLoading ?? true; // Enable by default

    throwIfAborted(signal);

    if (!mdsState) {
        return;
    }

    const rawEntries = Array.isArray(metadata?.entries) ? metadata.entries : [];
    const totalEntries = rawEntries.length;
    const shouldReportProgress = loaderIsActive() && !hasLoaded;
    
    throwIfAborted(signal);

    // Use lazy loading for large datasets
    if (useLazyLoading && totalEntries > 100) {
        await applyMetadataEntriesLazy(metadata, { ...opts, shouldReportProgress, noteText, signal });
        return;
    }

    // Fall back to original full loading for small datasets
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
            throwIfAborted(signal);
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

    throwIfAborted(signal);

    if (mdsState) {
        const map = new Map();
        mdsData.forEach(item => {
            throwIfAborted(signal);
            const key = normaliseAaguid(item.aaguid || item.id);
            if (key) {
                map.set(key, item);
            }
        });
        mdsState.byAaguid = map;
    }

    let lastUpdatedDate = formatSnapshotTimestamp(metadata?.meta || metadata) || formatSnapshotTimestamp(initialMdsInfo) || '';
    if (!lastUpdatedDate) {
        try {
            const metaResponse = await fetch(MDS_VERIFIED_META_PATH, { cache: 'no-store' });
            if (metaResponse.ok) {
                const metaData = await metaResponse.json();
                lastUpdatedDate = formatSnapshotTimestamp(metaData) || '';
            }
        } catch (error) {
            lastUpdatedDate = '';
        }
    }

    const optionSets = collectOptionSets(mdsData);
    updateOptionLists(optionSets);

    try {
        throwIfAborted(signal);
        await populateCertificateDerivedInfo(mdsData);
    } catch (error) {
        console.error('Failed to derive attestation certificate details:', error);
    }

    throwIfAborted(signal);

    applyFilters();
    scheduleHorizontalScrollMetricsUpdate();

    hasLoaded = true;

    const statusParts = [`Loaded ${mdsData.length.toLocaleString()} authenticators.`];
    let statusVariant = 'success';

    if (lastUpdatedDate) {
        statusParts.push(`Last updated: ${lastUpdatedDate}.`);
    }

    if (noteText) {
        statusParts.push(noteText);
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
    }
}

async function applyMetadataEntriesLazy(metadata, options = {}) {
    const { shouldReportProgress, noteText, signal } = options;
    
    throwIfAborted(signal);

    if (!mdsState) {
        return;
    }

    // Initialize lazy loader
    if (!lazyLoader) {
        lazyLoader = createMdsLazyLoader();
    }
    lazyLoader.initialize(metadata);

    if (shouldReportProgress) {
        loaderSetPhase('Loading authenticators with optimized parsing…', { progress: 58 });
        loaderSetMetadataCount(0);
    }

    // Get ALL raw entries
    const allRawEntries = lazyLoader.getAllRawEntries();
    const totalEntries = allRawEntries.length;
    const entries = [];

    throwIfAborted(signal);

    // Transform ALL entries with lightweight parsing (UI fields only)
    const progressBase = 58;
    const progressRange = 32;
    let processedCount = 0;
    const reportInterval = 100; // Report progress every 100 entries

    allRawEntries.forEach((entry, index) => {
        throwIfAborted(signal);
        processedCount += 1;
        
        // Use lightweight transformation for initial load
        const transformed = transformEntryLightweight(entry, index);
        if (transformed) {
            entries.push(transformed);
        }

        // Report progress periodically
        if (shouldReportProgress && processedCount % reportInterval === 0) {
            loaderSetMetadataCount(entries.length);
            const ratio = processedCount / totalEntries;
            const progress = progressBase + Math.min(progressRange, ratio * progressRange);
            loaderSetProgress(progress);
        }
    });

    if (shouldReportProgress) {
        loaderSetMetadataCount(entries.length);
        loaderSetProgress(90);
    }

    mdsData = entries;
    setUpdateButtonMode('update');
    resetSortState();

    throwIfAborted(signal);

    // Build AAGUID map for all entries
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

    let lastUpdatedDate = formatSnapshotTimestamp(metadata?.meta || metadata) || formatSnapshotTimestamp(initialMdsInfo) || '';
    if (!lastUpdatedDate) {
        try {
            const metaResponse = await fetch(MDS_VERIFIED_META_PATH, { cache: 'no-store' });
            if (metaResponse.ok) {
                const metaData = await metaResponse.json();
                lastUpdatedDate = formatSnapshotTimestamp(metaData) || '';
            }
        } catch (error) {
            lastUpdatedDate = '';
        }
    }

    // Collect option sets from all entries
    const optionSets = collectOptionSets(mdsData);
    updateOptionLists(optionSets);

    // Apply filters with all entries
    applyFilters();
    scheduleHorizontalScrollMetricsUpdate();

    hasLoaded = true;

    // Show initial status
    const statusParts = [
        `Loaded ${entries.length.toLocaleString()} authenticators.`
    ];
    if (lastUpdatedDate) {
        statusParts.push(`Last updated: ${lastUpdatedDate}.`);
    }
    if (noteText) {
        statusParts.push(noteText);
    }
    statusParts.push('Processing full details in background…');

    const statusMessage = statusParts.join(' ');
    setStatus(statusMessage, 'info');

    if (!mdsState.defaultStatus) {
        mdsState.defaultStatus = { html: statusMessage, variant: 'info', title: '' };
    }

    if (metadata?.legalHeader && mdsState.statusEl) {
        mdsState.statusEl.setAttribute('title', metadata.legalHeader);
    }

    setColumnResizersEnabled(true);

    if (shouldReportProgress) {
        loaderSetMetadataCount(entries.length);
        loaderSetPhase('Finalising interface…', { progress: 94 });
    }

    // Start background loading of full entry details
    startBackgroundMetadataLoading(metadata, { signal, lastUpdatedDate }).catch(error => {
        console.error('Background metadata loading failed:', error);
        // Optionally show error status to user
        if (mdsState?.statusEl) {
            const currentStatus = mdsState.statusEl.textContent || '';
            if (currentStatus.includes('Processing full details')) {
                setStatus(
                    `${currentStatus.split('Processing')[0]} Background processing encountered an error.`,
                    'warning'
                );
            }
        }
    });
}

async function startBackgroundMetadataLoading(metadata, options = {}) {
    if (backgroundLoadingInProgress || !lazyLoader) {
        return;
    }

    backgroundLoadingInProgress = true;
    const { signal, lastUpdatedDate } = options;

    // Set up progress callback
    lazyLoader.onProgress((parsed, total, percent) => {
        if (mdsState?.statusEl && !mdsState.statusEl.hidden) {
            // Update status occasionally
            if (parsed % 500 === 0 || parsed === total) {
                updateBackgroundLoadingStatus(parsed, total, lastUpdatedDate);
            }
        }
    });

    // Set up completion callback
    lazyLoader.onComplete(() => {
        finalizeBackgroundLoading(metadata, lastUpdatedDate);
    });

    // Define batch processor
    const processBatch = async (batchIndices) => {
        // Validate batch indices and filter out invalid entries
        const validIndices = batchIndices.filter(i => 
            typeof i === 'number' && i >= 0 && i < mdsData.length
        );
        
        if (!validIndices.length) {
            return;
        }
        
        // Process certificate info for this batch
        const batchEntries = validIndices.map(i => mdsData[i]).filter(entry => entry != null);
        
        try {
            await populateCertificateDerivedInfoForBatch(batchEntries);
        } catch (error) {
            console.error('Failed to process certificate info for batch:', error);
        }
    };

    // Start loading
    try {
        await lazyLoader.startBackgroundLoading({ 
            signal,
            onBatchProcessed: processBatch
        });
    } catch (error) {
        console.error('Background metadata loading failed:', error);
    } finally {
        backgroundLoadingInProgress = false;
    }
}

function updateBackgroundLoadingStatus(parsed, total, lastUpdatedDate) {
    // Just update status message, entries are already in mdsData
    const percentComplete = Math.round((parsed / total) * 100);
    const statusParts = [
        `Loaded ${total.toLocaleString()} authenticators.`
    ];
    if (lastUpdatedDate) {
        statusParts.push(`Last updated: ${lastUpdatedDate}.`);
    }
    if (parsed < total) {
        statusParts.push(`Processing full details… ${percentComplete}% complete`);
    }
    
    const statusMessage = statusParts.join(' ');
    const variant = parsed < total ? 'info' : 'success';
    setStatus(statusMessage, variant);
}

async function populateCertificateDerivedInfoForBatch(entries) {
    if (!Array.isArray(entries) || !entries.length) {
        return;
    }

    const seen = new Set();
    const certificates = [];

    entries.forEach(entry => {
        // Upgrade to full entry if lightweight
        if (entry.isLightweightEntry && entry.deferredRawEntry) {
            const fullEntry = upgradeEntryToFull(entry);
            Object.assign(entry, fullEntry);
        }

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

async function finalizeBackgroundLoading(metadata, lastUpdatedDate) {
    // Update final status
    const statusParts = [`Loaded ${mdsData.length.toLocaleString()} authenticators.`];
    if (lastUpdatedDate) {
        statusParts.push(`Last updated: ${lastUpdatedDate}.`);
    }
    
    const statusMessage = statusParts.join(' ');
    setStatus(statusMessage, 'success');

    if (mdsState.defaultStatus) {
        mdsState.defaultStatus.html = statusMessage;
        mdsState.defaultStatus.variant = 'success';
    }

    if (metadata?.legalHeader && mdsState?.statusEl) {
        if (mdsState.defaultStatus) {
            mdsState.defaultStatus.title = metadata.legalHeader;
        }
    }

    backgroundLoadingInProgress = false;
}

function buildLoadedStatus(snapshot, note) {
    const meta = snapshot?.meta && typeof snapshot.meta === 'object' ? snapshot.meta : {};
    const entryCount = Array.isArray(snapshot?.entries) ? snapshot.entries.length : 0;
    const parts = [`Loaded ${entryCount.toLocaleString()} authenticators.`];

    const lastUpdated = formatSnapshotTimestamp(meta);
    if (lastUpdated) {
        parts.push(`Last updated ${lastUpdated}.`);
    }

    if (Number.isFinite(meta?.customEntryCount) && meta.customEntryCount > 0) {
        const count = Number(meta.customEntryCount);
        const suffix = count === 1 ? 'entry' : 'entries';
        parts.push(`Including ${count.toLocaleString()} session metadata ${suffix}.`);
    }

    if (note) {
        parts.push(note);
    }

    return parts.join(' ');
}

function resetExplorerState(message, variant = 'info') {
    mdsData = [];
    filteredData = [];
    hasLoaded = true;
    resolvedEntryCache.clear();

    if (mdsState) {
        mdsState.byAaguid = new Map();
    }

    updateCount(0, 0);
    setColumnResizersEnabled(false);
    setStatus(message, variant);
    setRetryButtonVisible(false);

    if (mdsState) {
        mdsState.defaultStatus = { html: message, variant, title: '' };
        if (mdsState.tableBody) {
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
    }
}

function applyExplorerSnapshot(snapshot, note = '') {
    if (!mdsState) {
        return;
    }

    const meta = snapshot?.meta && typeof snapshot.meta === 'object' ? snapshot.meta : {};
    const incomingEntries = Array.isArray(snapshot?.entries) ? snapshot.entries : [];
    mdsState.metadataSnapshotInfo = normaliseSnapshotInfo(meta);
    const entries = incomingEntries
        .map(entry => cloneMetadataEntry(entry))
        .filter(entry => entry && typeof entry === 'object')
        .map(entry => {
            if (hasInlineDetail(entry)) {
                entry.isLightweightEntry = false;
            }
            const cached = entry.entryId ? resolvedEntryCache.get(entry.entryId) : null;
            return cached && typeof cached === 'object' ? { ...entry, ...cached } : entry;
        });

    mdsData = entries;
    resetSortState();
    setUpdateButtonMode('update');

    const byAaguid = new Map();
    entries.forEach(entry => {
        const key = normaliseAaguid(entry?.aaguid || entry?.id);
        if (key) {
            byAaguid.set(key, entry);
        }
        if (entry?.entryId) {
            resolvedEntryCache.set(entry.entryId, entry);
        }
    });
    mdsState.byAaguid = byAaguid;

    updateOptionLists(collectOptionSets(entries));
    applyFilters();
    scheduleHorizontalScrollMetricsUpdate();
    setColumnResizersEnabled(Boolean(entries.length));
    setRetryButtonVisible(false);

    hasLoaded = true;

    const statusMessage = buildLoadedStatus(snapshot, note);
    const statusVariant = entries.length ? 'success' : 'info';
    setStatus(statusMessage, statusVariant);

    mdsState.defaultStatus = {
        html: statusMessage,
        variant: statusVariant,
        title: typeof meta.legalHeader === 'string' ? meta.legalHeader : '',
    };

    if (mdsState.statusEl) {
        if (mdsState.defaultStatus.title) {
            mdsState.statusEl.setAttribute('title', mdsState.defaultStatus.title);
        } else {
            mdsState.statusEl.removeAttribute('title');
        }
    }
}

function integrateResolvedEntry(entry) {
    if (!entry || typeof entry !== 'object') {
        return null;
    }

    const key = normaliseAaguid(entry.aaguid || entry.id);
    let target = null;

    if (key && mdsState?.byAaguid?.has(key)) {
        target = mdsState.byAaguid.get(key);
    } else if (entry.entryId) {
        target = mdsData.find(item => item?.entryId === entry.entryId) || null;
    }

    if (target && target !== entry) {
        Object.assign(target, entry, { isLightweightEntry: false });
        entry = target;
    } else if (!target && hasLoaded) {
        mdsData.push(entry);
        applyFilters({ preserveTableScroll: true });
    }

    if (entry.entryId) {
        resolvedEntryCache.set(entry.entryId, entry);
    }
    if (key && mdsState?.byAaguid) {
        mdsState.byAaguid.set(key, entry);
    }

    return entry;
}

async function resolveMetadataEntry(query) {
    const params = new URLSearchParams();
    Object.entries(query || {}).forEach(([key, value]) => {
        if (typeof value === 'string' && value) {
            params.set(key, value);
        }
    });

    if (!params.toString()) {
        return null;
    }

    const response = await fetch(`${MDS_RESOLVE_PATH}?${params.toString()}`, {
        cache: 'no-store',
    });
    if (!response.ok) {
        return null;
    }

    const payload = await response.json();
    const resolved = payload?.entry;
    if (!resolved || typeof resolved !== 'object') {
        return null;
    }

    return integrateResolvedEntry(resolved);
}

async function loadMdsData(statusNote, options = {}) {
    if (!mdsState) {
        return;
    }

    const opts = options && typeof options === 'object' ? options : {};
    const signal = getAbortSignal(opts);
    const forceReload = Boolean(opts.forceReload);
    const note = typeof statusNote === 'string' ? statusNote.trim() : '';

    throwIfAborted(signal);

    if (isLoading && loadPromise) {
        await loadPromise;
        if (!forceReload) {
            return;
        }
    }

    if (hasLoaded && !forceReload) {
        return;
    }

    if (forceReload) {
        explorerPreloadPromise = null;
        resolvedEntryCache.clear();
    }

    isLoading = true;
    setRetryButtonVisible(false);
    setStatus(forceReload ? 'Refreshing authenticator explorer…' : 'Loading authenticator explorer…', 'info');
    setColumnResizersEnabled(false);

    const task = (async () => {
        const fetchOptions = {
            cache: forceReload ? 'reload' : 'no-store',
        };
        if (signal) {
            fetchOptions.signal = signal;
        }

        try {
            const response = await fetch(MDS_EXPLORER_FULL_PATH, fetchOptions);
            let payload = null;
            try {
                payload = await response.json();
            } catch (error) {
                payload = null;
            }

            if (!response.ok) {
                if (response.status === 404) {
                    resetExplorerState(
                        payload && typeof payload.error === 'string' && payload.error
                            ? payload.error
                            : MISSING_METADATA_MESSAGE,
                        'info',
                    );
                    return;
                }

                throw new Error(
                    payload && typeof payload.error === 'string' && payload.error
                        ? payload.error
                        : `Explorer request failed with status ${response.status}.`,
                );
            }

            if (!payload || typeof payload !== 'object') {
                throw new Error('Explorer response was not valid JSON.');
            }

            const payloadEntries = Array.isArray(payload.entries) ? payload.entries : [];
            const shouldUseLegacyEntryParser =
                payloadEntries.length > 0
                && payloadEntries.some(entry => {
                    if (!entry || typeof entry !== 'object') {
                        return true;
                    }
                    return !Object.prototype.hasOwnProperty.call(entry, 'entryId');
                });

            if (shouldUseLegacyEntryParser) {
                await applyMetadataEntries(payload, { note, signal });
            } else {
                applyExplorerSnapshot(payload, note);
            }
        } catch (error) {
            if (error && error.name === 'AbortError') {
                throw error;
            }

            console.error('Failed to load FIDO MDS explorer data:', error);
            const message =
                error instanceof Error && error.message
                    ? error.message
                    : 'Unable to load the packaged authenticator explorer.';
            setStatus(message, 'error');
            setRetryButtonVisible(true);

            if (!hasLoaded) {
                hasLoaded = false;
                setColumnResizersEnabled(false);
            } else {
                setColumnResizersEnabled(true);
            }
        } finally {
            isLoading = false;
        }
    })();

    loadPromise = task;
    explorerPreloadPromise = task;

    try {
        await task;
    } finally {
        if (loadPromise === task) {
            loadPromise = null;
        }
        if (explorerPreloadPromise === task && !isLoading) {
            explorerPreloadPromise = null;
        }
    }
}

export async function waitForMetadataLoad() {
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

    mdsState?.authenticatorStickyHeader?.sync();
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
    const detailPageActive = document.querySelector('.mds-detail-page.mds-detail-page--open');
    const shouldLock = Boolean(overlayActive || modalActive || mdsModalActive || detailPageActive);

    const targets = [document.body, document.documentElement].filter(Boolean);
    targets.forEach(target => target.classList.toggle('modal-open', shouldLock));
}

function createDetailStickyHeader(page, header, options = {}) {
    if (!(page instanceof HTMLElement) || !(header instanceof HTMLElement)) {
        return null;
    }

    const { defaultTitle = '', type = 'detail', onBack = null } = options || {};

    const backSource = header.querySelector('.mds-detail-page__back');
    const titleSource = header.querySelector('.mds-detail-page__title');
    const subtitleSource = header.querySelector('.mds-detail-page__subtitle');
    const actionsSource = header.querySelector('.mds-detail-page__actions');

    const controller = initializeStickyHeaderForElement(header, {
        root: document.body instanceof HTMLElement ? document.body : header.parentElement,
        scrollTarget: page,
        miniClass: 'mds-detail-mini',
        miniInnerClass: 'mds-detail-mini__inner',
        activeClass: 'mds-detail-mini--active',
        measuringClass: 'mds-detail-mini--measuring',
        createContent: () => {
            const wrapper = document.createElement('div');
            wrapper.className = 'mds-detail-mini__content';

            if (backSource instanceof HTMLElement) {
                const backButton = backSource.cloneNode(true);
                backButton.removeAttribute('id');
                backButton.classList.add('mds-detail-mini__back');
                wrapper.appendChild(backButton);
            }

            const heading = document.createElement('div');
            heading.className = 'mds-detail-mini__heading';

            const title = document.createElement('h3');
            title.className = 'mds-detail-page__title mds-detail-mini__title';
            title.textContent = titleSource?.textContent?.trim() || defaultTitle;
            heading.appendChild(title);

            const subtitle = document.createElement('p');
            subtitle.className = 'mds-detail-page__subtitle mds-detail-mini__subtitle';
            const subtitleText = subtitleSource?.textContent?.trim() || '';
            if (subtitleText) {
                subtitle.textContent = subtitleText;
            } else {
                subtitle.textContent = '';
                subtitle.hidden = true;
                subtitle.setAttribute('aria-hidden', 'true');
            }
            heading.appendChild(subtitle);

            wrapper.appendChild(heading);

            if (actionsSource instanceof HTMLElement && actionsSource.children.length > 0) {
                const actions = actionsSource.cloneNode(true);
                actions.removeAttribute('id');
                actions.classList.add('mds-detail-mini__actions');
                const buttons = actions.querySelectorAll('button');
                buttons.forEach(button => {
                    button.classList.add('mds-detail-mini__action');
                    button.removeAttribute('id');
                });
                wrapper.appendChild(actions);
            }

            return wrapper;
        },
    });

    if (!controller) {
        return null;
    }

    const miniHeader = controller.miniHeader;
    const miniInner = controller.miniInner;
    miniHeader.hidden = true;
    miniHeader.setAttribute('aria-hidden', 'true');
    miniHeader.dataset.mdsStickyType = type;

    const backTarget = miniHeader.querySelector('.mds-detail-mini__back');
    if (backTarget instanceof HTMLElement && backSource instanceof HTMLElement) {
        backTarget.addEventListener('click', event => {
            event.preventDefault();
            if (typeof onBack === 'function') {
                onBack();
            } else if (typeof backSource.click === 'function') {
                backSource.click();
            }
        });
    }

    const titleTarget = miniHeader.querySelector('.mds-detail-mini__title');
    const subtitleTarget = miniHeader.querySelector('.mds-detail-mini__subtitle');
    const actionsTarget = miniHeader.querySelector('.mds-detail-mini__actions');

    const actionPairs = [];
    if (actionsSource instanceof HTMLElement && actionsTarget instanceof HTMLElement) {
        const sourceButtons = Array.from(actionsSource.querySelectorAll('button'));
        const targetButtons = Array.from(actionsTarget.querySelectorAll('button'));
        targetButtons.forEach((button, index) => {
            const sourceButton = sourceButtons[index] || null;
            button.addEventListener('click', event => {
                event.preventDefault();
                if (sourceButton && typeof sourceButton.click === 'function') {
                    sourceButton.click();
                }
            });
            actionPairs.push({ source: sourceButton, target: button });
        });
    }

    let restoreAnimationCancel = null;

    const cancelRestoreAnimation = () => {
        if (typeof restoreAnimationCancel === 'function') {
            try {
                restoreAnimationCancel();
            } catch (error) {
                // Ignore cleanup errors.
            }
            restoreAnimationCancel = null;
        }
    };

    const startRestoreAnimation = () => {
        if (!miniHeader || miniHeader.hidden || !(miniInner instanceof HTMLElement)) {
            return null;
        }

        const scheduleTimeout =
            typeof window !== 'undefined' && typeof window.setTimeout === 'function'
                ? window.setTimeout.bind(window)
                : setTimeout;
        const cancelTimeout =
            typeof window !== 'undefined' && typeof window.clearTimeout === 'function'
                ? window.clearTimeout.bind(window)
                : clearTimeout;

        let timeoutId = null;
        let finished = false;

        const handleTransitionEnd = event => {
            if (!event || (event.target !== miniHeader && event.target !== miniInner)) {
                return;
            }
            cleanup();
        };

        function cleanup() {
            if (finished) {
                return;
            }
            finished = true;
            miniHeader.classList.remove('mds-detail-mini--restoring');
            miniInner.classList.remove('mds-detail-mini__inner--restoring');
            miniHeader.removeEventListener('transitionend', handleTransitionEnd);
            miniInner.removeEventListener('transitionend', handleTransitionEnd);
            if (timeoutId !== null) {
                cancelTimeout(timeoutId);
                timeoutId = null;
            }
            restoreAnimationCancel = null;
        }

        miniHeader.classList.add('mds-detail-mini--restoring');
        miniInner.classList.add('mds-detail-mini__inner--restoring');
        miniHeader.addEventListener('transitionend', handleTransitionEnd);
        miniInner.addEventListener('transitionend', handleTransitionEnd);

        timeoutId = scheduleTimeout(() => {
            cleanup();
        }, 360);

        return cleanup;
    };

    const sync = () => {
        if (titleTarget) {
            const titleText = titleSource?.textContent?.trim() || defaultTitle;
            titleTarget.textContent = titleText;
            titleTarget.setAttribute('title', titleText);
        }

        if (subtitleTarget) {
            const subtitleText = subtitleSource?.textContent?.trim() || '';
            if (subtitleText) {
                subtitleTarget.textContent = subtitleText;
                subtitleTarget.hidden = false;
                subtitleTarget.setAttribute('aria-hidden', 'false');
            } else {
                subtitleTarget.textContent = '';
                subtitleTarget.hidden = true;
                subtitleTarget.setAttribute('aria-hidden', 'true');
            }
        }

        actionPairs.forEach(({ source, target }) => {
            if (!target) {
                return;
            }
            if (!source) {
                target.disabled = true;
                target.setAttribute('aria-disabled', 'true');
                target.setAttribute('tabindex', '-1');
                return;
            }

            target.disabled = source.disabled;
            if (source.hasAttribute('aria-disabled')) {
                target.setAttribute('aria-disabled', source.getAttribute('aria-disabled'));
            } else {
                target.setAttribute('aria-disabled', source.disabled ? 'true' : 'false');
            }

            if (source.hasAttribute('title')) {
                target.setAttribute('title', source.getAttribute('title'));
            } else {
                target.removeAttribute('title');
            }

            if (source.hasAttribute('aria-label')) {
                target.setAttribute('aria-label', source.getAttribute('aria-label'));
            } else {
                target.removeAttribute('aria-label');
            }

            if (source.hasAttribute('data-tooltip')) {
                target.setAttribute('data-tooltip', source.getAttribute('data-tooltip'));
            } else {
                target.removeAttribute('data-tooltip');
            }

            const textContent = source.textContent || '';
            target.textContent = textContent;

            if (source.hasAttribute('tabindex')) {
                target.setAttribute('tabindex', source.getAttribute('tabindex'));
            } else {
                target.removeAttribute('tabindex');
            }
        });
    };

    const show = () => {
        miniHeader.hidden = false;
        miniHeader.setAttribute('aria-hidden', 'false');
        cancelRestoreAnimation();
        controller.reset();
        restoreAnimationCancel = startRestoreAnimation();
        controller.refreshGeometry();
        controller.evaluate();
        sync();
    };

    const prepareForClose = () => {
        cancelRestoreAnimation();
        controller.reset();
    };

    const hide = () => {
        cancelRestoreAnimation();
        miniHeader.hidden = true;
        miniHeader.setAttribute('aria-hidden', 'true');
    };

    return {
        controller,
        header,
        page,
        show,
        hide,
        sync,
        prepareForClose,
        miniHeader,
    };
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

    void openAuthenticatorModal(sourceEntry);
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
        button.addEventListener('click', () => openCertificatePage(certificate, button));
        container.appendChild(button);
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

    if (
        base.metadataStatement
        && typeof base.metadataStatement === 'object'
        && base.metadataStatement.attestationRootCertificates === undefined
        && Array.isArray(entry.attestationCertificates)
        && entry.attestationCertificates.length
    ) {
        base.metadataStatement.attestationRootCertificates = entry.attestationCertificates;
    }

    if (base.attestationCertificateKeyIdentifiers === undefined) {
        const identifiers = Array.isArray(entry.attestationKeyIdentifiers)
            ? entry.attestationKeyIdentifiers
            : [];
        if (identifiers.length) {
            base.attestationCertificateKeyIdentifiers = identifiers;
            if (
                base.metadataStatement
                && typeof base.metadataStatement === 'object'
                && base.metadataStatement.attestationCertificateKeyIdentifiers === undefined
            ) {
                base.metadataStatement.attestationCertificateKeyIdentifiers = identifiers;
            }
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

    // If lazy loading is active and certificate verification is requested,
    // ensure entries with this certificate are fully parsed
    if (lazyLoader && !lazyLoader.isFullyLoaded()) {
        const matchingRawEntries = lazyLoader.findEntriesWithCertificate(cleaned);
        if (matchingRawEntries.length > 0) {
            // Ensure these entries are fully parsed in mdsData
            matchingRawEntries.forEach(rawEntry => {
                const key = normaliseAaguid(rawEntry?.aaguid || rawEntry?.metadataStatement?.aaguid);
                
                // Check if entry already exists in mdsData
                let existingEntry = null;
                if (key && mdsState?.byAaguid) {
                    existingEntry = mdsState.byAaguid.get(key);
                }
                
                if (!existingEntry) {
                    // Entry not in mdsData yet, search by index
                    existingEntry = mdsData.find(e => {
                        const eKey = normaliseAaguid(e?.aaguid || e?.id);
                        return eKey === key;
                    });
                }
                
                if (existingEntry) {
                    // Entry exists but might be lightweight - upgrade it
                    if (existingEntry.isLightweightEntry) {
                        const fullEntry = upgradeEntryToFull(existingEntry);
                        Object.assign(existingEntry, fullEntry);
                        
                        // Mark as fully parsed
                        if (typeof existingEntry.index === 'number') {
                            lazyLoader.markEntryFullyParsed(existingEntry.index, key);
                        }
                    }
                } else {
                    // Entry not in mdsData at all - add it with full parsing
                    const index = mdsData.length;
                    const transformed = transformEntry(rawEntry, index);
                    if (transformed) {
                        mdsData.push(transformed);
                        if (key && mdsState?.byAaguid) {
                            mdsState.byAaguid.set(key, transformed);
                        }
                        lazyLoader.markEntryFullyParsed(index, key);
                    }
                }
            });
        }
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

function applyCertificateLoadingCursorVisibility() {
    const shouldShow = certificateCursorRequestCount > 0;
    [document.documentElement, document.body].forEach(target => {
        if (target) {
            target.classList.toggle(MDS_CERTIFICATE_LOADING_CURSOR_CLASS, shouldShow);
        }
    });
}

function beginCertificateLoadingCursor() {
    certificateCursorRequestCount += 1;
    applyCertificateLoadingCursorVisibility();
}

function endCertificateLoadingCursor() {
    certificateCursorRequestCount = Math.max(0, certificateCursorRequestCount - 1);
    applyCertificateLoadingCursorVisibility();
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

async function openCertificatePage(certificate, sourceButton = null) {
    if (!mdsState?.certificatePage) {
        return;
    }

    const cleaned = normaliseCertificateBase64(certificate);
    if (!cleaned) {
        return;
    }

    const triggerButton = sourceButton instanceof HTMLButtonElement ? sourceButton : null;

    if (triggerButton) {
        triggerButton.classList.add('is-loading');
        triggerButton.setAttribute('aria-busy', 'true');
        triggerButton.disabled = true;
    }

    beginCertificateLoadingCursor();

    let details = null;
    let decodeError = null;
    try {
        details = await decodeCertificate(cleaned);
    } catch (error) {
        decodeError = error;
    } finally {
        endCertificateLoadingCursor();
        if (triggerButton) {
            triggerButton.classList.remove('is-loading');
            triggerButton.removeAttribute('aria-busy');
            triggerButton.disabled = false;
        }
    }

    if (mdsState.certificateInput) {
        setCertificateFieldContent(mdsState.certificateInput, formatCertificateInput(cleaned));
        mdsState.certificateInput.scrollTop = 0;
        mdsState.certificateInput.scrollLeft = 0;
    }

    if (decodeError) {
        const message = decodeError instanceof Error ? decodeError.message : 'Unable to decode certificate.';
        if (mdsState.certificateOutput) {
            setCertificateFieldContent(mdsState.certificateOutput, message);
            mdsState.certificateOutput.scrollTop = 0;
            mdsState.certificateOutput.scrollLeft = 0;
        }
        setCertificateSummaryContent(message);
        if (mdsState.certificateTitle) {
            mdsState.certificateTitle.textContent = 'Attestation Certificate';
        }
        if (mdsState.certificateSubtitle) {
            mdsState.certificateSubtitle.textContent = '';
            mdsState.certificateSubtitle.hidden = true;
        }
    } else {
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
        if (mdsState.certificateTitle) {
            mdsState.certificateTitle.textContent = subject || 'Attestation Certificate';
        }
        const issuer = details && typeof details.issuer === 'string' ? details.issuer.trim() : '';
        if (mdsState.certificateSubtitle) {
            if (issuer) {
                mdsState.certificateSubtitle.textContent = issuer;
                mdsState.certificateSubtitle.hidden = false;
            } else {
                mdsState.certificateSubtitle.textContent = '';
                mdsState.certificateSubtitle.hidden = true;
            }
        }
    }

    hideScrollTopButton();

    const sticky = mdsState.certificateStickyHeader || null;
    const authenticatorSticky = mdsState.authenticatorStickyHeader || null;

    if (authenticatorSticky) {
        authenticatorSticky.prepareForClose?.();
        authenticatorSticky.hide();
    }

    if (sticky) {
        sticky.show();
    }

    sticky?.sync();

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

    const page = mdsState.certificatePage;
    page.classList.remove('mds-detail-page--open');
    page.classList.remove('mds-detail-page--closing');
    page.hidden = false;
    page.setAttribute('aria-hidden', 'false');

    const activatePage = () => {
        if (page.hidden) {
            return;
        }
        page.classList.add('mds-detail-page--open');
        notifyGlobalScrollLock();
    };
    if (typeof requestAnimationFrame === 'function') {
        requestAnimationFrame(activatePage);
    } else {
        activatePage();
    }

    resetScrollPositions(
        mdsState.certificatePageBody,
        page,
        mdsState.certificateSummary,
        mdsState.certificateInput,
        mdsState.certificateOutput,
    );
    scheduleCertificateTextareaResize();

    const focusTarget = mdsState.certificateClose instanceof HTMLElement ? mdsState.certificateClose : null;
    if (focusTarget) {
        requestAnimationFrame(() => focusTarget.focus());
    }

    sticky?.sync();
}

function closeCertificatePage() {
    if (!mdsState?.certificatePage) {
        return;
    }

    const page = mdsState.certificatePage;
    if (page.hidden) {
        return;
    }

    const sticky = mdsState.certificateStickyHeader || null;

    const previousScroll =
        typeof mdsState.listScrollTop === 'number' ? mdsState.listScrollTop : null;

    const clearSubtitle = () => {
        if (mdsState.certificateSubtitle) {
            mdsState.certificateSubtitle.textContent = '';
            mdsState.certificateSubtitle.hidden = true;
        }
    };

    const finishClose = () => {
        page.hidden = true;
        page.setAttribute('aria-hidden', 'true');
        page.classList.remove('mds-detail-page--closing');
        resetScrollPositions(
            mdsState.certificatePageBody,
            page,
            mdsState.certificateSummary,
            mdsState.certificateInput,
            mdsState.certificateOutput,
        );
        resetCertificateTextareaHeights();
        clearSubtitle();
        notifyGlobalScrollLock();
        restoreListSection(mdsState.listSection);
        scheduleScrollTopButtonUpdate();
        sticky?.hide();

        if (mdsState?.authenticatorModal && !mdsState.authenticatorModal.hidden) {
            const authenticatorSticky = mdsState.authenticatorStickyHeader || null;
            if (authenticatorSticky) {
                authenticatorSticky.show();
                authenticatorSticky.sync?.();
            }
        }
        if (previousScroll !== null && typeof window !== 'undefined') {
            requestAnimationFrame(() => {
                window.scrollTo(0, previousScroll);
            });
        }
        mdsState.listScrollTop = null;
    };

    const beginClose = () => {
        restoreListSection(mdsState.listSection);
        if (typeof requestAnimationFrame === 'function') {
            requestAnimationFrame(() => restoreListSection(mdsState.listSection));
        }
        page.classList.remove('mds-detail-page--open');
        page.classList.add('mds-detail-page--closing');
        sticky?.prepareForClose();

        const scheduleTimeout =
            typeof window !== 'undefined' && typeof window.setTimeout === 'function'
                ? window.setTimeout.bind(window)
                : setTimeout;
        const cancelTimeout =
            typeof window !== 'undefined' && typeof window.clearTimeout === 'function'
                ? window.clearTimeout.bind(window)
                : clearTimeout;

        let timeoutId = null;
        const clear = () => {
            if (timeoutId !== null) {
                cancelTimeout(timeoutId);
                timeoutId = null;
            }
        };

        const handleTransitionEnd = event => {
            if (event?.target !== page) {
                return;
            }
            page.removeEventListener('transitionend', handleTransitionEnd);
            clear();
            finishClose();
        };

        page.addEventListener('transitionend', handleTransitionEnd);
        timeoutId = scheduleTimeout(() => {
            page.removeEventListener('transitionend', handleTransitionEnd);
            clear();
            finishClose();
        }, 500);
    };

    beginClose();
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

    mdsState?.authenticatorStickyHeader?.sync();
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

async function openAuthenticatorModal(entry) {
    if (!mdsState?.authenticatorModal) {
        return;
    }

    if (entry && !hasInlineDetail(entry)) {
        const query = {};
        if (typeof entry.entryId === 'string' && entry.entryId) {
            query.entryId = entry.entryId;
        } else if (typeof entry.aaguid === 'string' && entry.aaguid) {
            query.aaguid = normaliseAaguid(entry.aaguid);
        } else if (typeof entry.id === 'string' && entry.id) {
            query.aaid = entry.id;
        }

        try {
            const resolved = await resolveMetadataEntry(query);
            if (resolved) {
                entry = resolved;
            }
        } catch (error) {
            console.warn('Failed to resolve full authenticator metadata entry.', error);
        }
    }

    const modal = mdsState.authenticatorModal;
    const sticky = mdsState.authenticatorStickyHeader || null;
    const certificateSticky = mdsState.certificateStickyHeader || null;

    if (mdsState?.certificatePage && !mdsState.certificatePage.hidden && certificateSticky) {
        certificateSticky.prepareForClose?.();
        certificateSticky.hide();
    }

    if (entry) {
        mdsState.activeDetailEntry = entry;
    }
    const detailEntry = mdsState.activeDetailEntry || entry || null;
    hideScrollTopButton();

    updateAuthenticatorRawButton(detailEntry);

    applyDetailHeader(detailEntry, mdsState.authenticatorModalTitle, mdsState.authenticatorModalSubtitle);
    populateDetailContent(mdsState.authenticatorModalContent, detailEntry);
    sticky?.sync();

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
    modal.classList.remove('mds-detail-page--closing');
    modal.hidden = false;
    modal.setAttribute('aria-hidden', 'false');
    if (sticky) {
        sticky.show();
    }
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
    const sticky = mdsState.authenticatorStickyHeader || null;

    if (modal.hidden) {
        return;
    }

    const previousScroll =
        typeof mdsState.listScrollTop === 'number' ? mdsState.listScrollTop : null;

    const finishClose = () => {
        modal.hidden = true;
        modal.setAttribute('aria-hidden', 'true');
        modal.classList.remove('mds-detail-page--closing');

        restoreListSection(mdsState.listSection);

        resetScrollPositions(mdsState.authenticatorModalBody, modal, mdsState.authenticatorModalContent);
        notifyGlobalScrollLock();
        mdsState.activeDetailEntry = null;
        updateAuthenticatorRawButton(null);
        sticky?.hide();
        scheduleScrollTopButtonUpdate();
        if (previousScroll !== null && typeof window !== 'undefined') {
            requestAnimationFrame(() => {
                window.scrollTo(0, previousScroll);
            });
        }
        mdsState.listScrollTop = null;
    };

    const beginClose = () => {
        restoreListSection(mdsState.listSection);
        if (typeof requestAnimationFrame === 'function') {
            requestAnimationFrame(() => restoreListSection(mdsState.listSection));
        }
        modal.classList.remove('mds-detail-page--open');
        modal.classList.add('mds-detail-page--closing');
        sticky?.prepareForClose();

        const scheduleTimeout =
            typeof window !== 'undefined' && typeof window.setTimeout === 'function'
                ? window.setTimeout.bind(window)
                : setTimeout;
        const cancelTimeout =
            typeof window !== 'undefined' && typeof window.clearTimeout === 'function'
                ? window.clearTimeout.bind(window)
                : clearTimeout;

        let timeoutId = null;
        const clear = () => {
            if (timeoutId !== null) {
                cancelTimeout(timeoutId);
                timeoutId = null;
            }
        };

        const handleTransitionEnd = event => {
            if (event?.target !== modal) {
                return;
            }
            modal.removeEventListener('transitionend', handleTransitionEnd);
            clear();
            finishClose();
        };

        modal.addEventListener('transitionend', handleTransitionEnd);
        timeoutId = scheduleTimeout(() => {
            modal.removeEventListener('transitionend', handleTransitionEnd);
            clear();
            finishClose();
        }, 500);
    };

    beginClose();
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

    if (isLoading && loadPromise) {
        try {
            await loadPromise;
        } catch (error) {
            // Continue to resolve via the server even if preload failed.
        }
    }

    const cached = mdsState.byAaguid?.get(targetKey) || null;
    if (cached && hasInlineDetail(cached)) {
        return cached;
    }

    const resolved = await resolveMetadataEntry({ aaguid: targetKey });
    if (resolved) {
        return resolved;
    }

    return cached || null;
}

async function openAuthenticatorModalByAaguid(aaguid) {
    const entry = await resolveEntryByAaguid(aaguid);
    if (!entry) {
        return null;
    }
    await openAuthenticatorModal(entry);
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

async function highlightAuthenticatorRowByAaguid(aaguid, options = {}) {
    const {
        scrollBehavior = 'smooth',
        preResolvedEntry = null,
        deferScroll = false,
        waitForVisibility = true,
        focusRow = true,
    } = options || {};

    let entry = preResolvedEntry || null;
    if (!entry) {
        entry = await resolveEntryByAaguid(aaguid);
    }
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

    if (waitForVisibility && mdsState.root) {
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

    const behaviour = typeof scrollBehavior === 'string' && scrollBehavior
        ? scrollBehavior
        : 'smooth';

    const applied = setHighlightedRow(row, key, {
        scroll: !deferScroll,
        behavior: behaviour,
        focus: focusRow && !deferScroll,
    });
    if (!applied && mdsState.highlightedRowKey === key) {
        mdsState.highlightedRowKey = '';
    }

    return { entry, highlighted: Boolean(applied), row: applied ? row : null };
}

function finaliseHighlightedAuthenticatorRow(options = {}) {
    if (!mdsState?.highlightedRow || !mdsState.highlightedRowKey) {
        return false;
    }

    const behaviour = typeof options.behavior === 'string' && options.behavior
        ? options.behavior
        : 'smooth';
    const shouldFocus = options.focus !== false;

    return setHighlightedRow(mdsState.highlightedRow, mdsState.highlightedRowKey, {
        scroll: true,
        behavior: behaviour,
        focus: shouldFocus,
    });
}

if (typeof window !== 'undefined') {
    window.openMdsAuthenticatorModal = openAuthenticatorModalByAaguid;
    window.focusMdsAuthenticator = focusAuthenticatorByAaguid;
    window.highlightMdsAuthenticatorRow = highlightAuthenticatorRowByAaguid;
    window.finaliseMdsAuthenticatorHighlight = finaliseHighlightedAuthenticatorRow;
    window.waitForMdsLoad = waitForMetadataLoad;
    window.getMdsLoadState = getMdsLoadStateSnapshot;
    window.resolveMdsEntryByAaguid = resolveEntryByAaguid;
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

    button.dataset.action = action;
    button.dataset.idleLabel = config.label;
    button.dataset.busyLabel = config.busyLabel;

    if (!button.classList.contains('is-busy')) {
        button.textContent = config.label;
    }
}



async function refreshMetadata() {
    if (isUpdatingMetadata) {
        return;
    }

    if (isLoading) {
        setStatus(
            'Metadata is currently loading. Please wait for the current operation to finish.',
            'info',
        );
        return;
    }

    isUpdatingMetadata = true;
    setUpdateButtonBusy(true);
    if (mdsState?.retryButton instanceof HTMLButtonElement) {
        mdsState.retryButton.disabled = true;
    }

    try {
        setStatus('Refreshing authenticator explorer…', 'info');
        clearMetadataCache();
        await loadMdsData('Explorer refreshed.', { forceReload: true });
    } catch (error) {
        console.error('Failed to refresh authenticator explorer:', error);
        const message =
            error instanceof Error && error.message
                ? error.message
                : 'Unable to refresh the packaged authenticator explorer.';
        setStatus(message, 'error');
        setRetryButtonVisible(true);
    } finally {
        setUpdateButtonBusy(false);
        if (mdsState?.retryButton instanceof HTMLButtonElement) {
            mdsState.retryButton.disabled = false;
        }
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
