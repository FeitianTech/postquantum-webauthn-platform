import { requestResolvedEntry } from '../explorer/entry-link.js';
import { indexEntriesByAaguid, prepareSnapshotEntries } from '../explorer/loading.js';
import { explorerLoadedStatus } from '../explorer/status.js';
import { loadMdsDataInState as loadMdsDataFromModule } from './explorer-load.js';

export function resetExplorerStateInState(message, variant = 'info', deps = {}) {
    const {
        getState,
        setMdsData,
        setFilteredData,
        setHasLoaded,
        clearResolvedEntryCache,
        updateCount,
        setColumnResizersEnabled,
        setStatus,
        setRetryButtonVisible,
        COLUMN_COUNT,
    } = deps;

    setMdsData([]);
    setFilteredData([]);
    setHasLoaded(true);
    clearResolvedEntryCache();

    const state = getState();
    if (state) {
        state.byAaguid = new Map();
    }

    updateCount(0, 0);
    setColumnResizersEnabled(false);
    setStatus(message, variant);
    setRetryButtonVisible(false);

    if (state) {
        state.defaultStatus = { text: message, variant, title: '' };
        if (state.tableBody) {
            const tbody = state.tableBody;
            tbody.replaceChildren();
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

export function applyExplorerSnapshotInState(snapshot, note = '', deps = {}) {
    const {
        getState,
        normaliseSnapshotInfo,
        getResolvedEntryCache,
        setMdsData,
        resetSortState,
        setUpdateButtonMode,
        collectOptionSets,
        updateOptionLists,
        applyFilters,
        scheduleHorizontalScrollMetricsUpdate,
        setColumnResizersEnabled,
        setRetryButtonVisible,
        setHasLoaded,
        buildLoadedStatus,
        setStatus,
    } = deps;

    const state = getState();
    if (!state) {
        return;
    }

    const meta = snapshot?.meta && typeof snapshot.meta === 'object' ? snapshot.meta : {};
    state.metadataSnapshotInfo = normaliseSnapshotInfo(meta);

    const resolvedEntryCache = getResolvedEntryCache();
    const entries = prepareSnapshotEntries(snapshot, resolvedEntryCache);

    setMdsData(entries);
    resetSortState();
    setUpdateButtonMode('update');

    state.byAaguid = indexEntriesByAaguid(entries, resolvedEntryCache);

    updateOptionLists(collectOptionSets(entries));
    applyFilters();
    scheduleHorizontalScrollMetricsUpdate();
    setColumnResizersEnabled(Boolean(entries.length));
    setRetryButtonVisible(false);

    setHasLoaded(true);

    const status = explorerLoadedStatus(snapshot, note, entries.length, buildLoadedStatus);
    setStatus(status.text, status.variant);

    state.defaultStatus = status;

    if (state.statusEl) {
        if (state.defaultStatus.title) {
            state.statusEl.setAttribute('title', state.defaultStatus.title);
        } else {
            state.statusEl.removeAttribute('title');
        }
    }
}

export function integrateResolvedEntryInState(entry, deps = {}) {
    const {
        getState,
        normaliseAaguid,
        getMdsData,
        setMdsData,
        getHasLoaded,
        applyFilters,
        hasInlineDetail,
        getResolvedEntryCache,
    } = deps;

    if (!entry || typeof entry !== 'object') {
        return null;
    }

    const state = getState();
    const mdsData = getMdsData();
    const resolvedEntryCache = getResolvedEntryCache();

    const key = normaliseAaguid(entry.aaguid || entry.id);
    let target = null;

    if (key && state?.byAaguid?.has(key)) {
        target = state.byAaguid.get(key);
    } else if (entry.entryId) {
        target = mdsData.find(item => item?.entryId === entry.entryId) || null;
    }

    if (target && target !== entry) {
        Object.assign(target, entry, { isLightweightEntry: false });
        entry = target;
    } else if (!target && getHasLoaded()) {
        const nextData = [...mdsData, entry];
        setMdsData(nextData);
        applyFilters({ preserveTableScroll: true });
    }

    if (entry.entryId) {
        resolvedEntryCache.set(entry.entryId, entry);
    }
    if (key && state?.byAaguid) {
        state.byAaguid.set(key, entry);
    }

    return entry;
}

// The current page opens with what the list had when the server refuses (it
// never shows the refusal) or answers without an entry.
export async function resolveMetadataEntryInState(query, deps = {}) {
    const { integrateResolvedEntry } = deps;
    const { entry } = await requestResolvedEntry(query);
    return entry ? integrateResolvedEntry(entry) : null;
}

export async function loadMdsDataInState(statusNote, options = {}, deps = {}) {
    return loadMdsDataFromModule(statusNote, options, deps);
}
