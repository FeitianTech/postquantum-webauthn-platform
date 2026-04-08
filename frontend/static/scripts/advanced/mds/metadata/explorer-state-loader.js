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
        state.defaultStatus = { html: message, variant, title: '' };
        if (state.tableBody) {
            const tbody = state.tableBody;
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

export function applyExplorerSnapshotInState(snapshot, note = '', deps = {}) {
    const {
        getState,
        normaliseSnapshotInfo,
        cloneMetadataEntry,
        hasInlineDetail,
        getResolvedEntryCache,
        setMdsData,
        resetSortState,
        setUpdateButtonMode,
        normaliseAaguid,
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
    const incomingEntries = Array.isArray(snapshot?.entries) ? snapshot.entries : [];
    state.metadataSnapshotInfo = normaliseSnapshotInfo(meta);

    const resolvedEntryCache = getResolvedEntryCache();

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

    setMdsData(entries);
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
    state.byAaguid = byAaguid;

    updateOptionLists(collectOptionSets(entries));
    applyFilters();
    scheduleHorizontalScrollMetricsUpdate();
    setColumnResizersEnabled(Boolean(entries.length));
    setRetryButtonVisible(false);

    setHasLoaded(true);

    const statusMessage = buildLoadedStatus(snapshot, note);
    const statusVariant = entries.length ? 'success' : 'info';
    setStatus(statusMessage, statusVariant);

    state.defaultStatus = {
        html: statusMessage,
        variant: statusVariant,
        title: typeof meta.legalHeader === 'string' ? meta.legalHeader : '',
    };

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

export async function resolveMetadataEntryInState(query, deps = {}) {
    const {
        mdsResolvePath,
        integrateResolvedEntry,
    } = deps;

    const params = new URLSearchParams();
    Object.entries(query || {}).forEach(([key, value]) => {
        if (typeof value === 'string' && value) {
            params.set(key, value);
        }
    });

    if (!params.toString()) {
        return null;
    }

    const response = await fetch(`${mdsResolvePath}?${params.toString()}`, {
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

export async function loadMdsDataInState(statusNote, options = {}, deps = {}) {
    return loadMdsDataFromModule(statusNote, options, deps);
}
