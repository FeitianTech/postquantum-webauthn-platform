export async function resolveEntryByAaguidInState(aaguid, deps = {}) {
    const {
        waitForStateReady,
        getState,
        normaliseAaguid,
        isLoading,
        loadPromise,
        hasInlineDetail,
        resolveMetadataEntry,
    } = deps;

    const ready = await waitForStateReady();
    const state = getState();
    if (!ready || !state) {
        return null;
    }

    const targetKey = normaliseAaguid(aaguid);
    if (!targetKey) {
        return null;
    }

    if (isLoading() && loadPromise()) {
        try {
            await loadPromise();
        } catch (error) {
            // Continue to resolve via the server even if preload failed.
        }
    }

    const cached = state.byAaguid?.get(targetKey) || null;
    if (cached && hasInlineDetail(cached)) {
        return cached;
    }

    const resolved = await resolveMetadataEntry({ aaguid: targetKey });
    if (resolved) {
        return resolved;
    }

    return cached || null;
}

export async function openAuthenticatorModalByAaguidInState(aaguid, deps = {}) {
    const { resolveEntryByAaguid, openAuthenticatorModal } = deps;

    const entry = await resolveEntryByAaguid(aaguid);
    if (!entry) {
        return null;
    }
    await openAuthenticatorModal(entry);
    return entry;
}

export async function focusAuthenticatorByAaguidInState(aaguid, deps = {}) {
    const { resolveEntryByAaguid, resetFilters, showAuthenticatorDetail } = deps;

    const entry = await resolveEntryByAaguid(aaguid);
    if (!entry) {
        return null;
    }

    resetFilters();
    showAuthenticatorDetail(entry, { scrollIntoView: true });
    return entry;
}

export async function highlightAuthenticatorRowByAaguidInState(aaguid, options = {}, deps = {}) {
    const {
        resolveEntryByAaguid,
        getState,
        normaliseAaguid,
        hideAuthenticatorDetail,
        waitForElementVisible,
        resetFilters,
        applyFilters,
        waitForLayoutSettled,
        waitForRowByKey,
        setHighlightedRow,
    } = deps;

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

    const state = getState();
    if (!state) {
        return { entry: entry || null, highlighted: false };
    }

    if (!entry) {
        return { entry: null, highlighted: false };
    }

    const key = normaliseAaguid(entry.aaguid || entry.id);
    if (!key) {
        return { entry, highlighted: false };
    }

    state.highlightedRowKey = key;

    if (state.authenticatorModal && !state.authenticatorModal.hidden) {
        hideAuthenticatorDetail();
    }

    if (waitForVisibility && state.root) {
        await waitForElementVisible(state.root);
    }

    resetFilters();
    applyFilters();
    await waitForLayoutSettled();

    const row = await waitForRowByKey(key, { attempts: 80 });
    if (!row || state.highlightedRowKey !== key) {
        if (state.highlightedRowKey === key) {
            state.highlightedRowKey = '';
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
    if (!applied && state.highlightedRowKey === key) {
        state.highlightedRowKey = '';
    }

    return { entry, highlighted: Boolean(applied), row: applied ? row : null };
}

export function finaliseHighlightedAuthenticatorRowInState(options = {}, deps = {}) {
    const { getState, setHighlightedRow } = deps;

    const state = getState();
    if (!state?.highlightedRow || !state.highlightedRowKey) {
        return false;
    }

    const behaviour = typeof options.behavior === 'string' && options.behavior
        ? options.behavior
        : 'smooth';
    const shouldFocus = options.focus !== false;

    return setHighlightedRow(state.highlightedRow, state.highlightedRowKey, {
        scroll: true,
        behavior: behaviour,
        focus: shouldFocus,
    });
}
