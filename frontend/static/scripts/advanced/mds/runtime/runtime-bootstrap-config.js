export function createBootstrapRuntimeConfig({
    handleWindowScroll,
    initializeState,
    updateSortButtonState,
    setUpdateButtonMode,
    formatInitialExplorerStatus,
    setStatus,
    getState,
    getInitialSnapshotPayload,
    applyExplorerSnapshot,
    loadMdsData,
    openAuthenticatorModalByAaguid,
    focusAuthenticatorByAaguid,
    highlightAuthenticatorRowByAaguid,
    finaliseHighlightedAuthenticatorRow,
    waitForMetadataLoad,
    getMdsLoadStateSnapshot,
    resolveEntryByAaguid,
}) {
    return {
        handleWindowScroll,
        initializeState,
        updateSortButtonState,
        setUpdateButtonMode,
        formatInitialExplorerStatus,
        setStatus,
        getState,
        setDefaultStatus: value => {
            const state = getState();
            if (!state || !value || typeof value !== 'object') {
                return;
            }
            state.defaultStatus = {
                html: typeof value.html === 'string' ? value.html : '',
                variant: typeof value.variant === 'string' ? value.variant : 'info',
                title: typeof value.title === 'string' ? value.title : '',
            };
        },
        getInitialSnapshotPayload,
        applyExplorerSnapshot,
        loadMdsData,
        openAuthenticatorModalByAaguid,
        focusAuthenticatorByAaguid,
        highlightAuthenticatorRowByAaguid,
        finaliseHighlightedAuthenticatorRow,
        waitForMetadataLoad,
        getMdsLoadStateSnapshot,
        resolveEntryByAaguid,
    };
}
