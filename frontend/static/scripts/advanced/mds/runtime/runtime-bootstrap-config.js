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
                text: typeof value.text === 'string' ? value.text : '',
                variant: typeof value.variant === 'string' ? value.variant : 'info',
                title: typeof value.title === 'string' ? value.title : '',
            };
        },
        getInitialSnapshotPayload,
        applyExplorerSnapshot,
        loadMdsData,
    };
}
