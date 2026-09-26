import {
    EXPLORER_BUSY_STATUS,
    EXPLORER_REFRESHED_NOTE,
    explorerLoadingStatus,
    explorerRefreshFailure,
} from '../explorer/status.js';

export async function refreshMetadataInState(deps = {}) {
    const {
        getIsUpdating,
        setIsUpdating,
        getIsLoading,
        setStatus,
        setUpdateButtonBusy,
        getState,
        clearMetadataCache,
        loadMdsData,
        setRetryButtonVisible,
    } = deps;

    if (getIsUpdating()) {
        return;
    }

    if (getIsLoading()) {
        setStatus(EXPLORER_BUSY_STATUS, 'info');
        return;
    }

    setIsUpdating(true);
    setUpdateButtonBusy(true);
    const state = getState();
    if (state?.retryButton instanceof HTMLButtonElement) {
        state.retryButton.disabled = true;
    }

    try {
        setStatus(explorerLoadingStatus(true), 'info');
        clearMetadataCache();
        await loadMdsData(EXPLORER_REFRESHED_NOTE, { forceReload: true });
    } catch (error) {
        console.error('Failed to refresh authenticator explorer:', error);
        setStatus(explorerRefreshFailure(error), 'error');
        setRetryButtonVisible(true);
    } finally {
        setUpdateButtonBusy(false);
        const latestState = getState();
        if (latestState?.retryButton instanceof HTMLButtonElement) {
            latestState.retryButton.disabled = false;
        }
        setIsUpdating(false);
    }
}
