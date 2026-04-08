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
        setStatus(
            'Metadata is currently loading. Please wait for the current operation to finish.',
            'info',
        );
        return;
    }

    setIsUpdating(true);
    setUpdateButtonBusy(true);
    const state = getState();
    if (state?.retryButton instanceof HTMLButtonElement) {
        state.retryButton.disabled = true;
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
        const latestState = getState();
        if (latestState?.retryButton instanceof HTMLButtonElement) {
            latestState.retryButton.disabled = false;
        }
        setIsUpdating(false);
    }
}
