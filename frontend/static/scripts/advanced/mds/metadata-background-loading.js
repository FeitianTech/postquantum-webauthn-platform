export async function startBackgroundMetadataLoadingInState(metadata, options = {}, deps = {}) {
    const {
        getLazyLoader,
        getBackgroundLoadingInProgress,
        setBackgroundLoadingInProgress,
        getState,
        updateBackgroundLoadingStatus,
        finalizeBackgroundLoading,
        populateCertificateDerivedInfoForBatch,
        getMdsData,
    } = deps;

    const lazyLoader = getLazyLoader();
    if (getBackgroundLoadingInProgress() || !lazyLoader) {
        return;
    }

    setBackgroundLoadingInProgress(true);
    const { signal, lastUpdatedDate } = options;

    lazyLoader.onProgress((parsed, total) => {
        const state = getState();
        if (state?.statusEl && !state.statusEl.hidden) {
            if (parsed % 500 === 0 || parsed === total) {
                updateBackgroundLoadingStatus(parsed, total, lastUpdatedDate);
            }
        }
    });

    lazyLoader.onComplete(() => {
        finalizeBackgroundLoading(metadata, lastUpdatedDate);
    });

    const processBatch = async batchIndices => {
        const data = getMdsData();
        const validIndices = batchIndices.filter(i =>
            typeof i === 'number' && i >= 0 && i < data.length,
        );

        if (!validIndices.length) {
            return;
        }

        const batchEntries = validIndices.map(i => data[i]).filter(entry => entry != null);

        try {
            await populateCertificateDerivedInfoForBatch(batchEntries);
        } catch (error) {
            console.error('Failed to process certificate info for batch:', error);
        }
    };

    try {
        await lazyLoader.startBackgroundLoading({ signal, onBatchProcessed: processBatch });
    } catch (error) {
        console.error('Background metadata loading failed:', error);
    } finally {
        setBackgroundLoadingInProgress(false);
    }
}
