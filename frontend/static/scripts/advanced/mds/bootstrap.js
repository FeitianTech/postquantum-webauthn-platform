export function bootstrapMds(deps = {}) {
    const {
        handleWindowScroll,
        initializeState,
        updateSortButtonState,
        setUpdateButtonMode,
        formatInitialExplorerStatus,
        setStatus,
        getState,
        setDefaultStatus,
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
    } = deps;

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
            initializeState(tabElement);
            updateSortButtonState();
            setUpdateButtonMode('update');
            const initialStatus = formatInitialExplorerStatus(getState()?.metadataSnapshotInfo);
            if (initialStatus) {
                setStatus(initialStatus, 'info');
                setDefaultStatus({
                    html: initialStatus,
                    variant: 'info',
                    title: '',
                });
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

    if (typeof window !== 'undefined') {
        window.openMdsAuthenticatorModal = openAuthenticatorModalByAaguid;
        window.focusMdsAuthenticator = focusAuthenticatorByAaguid;
        window.highlightMdsAuthenticatorRow = highlightAuthenticatorRowByAaguid;
        window.finaliseMdsAuthenticatorHighlight = finaliseHighlightedAuthenticatorRow;
        window.waitForMdsLoad = waitForMetadataLoad;
        window.getMdsLoadState = getMdsLoadStateSnapshot;
        window.resolveMdsEntryByAaguid = resolveEntryByAaguid;
    }
}
