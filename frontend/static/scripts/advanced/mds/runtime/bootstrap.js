import { el } from '../../../shared/ui/dom.js';

const PRELOAD_FALLBACK_DELAY_MS = 10000;
const IDLE_CALLBACK_TIMEOUT_MS = 4000;
const IDLE_FALLBACK_DELAY_MS = 1500;

function shouldSkipBackgroundPreload() {
    const connection = typeof navigator !== 'undefined' ? navigator.connection : null;
    if (!connection) {
        return false;
    }
    if (connection.saveData) {
        return true;
    }
    return typeof connection.effectiveType === 'string' && /2g$/.test(connection.effectiveType);
}

function runWhenIdle(callback) {
    if (typeof window !== 'undefined' && typeof window.requestIdleCallback === 'function') {
        window.requestIdleCallback(() => callback(), { timeout: IDLE_CALLBACK_TIMEOUT_MS });
        return;
    }
    setTimeout(callback, IDLE_FALLBACK_DELAY_MS);
}

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
    } = deps;

    if (typeof window !== 'undefined') {
        window.addEventListener('scroll', handleWindowScroll, { passive: true });
        window.addEventListener('resize', handleWindowScroll);
    }

    let explorerReady = false;
    let backgroundPreloadScheduled = false;

    function startLoad() {
        if (explorerReady) {
            void loadMdsData();
        }
    }

    // The explorer is not needed to use the rest of the app, so its data is
    // loaded once the app is interactive, or immediately when the user heads
    // for the MDS tab.
    function scheduleBackgroundPreload() {
        if (!explorerReady || backgroundPreloadScheduled || shouldSkipBackgroundPreload()) {
            return;
        }
        backgroundPreloadScheduled = true;
        runWhenIdle(startLoad);
    }

    document.addEventListener('app:ready', scheduleBackgroundPreload, { once: true });

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
                    text: initialStatus,
                    variant: 'info',
                    title: '',
                });
            }
        } catch (error) {
            console.error('Failed to initialise the FIDO MDS tab:', error);
            tabElement.replaceChildren(
                el('div', { className: 'section mds-section' },
                    el('div', {
                        className: 'mds-status mds-status-error',
                        text: 'Unable to load authenticator explorer. Check the console for details.',
                    }),
                ),
            );
            return;
        }

        explorerReady = true;

        const bootstrapSnapshot = getInitialSnapshotPayload();
        if (bootstrapSnapshot) {
            applyExplorerSnapshot(bootstrapSnapshot);
            return;
        }

        if (tabElement.classList.contains('active')) {
            startLoad();
            return;
        }

        const mdsNavButton = document.querySelector('[data-tab="mds"]');
        if (mdsNavButton) {
            mdsNavButton.addEventListener('pointerenter', startLoad, { once: true });
            mdsNavButton.addEventListener('focus', startLoad, { once: true });
        }

        setTimeout(scheduleBackgroundPreload, PRELOAD_FALLBACK_DELAY_MS);
    });

    document.addEventListener('tab:changed', event => {
        if (event?.detail?.tab === 'mds') {
            void loadMdsData();
        }
    });
}
