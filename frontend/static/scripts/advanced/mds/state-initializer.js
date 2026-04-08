import {
    bindCustomMetadataPanelControls,
    createUpdateOverlay,
    setupActionButtons,
    setupDetailElements,
    setupSortButtons,
    setupTableElementsAndScrollSync,
} from './state-initializer-dom.js';
import { registerMdsTabChangeHandler } from './state-initializer-tab-change.js';

export function initializeMdsState(root, deps) {
    const {
        FILTER_CONFIG,
        FILTER_LOOKUP,
        DEFAULT_SORT_KEY,
        DEFAULT_SORT_DIRECTION,
        SORT_NONE,
        createFilterDropdown,
        formatEnum,
        normaliseSnapshotInfo,
        initialMdsInfo,
        customMetadataItems,
        getState,
        applyFilters,
        handleCustomPanelKeydown,
        closeCustomMetadataPanel,
        openCustomMetadataPanel,
        handleCustomDropzoneDragEnter,
        handleCustomDropzoneDragLeave,
        handleCustomDrop,
        handleCustomFileInputChange,
        scheduleScrollTopButtonUpdate,
        syncHorizontalScrollPositions,
        handleSortButtonClick,
        scrollMdsSectionToTop,
        refreshMetadata,
        closeCertificatePage,
        closeAuthenticatorModal,
        openAuthenticatorRawWindow,
        clearRowHighlight,
        hideScrollTopButton,
        hideHorizontalScroll,
        scheduleHorizontalScrollMetricsUpdate,
        createDetailStickyHeader,
        updateCustomMetadataList,
        setCustomMetadataMessage,
        setupColumnResizers,
        setColumnResizersEnabled,
        deleteCustomMetadata,
    } = deps;

    const statusEl = root.querySelector('#mds-status');
    let defaultStatus = null;
    if (statusEl) {
        let variant = 'info';
        if (statusEl.classList.contains('mds-status-success')) {
            variant = 'success';
        } else if (statusEl.classList.contains('mds-status-error')) {
            variant = 'error';
        }
        defaultStatus = {
            html: statusEl.innerHTML,
            variant,
            title: statusEl.getAttribute('title') || '',
        };
    }

    const filters = {};
    const filterInputs = {};
    FILTER_CONFIG.forEach(config => {
        const input = root.querySelector(`#${config.inputId}`);
        if (input) {
            filters[config.key] = '';
            filterInputs[config.key] = input;
        }
    });

    const updateFilter = (key, rawValue) => {
        if (typeof getState === 'function' && !getState()) {
            return;
        }
        const value = rawValue.trim();
        if (filters[key] === value) {
            return;
        }
        filters[key] = value;
        applyFilters();
    };

    const dropdowns = {};
    Object.entries(filterInputs).forEach(([key, input]) => {
        input.addEventListener('keydown', event => {
            if (event.key === 'Enter') {
                updateFilter(key, event.target.value);
            }
            if (event.key === 'Escape') {
                event.target.value = '';
                updateFilter(key, '');
            }
        });

        input.addEventListener('change', event => {
            updateFilter(key, event.target.value);
        });

        input.addEventListener('input', event => {
            updateFilter(key, event.target.value);
        });

        const config = FILTER_LOOKUP[key];
        if (config?.optionsKey) {
            const dropdown = createFilterDropdown(input, value => updateFilter(key, value), config);
            dropdowns[key] = dropdown;
            if (Array.isArray(config.staticOptions)) {
                const initialOptions = config.staticOptions
                    .map(option => formatEnum(option))
                    .filter(Boolean);
                dropdown.setOptions(initialOptions);
            }
        }
    });

    const addMetadataButton = root.querySelector('#mds-add-metadata-button');
    const customPanel = root.querySelector('#mds-custom-metadata-panel');
    const customPanelClose = root.querySelector('#mds-custom-panel-close');
    const customMessages = root.querySelector('#mds-custom-messages');
    const customList = root.querySelector('#mds-custom-list');
    const customDropzone = root.querySelector('#mds-custom-dropzone');
    const customFileInput = root.querySelector('#mds-custom-file-input');
    const {
        overlay,
        overlayMessage,
        overlayCancel,
        overlayActions,
    } = createUpdateOverlay(root);

    bindCustomMetadataPanelControls(
        {
            customPanel,
            customPanelClose,
            addMetadataButton,
            customDropzone,
            customFileInput,
        },
        {
            handleCustomPanelKeydown,
            closeCustomMetadataPanel,
            openCustomMetadataPanel,
            handleCustomDropzoneDragEnter,
            handleCustomDropzoneDragLeave,
            handleCustomDrop,
            handleCustomFileInputChange,
        },
    );

    const {
        tableContainer,
        table,
        tableBody,
        horizontalScrollContainer,
        horizontalScrollContent,
    } = setupTableElementsAndScrollSync(root, {
        scheduleScrollTopButtonUpdate,
        syncHorizontalScrollPositions,
    });

    const sortButtons = setupSortButtons(root, handleSortButtonClick, SORT_NONE);

    const { scrollTopButton, retryButton, updateButton } = setupActionButtons(root, {
        scrollMdsSectionToTop,
        refreshMetadata,
    });

    const {
        listSection,
        certificatePage,
        certificateClose,
        certificateBody,
        certificateSummary,
        certificateHeader,
        authenticatorModal,
        authenticatorClose,
        authenticatorHeader,
        authenticatorRawButton,
    } = setupDetailElements(root, {
        closeCertificatePage,
        closeAuthenticatorModal,
        openAuthenticatorRawWindow,
    });

    const state = {
        root,
        listSection,
        listScrollTop: null,
        filters,
        filterInputs,
        dropdowns,
        tableContainer,
        table,
        tableBody,
        horizontalScrollContainer,
        horizontalScrollContent,
        sortButtons,
        sort: { key: DEFAULT_SORT_KEY, direction: DEFAULT_SORT_DIRECTION },
        countEl: root.querySelector('#mds-entry-count'),
        totalEl: root.querySelector('#mds-total-count'),
        statusEl,
        retryButton,
        defaultStatus,
        statusResetTimer: null,
        columnWidths: null,
        columnMinWidths: null,
        columnWidthAttempts: 0,
        columnResizers: [],
        columnResizeState: null,
        columnResizersEnabled: false,
        addMetadataButton,
        customPanel,
        customPanelClose,
        customPanelMessages: customMessages,
        customList,
        customDropzone,
        customFileInput,
        onDeleteMetadata: deleteCustomMetadata,
        customPanelIsOpen: false,
        customPanelReturnFocus: null,
        customPanelScrollCleanup: null,
        updateButton,
        updateButtonMode: 'update',
        metadataSnapshotInfo: normaliseSnapshotInfo(initialMdsInfo),
        updateOverlay: overlay,
        updateOverlayMessage: overlayMessage,
        updateOverlayCancel: overlayCancel,
        updateOverlayActions: overlayActions,
        updateOverlayCancelHandler: null,
        updateOverlayAllowCancel: false,
        certificatePage,
        certificateHeader,
        certificatePageBody: certificateBody,
        certificateInput: root.querySelector('#mds-certificate-input'),
        certificateOutput: root.querySelector('#mds-certificate-output'),
        certificateTitle: root.querySelector('#mds-certificate-page-title'),
        certificateSubtitle: root.querySelector('#mds-certificate-page-subtitle'),
        certificateSummary,
        certificateClose,
        authenticatorModal,
        authenticatorHeader,
        authenticatorModalContent: root.querySelector('#mds-authenticator-modal-content'),
        authenticatorModalTitle: root.querySelector('#mds-authenticator-modal-title'),
        authenticatorModalSubtitle: root.querySelector('#mds-authenticator-modal-subtitle'),
        authenticatorModalBody: root.querySelector('#mds-authenticator-modal-body'),
        authenticatorModalClose: authenticatorClose,
        authenticatorModalRawButton: authenticatorRawButton,
        authenticatorRawWindow: null,
        activeDetailEntry: null,
        highlightedRow: null,
        highlightedRowKey: '',
        tabChangeHandler: null,
        byAaguid: new Map(),
        scrollTopButton,
        scrollTopButtonVisible: false,
        certificateStickyHeader: null,
        authenticatorStickyHeader: null,
    };

    if (certificatePage && certificateHeader) {
        state.certificateStickyHeader = createDetailStickyHeader(certificatePage, certificateHeader, {
            defaultTitle: 'Attestation Certificate',
            type: 'certificate',
            onBack: () => closeCertificatePage(),
        });
    }

    if (authenticatorModal && authenticatorHeader) {
        state.authenticatorStickyHeader = createDetailStickyHeader(authenticatorModal, authenticatorHeader, {
            defaultTitle: 'Authenticator',
            type: 'authenticator',
            onBack: () => closeAuthenticatorModal(),
        });
    }

    state.certificateStickyHeader?.sync();
    state.authenticatorStickyHeader?.sync();

    state.tabChangeHandler = registerMdsTabChangeHandler(state, {
        clearRowHighlight,
        hideScrollTopButton,
        hideHorizontalScroll,
        scheduleScrollTopButtonUpdate,
        scheduleHorizontalScrollMetricsUpdate,
    });

    updateCustomMetadataList(customMetadataItems, state);
    setCustomMetadataMessage('', 'info', state);

    setupColumnResizers(state);
    setColumnResizersEnabled(false, state);
    scheduleHorizontalScrollMetricsUpdate();
    return state;
}
