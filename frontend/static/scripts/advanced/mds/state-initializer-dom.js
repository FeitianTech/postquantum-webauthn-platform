export function createUpdateOverlay(root) {
    const overlay = document.createElement('div');
    overlay.id = 'mds-update-overlay';
    overlay.className = 'mds-update-overlay';
    overlay.setAttribute('role', 'alertdialog');
    overlay.setAttribute('aria-modal', 'true');
    overlay.setAttribute('aria-hidden', 'true');
    overlay.hidden = true;

    const overlayDialog = document.createElement('div');
    overlayDialog.className = 'mds-update-overlay__dialog';
    overlayDialog.setAttribute('tabindex', '-1');
    overlay.appendChild(overlayDialog);

    const overlayToast = document.createElement('div');
    overlayToast.className = 'mds-update-overlay__toast';
    overlayDialog.appendChild(overlayToast);

    const overlaySpinner = document.createElement('div');
    overlaySpinner.className = 'mds-update-overlay__spinner';
    overlaySpinner.setAttribute('aria-hidden', 'true');
    overlayToast.appendChild(overlaySpinner);

    const overlayMessage = document.createElement('span');
    overlayMessage.className = 'mds-update-overlay__message';
    overlayMessage.id = 'mds-update-overlay-message';
    overlayMessage.textContent = 'MDS is updating…';
    overlayToast.appendChild(overlayMessage);
    overlay.setAttribute('aria-labelledby', overlayMessage.id);

    const overlayActions = document.createElement('div');
    overlayActions.className = 'mds-update-overlay__actions';
    overlayActions.hidden = true;
    overlayDialog.appendChild(overlayActions);

    const overlayCancel = document.createElement('button');
    overlayCancel.type = 'button';
    overlayCancel.className = 'mds-update-overlay__cancel';
    overlayCancel.textContent = 'Cancel update';
    overlayCancel.hidden = true;
    overlayCancel.disabled = true;
    overlayCancel.setAttribute('aria-hidden', 'true');
    overlayCancel.setAttribute('aria-disabled', 'true');
    overlayActions.appendChild(overlayCancel);

    root.appendChild(overlay);

    return {
        overlay,
        overlayMessage,
        overlayCancel,
        overlayActions,
    };
}

export function bindCustomMetadataPanelControls(elements, handlers) {
    const {
        customPanel,
        customPanelClose,
        addMetadataButton,
        customDropzone,
        customFileInput,
    } = elements;

    const {
        handleCustomPanelKeydown,
        closeCustomMetadataPanel,
        openCustomMetadataPanel,
        handleCustomDropzoneDragEnter,
        handleCustomDropzoneDragLeave,
        handleCustomDrop,
        handleCustomFileInputChange,
    } = handlers;

    if (customPanel) {
        customPanel.addEventListener('keydown', handleCustomPanelKeydown);
    }

    if (customPanelClose instanceof HTMLElement) {
        customPanelClose.addEventListener('click', event => {
            event.preventDefault();
            closeCustomMetadataPanel();
        });
    }

    if (addMetadataButton instanceof HTMLButtonElement) {
        addMetadataButton.type = 'button';
        addMetadataButton.setAttribute('aria-haspopup', 'dialog');
        addMetadataButton.setAttribute('aria-expanded', 'false');
        addMetadataButton.addEventListener('click', event => {
            event.preventDefault();
            openCustomMetadataPanel();
        });
        addMetadataButton.addEventListener('keydown', event => {
            if (event.key === 'Enter' || event.key === ' ') {
                event.preventDefault();
                openCustomMetadataPanel();
            }
        });
    }

    if (customDropzone instanceof HTMLElement) {
        const activateFileInput = () => {
            if (customFileInput instanceof HTMLInputElement) {
                customFileInput.click();
            }
        };

        customDropzone.addEventListener('click', event => {
            event.preventDefault();
            activateFileInput();
        });
        customDropzone.addEventListener('keydown', event => {
            if (event.key === 'Enter' || event.key === ' ') {
                event.preventDefault();
                activateFileInput();
            }
        });
        customDropzone.addEventListener('dragenter', handleCustomDropzoneDragEnter);
        customDropzone.addEventListener('dragover', handleCustomDropzoneDragEnter);
        customDropzone.addEventListener('dragleave', handleCustomDropzoneDragLeave);
        customDropzone.addEventListener('drop', handleCustomDrop);
    }

    if (customFileInput instanceof HTMLInputElement) {
        customFileInput.addEventListener('change', handleCustomFileInputChange);
    }
}

export function setupTableElementsAndScrollSync(root, handlers) {
    const { scheduleScrollTopButtonUpdate, syncHorizontalScrollPositions } = handlers;

    const tableContainer = root.querySelector('#mds-table-container');
    const table = root.querySelector('.mds-table');
    const tableBody = root.querySelector('#mds-table-body');
    const horizontalScrollContainer = root.querySelector('#mds-horizontal-scroll');
    const horizontalScrollContent = horizontalScrollContainer
        ? horizontalScrollContainer.querySelector('.mds-horizontal-scroll__content')
        : null;

    if (horizontalScrollContainer) {
        horizontalScrollContainer.hidden = true;
        horizontalScrollContainer.setAttribute('hidden', '');
    }

    if (tableContainer) {
        const handleScroll = () => {
            scheduleScrollTopButtonUpdate();
            if (horizontalScrollContainer) {
                syncHorizontalScrollPositions(tableContainer, horizontalScrollContainer);
            }
        };
        tableContainer.addEventListener('scroll', handleScroll, { passive: true });
    }

    if (horizontalScrollContainer) {
        horizontalScrollContainer.addEventListener(
            'scroll',
            () => {
                if (tableContainer) {
                    syncHorizontalScrollPositions(horizontalScrollContainer, tableContainer);
                }
            },
            { passive: true },
        );
    }

    return {
        tableContainer,
        table,
        tableBody,
        horizontalScrollContainer,
        horizontalScrollContent,
    };
}

export function setupSortButtons(root, handleSortButtonClick, sortNone) {
    const sortButtons = new Map();
    root.querySelectorAll('.mds-sort-button[data-sort-key]').forEach(button => {
        const sortKey = button.dataset.sortKey;
        if (!sortKey) {
            return;
        }
        sortButtons.set(sortKey, button);
        button.addEventListener('click', () => handleSortButtonClick(sortKey));
        if (!button.hasAttribute('data-sort-direction')) {
            button.setAttribute('data-sort-direction', sortNone);
        }
    });

    return sortButtons;
}

export function setupActionButtons(root, handlers) {
    const { scrollMdsSectionToTop, refreshMetadata } = handlers;

    const scrollTopButton = root.querySelector('#mds-scroll-top-button');
    if (scrollTopButton) {
        scrollTopButton.addEventListener('click', event => {
            event.preventDefault();
            scrollMdsSectionToTop();
        });
        scrollTopButton.hidden = true;
        scrollTopButton.setAttribute('aria-hidden', 'true');
    }

    const retryButton = root.querySelector('#mds-retry-button');
    if (retryButton instanceof HTMLButtonElement) {
        retryButton.addEventListener('click', event => {
            event.preventDefault();
            void refreshMetadata();
        });
        retryButton.hidden = true;
        retryButton.setAttribute('aria-hidden', 'true');
    }

    const updateButton = root.querySelector('#mds-update-button');
    if (updateButton) {
        updateButton.addEventListener('click', () => {
            void refreshMetadata();
        });
    }

    return {
        scrollTopButton,
        retryButton,
        updateButton,
    };
}

export function setupDetailElements(root, handlers) {
    const { closeCertificatePage, closeAuthenticatorModal, openAuthenticatorRawWindow } = handlers;

    const listSection = root.querySelector('#mds-list-section');
    const certificatePage = root.querySelector('#mds-certificate-page');
    const certificateClose = root.querySelector('#mds-certificate-page-close');
    const certificateBody = root.querySelector('#mds-certificate-page-body');
    const certificateSummary = root.querySelector('#mds-certificate-summary');
    const certificateHeader = certificatePage?.querySelector('.mds-detail-page__header') || null;
    if (certificateClose) {
        certificateClose.addEventListener('click', () => closeCertificatePage());
    }

    const authenticatorModal = root.querySelector('#mds-authenticator-modal');
    const authenticatorClose = root.querySelector('#mds-authenticator-modal-close');
    const authenticatorHeader = authenticatorModal?.querySelector('.mds-detail-page__header') || null;
    if (authenticatorClose) {
        authenticatorClose.addEventListener('click', () => closeAuthenticatorModal());
    }

    const authenticatorRawButton = root.querySelector('#mds-authenticator-modal-raw');
    if (authenticatorRawButton instanceof HTMLButtonElement) {
        authenticatorRawButton.addEventListener('click', event => {
            event.preventDefault();
            openAuthenticatorRawWindow();
        });
        authenticatorRawButton.disabled = true;
        authenticatorRawButton.setAttribute('aria-disabled', 'true');
        authenticatorRawButton.setAttribute('tabindex', '-1');
        authenticatorRawButton.setAttribute('title', 'Raw authenticator data unavailable');
    }

    return {
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
    };
}
