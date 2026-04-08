export function createCustomMetadataAdapters(config = {}) {
    const {
        getState,
        setCustomMetadataMessageInState,
        updateCustomMetadataListInState,
        handleCustomPanelKeydownValue,
        openCustomMetadataPanelInState,
        closeCustomMetadataPanelInState,
        normaliseFileListValue,
        splitAcceptedFilesValue,
        uploadCustomMetadataFilesInState,
        deleteCustomMetadataInState,
        runWithMetadataUpdateOverlay,
        applyExplorerSnapshot,
        loadMdsData,
        setButtonBusy,
        customMetadataUploadPath,
        customMetadataDeletePath,
        resetCustomMetadataCache,
    } = config;

    function setCustomMetadataMessage(message, variant = 'info', targetState = getState()) {
        return setCustomMetadataMessageInState(targetState, message, variant);
    }

    function updateCustomMetadataList(items, targetState = getState()) {
        return updateCustomMetadataListInState(targetState, items);
    }

    function handleCustomPanelKeydown(event) {
        return handleCustomPanelKeydownValue(event);
    }

    function openCustomMetadataPanel() {
        return openCustomMetadataPanelInState(getState());
    }

    function closeCustomMetadataPanel() {
        return closeCustomMetadataPanelInState(getState());
    }

    function handleCustomDropzoneDragEnter(event) {
        const state = getState();
        if (!state?.customDropzone) {
            return;
        }
        event.preventDefault();
        event.stopPropagation();
        if (event.dataTransfer) {
            event.dataTransfer.dropEffect = 'copy';
        }
        state.customDropzone.classList.add('is-active');
    }

    function handleCustomDropzoneDragLeave(event) {
        const state = getState();
        if (!state?.customDropzone) {
            return;
        }
        event.preventDefault();
        event.stopPropagation();
        if (event.target === state.customDropzone || event.currentTarget === state.customDropzone) {
            state.customDropzone.classList.remove('is-active');
        }
    }

    function normaliseFileList(list) {
        return normaliseFileListValue(list);
    }

    function splitAcceptedFiles(files) {
        return splitAcceptedFilesValue(files);
    }

    async function uploadCustomMetadataFiles(files) {
        return uploadCustomMetadataFilesInState(getState(), files, {
            runWithMetadataUpdateOverlay,
            setCustomMetadataMessage,
            applyExplorerSnapshot,
            loadMdsData,
            resetCustomMetadataCache,
            customMetadataUploadPath,
        });
    }

    async function deleteCustomMetadata(storedFilename, options = {}) {
        return deleteCustomMetadataInState(getState(), storedFilename, options, {
            runWithMetadataUpdateOverlay,
            setCustomMetadataMessage,
            setButtonBusy,
            applyExplorerSnapshot,
            loadMdsData,
            resetCustomMetadataCache,
            customMetadataDeletePath,
        });
    }

    async function handleCustomFileSelection(files) {
        const { accepted, rejected } = splitAcceptedFiles(files);

        if (rejected.length) {
            setCustomMetadataMessage(
                `Ignored non-JSON files: ${rejected.join(', ')}`,
                'warning',
            );
        }

        if (!accepted.length) {
            if (!rejected.length) {
                setCustomMetadataMessage('Please select one or more JSON files.', 'warning');
            }
            return;
        }

        await uploadCustomMetadataFiles(accepted);
    }

    function handleCustomDrop(event) {
        const state = getState();
        if (!state?.customDropzone) {
            return;
        }
        event.preventDefault();
        event.stopPropagation();
        state.customDropzone.classList.remove('is-active');
        const files = normaliseFileList(event.dataTransfer?.files);
        void handleCustomFileSelection(files);
    }

    function handleCustomFileInputChange(event) {
        const state = getState();
        const files = normaliseFileList(event.target?.files);
        if (state?.customFileInput) {
            state.customFileInput.value = '';
        }
        void handleCustomFileSelection(files);
    }

    return {
        setCustomMetadataMessage,
        updateCustomMetadataList,
        handleCustomPanelKeydown,
        openCustomMetadataPanel,
        closeCustomMetadataPanel,
        handleCustomDropzoneDragEnter,
        handleCustomDropzoneDragLeave,
        normaliseFileList,
        splitAcceptedFiles,
        handleCustomFileSelection,
        handleCustomDrop,
        handleCustomFileInputChange,
        uploadCustomMetadataFiles,
        deleteCustomMetadata,
    };
}
