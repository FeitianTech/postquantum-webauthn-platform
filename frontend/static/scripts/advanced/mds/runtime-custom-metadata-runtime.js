import {
    CUSTOM_METADATA_DELETE_PATH,
    CUSTOM_METADATA_UPLOAD_PATH,
} from '../mds-constants.js';
import {
    normaliseFileList as normaliseFileListValue,
    splitAcceptedFiles as splitAcceptedFilesValue,
} from './metadata-helpers.js';
import {
    closeCustomMetadataPanel as closeCustomMetadataPanelInState,
    handleCustomPanelKeydown as handleCustomPanelKeydownValue,
    openCustomMetadataPanel as openCustomMetadataPanelInState,
    setCustomMetadataMessage as setCustomMetadataMessageInState,
    updateCustomMetadataList as updateCustomMetadataListInState,
} from './custom-panel-utils.js';
import {
    deleteCustomMetadataInState,
    uploadCustomMetadataFilesInState,
} from './custom-metadata-actions.js';
import { createCustomMetadataAdapters } from './runtime-custom-metadata-adapters.js';

export function createCustomMetadataRuntime({
    getState,
    runWithMetadataUpdateOverlay,
    applyExplorerSnapshot,
    loadMdsData,
    setButtonBusy,
    resetCustomMetadataCache,
}) {
    return createCustomMetadataAdapters({
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
        customMetadataUploadPath: CUSTOM_METADATA_UPLOAD_PATH,
        customMetadataDeletePath: CUSTOM_METADATA_DELETE_PATH,
        resetCustomMetadataCache,
    });
}
