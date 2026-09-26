import {
    CANNOT_DELETE_METADATA,
    CHOOSE_METADATA_FILES,
    CUSTOM_METADATA_UPDATED_NOTE,
    DELETE_METADATA_FAILED,
    DELETE_PROGRESS,
    METADATA_UPDATE_CANCELLED,
    UPLOADING_METADATA,
    UPLOAD_METADATA_FAILED,
    UPLOAD_PROGRESS,
    customMetadataItemLabel,
    describeDeleteAnswer,
    describeUploadAnswer,
    removedCustomMetadataMessage,
    removingCustomMetadataMessage,
    requestCustomMetadataDelete,
    requestCustomMetadataUpload,
} from '../explorer/custom-metadata.js';

export async function uploadCustomMetadataFilesInState(state, files, deps = {}) {
    const {
        runWithMetadataUpdateOverlay,
        setCustomMetadataMessage,
        applyExplorerSnapshot,
        loadMdsData,
        resetCustomMetadataCache,
        customMetadataUploadPath,
    } = deps;

    if (!files.length) {
        setCustomMetadataMessage(CHOOSE_METADATA_FILES, 'warning');
        return;
    }

    setCustomMetadataMessage(UPLOADING_METADATA, 'info');

    try {
        await runWithMetadataUpdateOverlay(async context => {
            context.updateStatus(UPLOAD_PROGRESS.uploading);
            const { response, payload } = await requestCustomMetadataUpload(files, {
                signal: context.signal,
                path: customMetadataUploadPath,
            });

            context.throwIfAborted();

            const answer = describeUploadAnswer(response, payload);
            if (!answer.ok) {
                setCustomMetadataMessage(answer.message, answer.variant);
                throw new Error(answer.message);
            }

            resetCustomMetadataCache();
            setCustomMetadataMessage(answer.message, answer.variant);

            if (answer.snapshot) {
                context.updateStatus(UPLOAD_PROGRESS.applying);
                applyExplorerSnapshot(answer.snapshot, CUSTOM_METADATA_UPDATED_NOTE);
            } else {
                context.updateStatus(UPLOAD_PROGRESS.reloading);
                await loadMdsData(CUSTOM_METADATA_UPDATED_NOTE, { forceReload: true, signal: context.signal });
            }
            context.throwIfAborted();
        }, {
            startMessage: UPLOAD_PROGRESS.start,
            successMessage: UPLOAD_PROGRESS.success,
            cancelMessage: UPLOAD_PROGRESS.cancel,
            failureMessage: UPLOAD_PROGRESS.failure,
            cancelable: false,
        });
    } catch (error) {
        if (error && error.name === 'AbortError') {
            setCustomMetadataMessage(METADATA_UPDATE_CANCELLED, 'warning');
            return;
        }
        console.error('Failed to upload custom metadata files.', error);
        setCustomMetadataMessage(UPLOAD_METADATA_FAILED, 'error');
    }
}

export async function deleteCustomMetadataInState(state, storedFilename, options = {}, deps = {}) {
    const {
        runWithMetadataUpdateOverlay,
        setCustomMetadataMessage,
        setButtonBusy,
        applyExplorerSnapshot,
        loadMdsData,
        resetCustomMetadataCache,
        customMetadataDeletePath,
    } = deps;

    const opts = options && typeof options === 'object' ? options : {};
    const triggerButton = opts.trigger instanceof HTMLButtonElement ? opts.trigger : null;
    const itemName = customMetadataItemLabel(opts.itemName);

    if (!storedFilename) {
        setCustomMetadataMessage(CANNOT_DELETE_METADATA, 'error');
        if (triggerButton) {
            setButtonBusy(triggerButton, false);
        }
        return;
    }

    if (triggerButton) {
        setButtonBusy(triggerButton, true);
    }

    setCustomMetadataMessage(removingCustomMetadataMessage(itemName), 'info');

    try {
        await runWithMetadataUpdateOverlay(async context => {
            context.updateStatus(DELETE_PROGRESS.removing);
            const { response, payload } = await requestCustomMetadataDelete(storedFilename, {
                signal: context.signal,
                path: customMetadataDeletePath,
            });

            context.throwIfAborted();

            const answer = describeDeleteAnswer(response, payload);
            if (!answer.ok) {
                setCustomMetadataMessage(answer.message, answer.variant);
                if (answer.variant === 'error') {
                    throw new Error(answer.message);
                }
                context.updateStatus(DELETE_PROGRESS.unchanged);
                return;
            }

            resetCustomMetadataCache();

            if (answer.snapshot) {
                context.updateStatus(DELETE_PROGRESS.applying);
                applyExplorerSnapshot(answer.snapshot, CUSTOM_METADATA_UPDATED_NOTE);
            } else {
                context.updateStatus(DELETE_PROGRESS.refreshing);
                await loadMdsData(CUSTOM_METADATA_UPDATED_NOTE, { forceReload: true, signal: context.signal });
            }
            context.throwIfAborted();
            setCustomMetadataMessage(removedCustomMetadataMessage(itemName), 'success');
        }, {
            startMessage: DELETE_PROGRESS.start,
            successMessage: DELETE_PROGRESS.success,
            cancelMessage: DELETE_PROGRESS.cancel,
            failureMessage: DELETE_PROGRESS.failure,
            cancelable: false,
        });
    } catch (error) {
        if (error && error.name === 'AbortError') {
            setCustomMetadataMessage(METADATA_UPDATE_CANCELLED, 'warning');
        } else {
            console.error('Failed to delete custom metadata file.', error);
            setCustomMetadataMessage(DELETE_METADATA_FAILED, 'error');
        }
    } finally {
        if (triggerButton) {
            setButtonBusy(triggerButton, false);
        }
    }
}
