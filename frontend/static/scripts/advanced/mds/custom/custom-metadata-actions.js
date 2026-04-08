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
        setCustomMetadataMessage('Please choose one or more JSON files.', 'warning');
        return;
    }

    const formData = new FormData();
    files.forEach(file => {
        const name = typeof file.name === 'string' && file.name ? file.name : 'metadata.json';
        formData.append('files', file, name);
    });

    setCustomMetadataMessage('Uploading metadata…', 'info');

    try {
        await runWithMetadataUpdateOverlay(async context => {
            context.updateStatus('Uploading metadata…');
            const response = await fetch(customMetadataUploadPath, {
                method: 'POST',
                body: formData,
                signal: context.signal,
            });

            let payload;
            try {
                payload = await response.json();
            } catch (error) {
                payload = null;
            }

            context.throwIfAborted();

            const errors = Array.isArray(payload?.errors) ? payload.errors : [];
            if (!response.ok) {
                const message =
                    (payload && typeof payload.error === 'string' && payload.error.trim()) ||
                    errors.join(' ') ||
                    'Failed to upload metadata files.';
                setCustomMetadataMessage(message, 'error');
                throw new Error(message);
            }

            resetCustomMetadataCache();
            const successMessage =
                errors.length > 0
                    ? `Metadata uploaded with warnings: ${errors.join(' ')}`
                    : 'Metadata uploaded successfully.';
            setCustomMetadataMessage(successMessage, errors.length ? 'warning' : 'success');

            const refreshNote = 'Custom metadata updated.';
            if (payload?.snapshot && typeof payload.snapshot === 'object') {
                context.updateStatus('Applying metadata…');
                applyExplorerSnapshot(payload.snapshot, refreshNote);
            } else {
                context.updateStatus('Reloading metadata…');
                await loadMdsData(refreshNote, { forceReload: true, signal: context.signal });
            }
            context.throwIfAborted();
        }, {
            startMessage: 'Updating Metadata...',
            successMessage: 'Completing metadata update...',
            cancelMessage: 'Metadata update cancelled.',
            failureMessage: 'Metadata update failed.',
            cancelable: false,
        });
    } catch (error) {
        if (error && error.name === 'AbortError') {
            setCustomMetadataMessage('Metadata update cancelled.', 'warning');
            return;
        }
        console.error('Failed to upload custom metadata files.', error);
        setCustomMetadataMessage('Failed to upload metadata files.', 'error');
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
    const itemName =
        typeof opts.itemName === 'string' && opts.itemName.trim()
            ? opts.itemName.trim()
            : 'metadata file';

    if (!storedFilename) {
        setCustomMetadataMessage('Unable to delete the metadata file.', 'error');
        if (triggerButton) {
            setButtonBusy(triggerButton, false);
        }
        return;
    }

    if (triggerButton) {
        setButtonBusy(triggerButton, true);
    }

    setCustomMetadataMessage(`Removing ${itemName}…`, 'info');

    try {
        await runWithMetadataUpdateOverlay(async context => {
            context.updateStatus('Removing metadata…');
            const response = await fetch(
                `${customMetadataDeletePath}/${encodeURIComponent(storedFilename)}`,
                {
                    method: 'DELETE',
                    signal: context.signal,
                },
            );

            let payload;
            try {
                payload = await response.json();
            } catch (error) {
                payload = null;
            }

            context.throwIfAborted();

            if (!response.ok) {
                const errorMessage =
                    (payload && typeof payload.error === 'string' && payload.error.trim()) ||
                    (payload && typeof payload.message === 'string' && payload.message.trim()) ||
                    'Failed to delete metadata file.';
                const variant = response.status === 404 ? 'warning' : 'error';
                setCustomMetadataMessage(errorMessage, variant);
                if (variant === 'error') {
                    throw new Error(errorMessage);
                }
                context.updateStatus('No metadata changes detected.');
                return;
            }

            resetCustomMetadataCache();

            if (payload?.snapshot && typeof payload.snapshot === 'object') {
                context.updateStatus('Applying metadata…');
                applyExplorerSnapshot(payload.snapshot, 'Custom metadata updated.');
            } else {
                context.updateStatus('Refreshing metadata…');
                await loadMdsData('Custom metadata updated.', { forceReload: true, signal: context.signal });
            }
            context.throwIfAborted();
            setCustomMetadataMessage(`${itemName} removed.`, 'success');
        }, {
            startMessage: 'Removing metadata...',
            successMessage: 'Completing metadata removal...',
            cancelMessage: 'Metadata removal cancelled.',
            failureMessage: 'Metadata removal failed.',
            cancelable: false,
        });
    } catch (error) {
        if (error && error.name === 'AbortError') {
            setCustomMetadataMessage('Metadata update cancelled.', 'warning');
        } else {
            console.error('Failed to delete custom metadata file.', error);
            setCustomMetadataMessage('Failed to delete metadata file.', 'error');
        }
    } finally {
        if (triggerButton) {
            setButtonBusy(triggerButton, false);
        }
    }
}
