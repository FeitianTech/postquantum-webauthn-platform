export function showMetadataUpdateOverlayInState(state, message, options = {}) {
    const overlay = state?.updateOverlay;
    const messageEl = state?.updateOverlayMessage;
    const cancelButton = state?.updateOverlayCancel;
    const actionsEl = state?.updateOverlayActions;
    const allowCancel = options && Object.prototype.hasOwnProperty.call(options, 'cancelable')
        ? Boolean(options.cancelable)
        : true;
    const onCancel = allowCancel && typeof options.onCancel === 'function' ? options.onCancel : null;

    if (!overlay || !messageEl) {
        return {
            updateMessage() {},
            setCancelable() {},
            close() {},
        };
    }

    if (cancelButton && state.updateOverlayCancelHandler) {
        cancelButton.removeEventListener('click', state.updateOverlayCancelHandler);
    }

    let handleCancel = null;
    if (allowCancel && cancelButton instanceof HTMLButtonElement) {
        handleCancel = event => {
            event.preventDefault();
            if (cancelButton.disabled) {
                return;
            }
            cancelButton.blur();
            if (onCancel) {
                onCancel();
            }
        };

        cancelButton.addEventListener('click', handleCancel);
        state.updateOverlayCancelHandler = handleCancel;
    } else {
        state.updateOverlayCancelHandler = null;
    }

    overlay.hidden = false;
    overlay.removeAttribute('hidden');
    overlay.classList.add('is-visible');
    overlay.setAttribute('aria-hidden', 'false');
    overlay.setAttribute('aria-busy', 'true');

    const initialMessage = typeof message === 'string' && message.trim()
        ? message.trim()
        : 'MDS is updating…';
    messageEl.textContent = initialMessage;

    if (cancelButton instanceof HTMLButtonElement) {
        cancelButton.hidden = !allowCancel;
        cancelButton.setAttribute('aria-hidden', allowCancel ? 'false' : 'true');
        cancelButton.disabled = !allowCancel;
        if (allowCancel) {
            cancelButton.removeAttribute('aria-disabled');
        } else {
            cancelButton.setAttribute('aria-disabled', 'true');
        }
    }

    if (actionsEl instanceof HTMLElement) {
        actionsEl.hidden = !allowCancel;
    }

    state.updateOverlayAllowCancel = allowCancel;

    return {
        updateMessage(text) {
            if (messageEl) {
                messageEl.textContent = typeof text === 'string' && text.trim() ? text.trim() : '';
            }
        },
        setCancelable(isCancelable) {
            if (!allowCancel || !(cancelButton instanceof HTMLButtonElement)) {
                return;
            }
            const enable = Boolean(isCancelable);
            cancelButton.disabled = !enable;
            if (enable) {
                cancelButton.removeAttribute('aria-disabled');
            } else {
                cancelButton.setAttribute('aria-disabled', 'true');
            }
        },
        close({ delay = 0 } = {}) {
            const hide = () => {
                overlay.classList.remove('is-visible');
                overlay.hidden = true;
                overlay.setAttribute('aria-hidden', 'true');
                overlay.removeAttribute('aria-busy');
                if (cancelButton instanceof HTMLButtonElement) {
                    if (handleCancel && state.updateOverlayCancelHandler === handleCancel) {
                        cancelButton.removeEventListener('click', handleCancel);
                        state.updateOverlayCancelHandler = null;
                    }
                    cancelButton.hidden = true;
                    cancelButton.setAttribute('aria-hidden', 'true');
                    cancelButton.disabled = true;
                    cancelButton.setAttribute('aria-disabled', 'true');
                } else {
                    state.updateOverlayCancelHandler = null;
                }
                if (actionsEl instanceof HTMLElement) {
                    actionsEl.hidden = true;
                }
                state.updateOverlayAllowCancel = false;
            };

            if (delay > 0) {
                setTimeout(hide, delay);
            } else {
                hide();
            }
        },
    };
}

export async function runWithMetadataUpdateOverlayInState(state, task, options = {}, deps = {}) {
    const { throwIfAborted, showMetadataUpdateOverlay } = deps;

    const startMessage = typeof options.startMessage === 'string' && options.startMessage.trim()
        ? options.startMessage.trim()
        : 'MDS is updating…';
    const successMessage = typeof options.successMessage === 'string' && options.successMessage.trim()
        ? options.successMessage.trim()
        : '';
    const cancelMessage = typeof options.cancelMessage === 'string' && options.cancelMessage.trim()
        ? options.cancelMessage.trim()
        : 'Metadata update cancelled.';
    const failureMessage = typeof options.failureMessage === 'string' && options.failureMessage.trim()
        ? options.failureMessage.trim()
        : '';
    const closeDelay = Number.isFinite(options.closeDelay) ? Number(options.closeDelay) : 520;
    const allowCancel = options && Object.prototype.hasOwnProperty.call(options, 'cancelable')
        ? Boolean(options.cancelable)
        : true;

    const controller = new AbortController();
    const overlayControls = showMetadataUpdateOverlay(startMessage, {
        onCancel: allowCancel ? () => controller.abort() : null,
        cancelable: allowCancel,
    });

    const context = {
        signal: controller.signal,
        updateStatus: text => overlayControls.updateMessage(text),
        setCancelable: value => overlayControls.setCancelable(value),
        throwIfAborted: () => {
            throwIfAborted(controller.signal);
        },
    };

    try {
        const result = await task(context);
        if (controller.signal.aborted) {
            overlayControls.updateMessage(cancelMessage);
            overlayControls.setCancelable(false);
            overlayControls.close({ delay: 320 });
        } else {
            if (successMessage) {
                overlayControls.updateMessage(successMessage);
            }
            overlayControls.setCancelable(false);
            overlayControls.close({ delay: closeDelay });
        }
        return result;
    } catch (error) {
        if (controller.signal.aborted) {
            overlayControls.updateMessage(cancelMessage);
            overlayControls.setCancelable(false);
            overlayControls.close({ delay: 320 });
        } else {
            if (failureMessage) {
                overlayControls.updateMessage(failureMessage);
            }
            overlayControls.setCancelable(false);
            overlayControls.close({ delay: 720 });
        }
        throw error;
    }
}
