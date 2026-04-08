import { createCustomPanelScrollGuard } from './custom-panel-scroll-guard.js';

export function createAbortError() {
    try {
        return new DOMException('Operation aborted', 'AbortError');
    } catch (error) {
        const abortError = new Error('Operation aborted');
        abortError.name = 'AbortError';
        return abortError;
    }
}

export function isAbortSignal(value) {
    return Boolean(value && typeof value === 'object' && 'aborted' in value);
}

export function getAbortSignal(options) {
    if (!options || typeof options !== 'object') {
        return null;
    }
    if (isAbortSignal(options)) {
        return options;
    }
    const signal = options.signal;
    if (isAbortSignal(signal)) {
        return signal;
    }
    return null;
}

export function throwIfAborted(signal) {
    if (signal && signal.aborted) {
        throw createAbortError();
    }
}

export function setButtonBusy(button, busy) {
    if (!(button instanceof HTMLButtonElement)) {
        return;
    }
    if (busy) {
        button.disabled = true;
        button.setAttribute('aria-disabled', 'true');
        button.classList.add('is-busy');
    } else {
        button.disabled = false;
        button.removeAttribute('aria-disabled');
        button.classList.remove('is-busy');
    }
}

export function setCustomMetadataMessage(state, message, variant = 'info') {
    const container = state?.customPanelMessages;
    if (!container) {
        return;
    }

    const variants = ['info', 'success', 'error', 'warning'];
    container.classList.remove(
        ...variants.map(name => `mds-custom-panel__messages--${name}`),
    );

    const safeVariant = variants.includes(variant) ? variant : 'info';
    container.classList.add(`mds-custom-panel__messages--${safeVariant}`);

    if (typeof message === 'string' && message.trim()) {
        container.textContent = message.trim();
        container.hidden = false;
        container.removeAttribute('hidden');
    } else {
        container.textContent = '';
        container.hidden = true;
        container.setAttribute('hidden', '');
    }
}

export function updateCustomMetadataList(state, items) {
    const list = state?.customList;
    if (!list) {
        return;
    }

    list.innerHTML = '';

    const entries = Array.isArray(items) ? items : [];
    if (!entries.length) {
        const emptyItem = document.createElement('li');
        emptyItem.className = 'mds-custom-panel__list-item mds-custom-panel__list-item--empty';
        emptyItem.textContent = 'No custom metadata has been added yet.';
        list.appendChild(emptyItem);
        return;
    }

    entries.forEach(item => {
        const listItem = document.createElement('li');
        listItem.className = 'mds-custom-panel__list-item';

        const name =
            (item?.source?.originalFilename && String(item.source.originalFilename).trim()) ||
            (item?.source?.storedFilename && String(item.source.storedFilename).trim()) ||
            'metadata.json';

        const storedFilename =
            (item?.source?.storedFilename && String(item.source.storedFilename).trim()) || '';

        if (storedFilename) {
            listItem.dataset.filename = storedFilename;
        }

        const headerEl = document.createElement('div');
        headerEl.className = 'mds-custom-panel__item-header';

        const nameEl = document.createElement('span');
        nameEl.className = 'mds-custom-panel__item-name';
        nameEl.textContent = name;
        headerEl.appendChild(nameEl);

        if (storedFilename) {
            const actionsEl = document.createElement('div');
            actionsEl.className = 'mds-custom-panel__item-actions';

            const deleteButton = document.createElement('button');
            deleteButton.type = 'button';
            deleteButton.className = 'mds-custom-panel__delete-button';
            deleteButton.textContent = 'Delete';
            deleteButton.setAttribute('aria-label', `Delete ${name}`);
            deleteButton.title = `Delete ${name}`;
            deleteButton.addEventListener('click', event => {
                event.preventDefault();
                event.stopPropagation();
                if (deleteButton.disabled) {
                    return;
                }
                setButtonBusy(deleteButton, true);
                if (typeof state?.onDeleteMetadata === 'function') {
                    void state.onDeleteMetadata(storedFilename, {
                        trigger: deleteButton,
                        itemName: name,
                    });
                }
            });

            actionsEl.appendChild(deleteButton);
            headerEl.appendChild(actionsEl);
        }

        listItem.appendChild(headerEl);

        const details = [];
        const uploadedAtRaw = item?.source?.uploadedAt;
        if (typeof uploadedAtRaw === 'string' && uploadedAtRaw) {
            const parsed = new Date(uploadedAtRaw);
            if (!Number.isNaN(parsed.getTime())) {
                details.push(`Uploaded ${parsed.toLocaleString()}`);
            }
        }
        if (item?.legalHeader) {
            details.push('Includes legal header');
        }

        if (details.length) {
            const detailEl = document.createElement('span');
            detailEl.className = 'mds-custom-panel__item-details';
            detailEl.textContent = details.join(' · ');
            listItem.appendChild(detailEl);
        }

        list.appendChild(listItem);
    });
}

export function handleCustomPanelKeydown(event) {
    if (event.key === 'Escape') {
        event.stopPropagation();
        event.preventDefault();
    }
}

export function openCustomMetadataPanel(state) {
    if (!state?.customPanel) {
        return;
    }

    if (!state.customPanelIsOpen) {
        const panel = state.customPanel;
        panel.hidden = false;
        panel.removeAttribute('hidden');
        panel.classList.remove('is-closing');
        void panel.offsetWidth;
        panel.classList.add('is-open');
        if (typeof state.customPanelScrollCleanup === 'function') {
            state.customPanelScrollCleanup();
        }
        state.customPanelScrollCleanup = createCustomPanelScrollGuard(panel);
        state.customPanelIsOpen = true;
        state.customPanelReturnFocus =
            document.activeElement instanceof HTMLElement ? document.activeElement : null;
        if (state.addMetadataButton) {
            state.addMetadataButton.setAttribute('aria-expanded', 'true');
        }
        if (state.customDropzone instanceof HTMLElement) {
            state.customDropzone.focus();
        }
    }
}

export function closeCustomMetadataPanel(state) {
    if (!state?.customPanel) {
        return;
    }

    const panel = state.customPanel;
    const finalizeClose = () => {
        panel.classList.remove('is-open');
        panel.classList.remove('is-closing');
        panel.hidden = true;
        panel.setAttribute('hidden', '');
        if (typeof state.customPanelScrollCleanup === 'function') {
            state.customPanelScrollCleanup();
            state.customPanelScrollCleanup = null;
        }

        if (state.customDropzone instanceof HTMLElement) {
            state.customDropzone.classList.remove('is-active');
        }

        if (state.customPanelReturnFocus instanceof HTMLElement) {
            try {
                state.customPanelReturnFocus.focus();
            } catch (error) {
                /* ignore focus errors */
            }
        }
        state.customPanelReturnFocus = null;
    };

    if (state.addMetadataButton) {
        state.addMetadataButton.setAttribute('aria-expanded', 'false');
    }

    if (!panel.classList.contains('is-open')) {
        state.customPanelIsOpen = false;
        finalizeClose();
        return;
    }

    state.customPanelIsOpen = false;
    panel.classList.add('is-closing');
    panel.classList.remove('is-open');

    const dialog = panel.querySelector('.mds-custom-panel__dialog');
    if (!(dialog instanceof HTMLElement)) {
        finalizeClose();
        return;
    }

    let hasClosed = false;
    const completeClose = () => {
        if (hasClosed) {
            return;
        }
        hasClosed = true;
        finalizeClose();
    };

    const handleTransitionEnd = event => {
        if (event.target !== dialog) {
            return;
        }
        dialog.removeEventListener('transitionend', handleTransitionEnd);
        completeClose();
    };

    dialog.addEventListener('transitionend', handleTransitionEnd);
    setTimeout(completeClose, 400);
}
