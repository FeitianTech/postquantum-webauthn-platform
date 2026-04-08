export function updateCount(state, filtered, total) {
    if (state?.countEl) {
        state.countEl.textContent = filtered.toLocaleString();
    }
    if (state?.totalEl) {
        state.totalEl.textContent = total ? `of ${total.toLocaleString()} total` : '';
    }
}

export function setStatus(state, message, variant, options = {}) {
    if (!state?.statusEl) {
        return;
    }

    const statusEl = state.statusEl;
    const { restoreDefault = false, delay = 5000 } = options;

    if (state.statusResetTimer) {
        window.clearTimeout(state.statusResetTimer);
        state.statusResetTimer = null;
    }

    statusEl.classList.remove('mds-status-info', 'mds-status-success', 'mds-status-error');
    statusEl.classList.add(`mds-status-${variant}`);
    statusEl.innerHTML = message;

    if (restoreDefault && state.defaultStatus) {
        const timeout = Number.isFinite(delay) ? Math.max(0, delay) : 5000;
        state.statusResetTimer = window.setTimeout(() => {
            if (!state?.statusEl || !state?.defaultStatus) {
                return;
            }
            const target = state.statusEl;
            const defaults = state.defaultStatus;
            target.classList.remove('mds-status-info', 'mds-status-success', 'mds-status-error');
            target.classList.add(`mds-status-${defaults.variant}`);
            target.innerHTML = defaults.html;
            if (defaults.title) {
                target.setAttribute('title', defaults.title);
            } else {
                target.removeAttribute('title');
            }
            state.statusResetTimer = null;
        }, timeout);
    }
}

export function setUpdateButtonBusy(state, isBusy, buttonStates) {
    const button = state?.updateButton;
    if (!button) {
        return;
    }

    if (isBusy) {
        button.disabled = true;
        button.classList.add('is-busy');
        button.setAttribute('aria-busy', 'true');
        const mode = state?.updateButtonMode || 'update';
        const config = buttonStates[mode] || buttonStates.update;
        button.textContent = config.busyLabel;
        return;
    }

    button.disabled = false;
    button.classList.remove('is-busy');
    button.removeAttribute('aria-busy');
    const mode = state?.updateButtonMode || 'update';
    const config = buttonStates[mode] || buttonStates.update;
    button.textContent = config.label;
    button.blur();
}

export function setUpdateButtonMode(state, mode, buttonStates) {
    const button = state?.updateButton;
    if (!button) {
        return;
    }

    const action = mode === 'download' ? 'download' : 'update';
    const config = buttonStates[action] || buttonStates.update;

    state.updateButtonMode = action;

    button.dataset.action = action;
    button.dataset.idleLabel = config.label;
    button.dataset.busyLabel = config.busyLabel;

    if (!button.classList.contains('is-busy')) {
        button.textContent = config.label;
    }
}

export function updateOptionLists(state, optionSets, filterLookup, formatEnum) {
    if (!state) {
        return;
    }

    Object.entries(optionSets).forEach(([key, values]) => {
        const dropdown = state.dropdowns[key];
        if (!dropdown) {
            return;
        }
        const config = filterLookup[key];
        const optionList = Array.from(values).filter(Boolean);
        if (config?.staticOptions) {
            const staticValues = config.staticOptions
                .map(option => formatEnum(option))
                .filter(Boolean);
            optionList.push(...staticValues);
        }
        const unique = Array.from(new Set(optionList));
        dropdown.setOptions(unique);
    });
}
