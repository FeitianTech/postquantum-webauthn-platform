export function clearRowHighlight(state) {
    if (!state) {
        return;
    }
    if (state.tableBody) {
        state.tableBody.querySelectorAll('tr.mds-row--highlight').forEach(row => {
            row.classList.remove('mds-row--highlight');
        });
    }
    state.highlightedRow = null;
    state.highlightedRowKey = '';
}

export function findRowByKey(state, key) {
    if (!state?.tableBody || !key) {
        return null;
    }
    const normalised = key.toLowerCase();
    const rows = state.tableBody.querySelectorAll('tr[data-aaguid]');
    for (const row of rows) {
        if ((row.dataset.aaguid || '').toLowerCase() === normalised) {
            return row;
        }
    }
    return null;
}

export function applyRowHighlightByKey(state, key, setHighlightedRow, options = {}) {
    if (!state || !key || typeof setHighlightedRow !== 'function') {
        return false;
    }

    const row = findRowByKey(state, key);
    if (!row) {
        return false;
    }

    const applied = setHighlightedRow(row, key, options);
    return applied ? row : false;
}

export function isElementVisible(element) {
    if (!(element instanceof HTMLElement)) {
        return false;
    }
    if (element.offsetParent !== null) {
        return true;
    }
    const style = window.getComputedStyle ? window.getComputedStyle(element) : null;
    if (!style) {
        return false;
    }
    return style.display !== 'none' && style.visibility !== 'hidden' && style.opacity !== '0';
}

export function waitForElementVisible(element, { timeout = 2000, interval = 32 } = {}) {
    if (isElementVisible(element)) {
        return Promise.resolve(true);
    }

    return new Promise(resolve => {
        const start = Date.now();
        const check = () => {
            if (isElementVisible(element)) {
                resolve(true);
                return;
            }
            if (Date.now() - start >= timeout) {
                resolve(false);
                return;
            }
            if (typeof requestAnimationFrame === 'function') {
                requestAnimationFrame(check);
            } else {
                setTimeout(check, interval);
            }
        };
        check();
    });
}

export function showAuthenticatorDetail({
    state,
    entry,
    options = {},
    mdsData,
    normaliseAaguid,
    clearRowHighlight,
    findRowByKey,
    scrollRowIntoView,
    openAuthenticatorModal,
}) {
    if (!state || !entry) {
        return;
    }

    clearRowHighlight(state);

    const key = normaliseAaguid(entry.aaguid || entry.id);
    let sourceEntry = entry;
    if (key && state.byAaguid?.has(key)) {
        sourceEntry = state.byAaguid.get(key);
    } else if (typeof entry.index === 'number' && mdsData[entry.index]) {
        sourceEntry = mdsData[entry.index];
    }

    state.activeDetailEntry = sourceEntry;

    const { scrollIntoView = false } = options || {};
    if (scrollIntoView && key) {
        const row = findRowByKey(state, key);
        if (row) {
            const scroll = () => scrollRowIntoView(row, { behavior: 'smooth' });
            if (typeof requestAnimationFrame === 'function') {
                requestAnimationFrame(scroll);
            } else {
                scroll();
            }
        }
    }

    void openAuthenticatorModal(sourceEntry);
}

export function hideAuthenticatorDetail({ state, closeAuthenticatorModal }) {
    if (!state) {
        return;
    }

    closeAuthenticatorModal();
}
