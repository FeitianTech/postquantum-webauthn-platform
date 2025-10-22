const STATUS_TIMEOUT_MS = 10000;

function resolveStatusElement(tabIdOrElement) {
    if (typeof tabIdOrElement === 'string') {
        return document.getElementById(`${tabIdOrElement}-status`);
    }

    if (tabIdOrElement instanceof Element && tabIdOrElement.classList.contains('status')) {
        return tabIdOrElement;
    }

    return null;
}

function clearStatusTimeout(statusEl) {
    if (!statusEl || !statusEl.dataset.statusTimeoutId) {
        return;
    }

    clearTimeout(Number(statusEl.dataset.statusTimeoutId));
    delete statusEl.dataset.statusTimeoutId;
}

export function showStatus(tabId, message, type) {
    const statusEl = resolveStatusElement(tabId);
    if (!statusEl) {
        return;
    }

    hideAllStatuses();

    clearStatusTimeout(statusEl);

    statusEl.className = `status ${type}`;
    statusEl.textContent = message;

    requestAnimationFrame(() => {
        statusEl.classList.add('status--visible');
    });

    const timeoutId = window.setTimeout(() => {
        hideStatus(statusEl);
    }, STATUS_TIMEOUT_MS);
    statusEl.dataset.statusTimeoutId = String(timeoutId);
}

export function hideStatus(tabIdOrElement) {
    const statusEl = resolveStatusElement(tabIdOrElement);
    if (!statusEl) {
        return;
    }

    clearStatusTimeout(statusEl);
    statusEl.classList.remove('status--visible');
}

export function hideAllStatuses() {
    const statuses = document.querySelectorAll('.status');
    statuses.forEach(statusEl => {
        hideStatus(statusEl);
    });
}

function resolveProgressElements(tabIdOrElement) {
    if (typeof tabIdOrElement === 'string') {
        const progressEl = document.getElementById(`${tabIdOrElement}-progress`);
        const textEl = document.getElementById(`${tabIdOrElement}-progress-text`);
        return { progressEl, textEl };
    }

    if (tabIdOrElement instanceof Element) {
        const progressEl = tabIdOrElement.classList.contains('progress')
            ? tabIdOrElement
            : tabIdOrElement.closest('.progress');
        const textEl = progressEl ? progressEl.querySelector('[id$="-progress-text"]') : null;
        return { progressEl, textEl };
    }

    return { progressEl: null, textEl: null };
}

export function showProgress(tabId, message) {
    const { progressEl, textEl } = resolveProgressElements(tabId);
    if (progressEl && textEl) {
        textEl.textContent = message;
        progressEl.classList.add('show');
    }
}

export function hideProgress(tabIdOrElement) {
    const { progressEl } = resolveProgressElements(tabIdOrElement);
    if (progressEl) {
        progressEl.classList.remove('show');
    }
}

export function hideAllProgress() {
    document.querySelectorAll('.progress').forEach(progressEl => {
        hideProgress(progressEl);
    });
}

export function dismissAllTransientMessages() {
    hideAllStatuses();
    hideAllProgress();
}
