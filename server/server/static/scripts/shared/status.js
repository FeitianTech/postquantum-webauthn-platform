const STATUS_TIMEOUT_MS = 10000;

export function showStatus(tabId, message, type) {
    const statusEl = document.getElementById(`${tabId}-status`);
    if (!statusEl) {
        return;
    }

    if (statusEl.dataset.statusTimeoutId) {
        clearTimeout(Number(statusEl.dataset.statusTimeoutId));
        delete statusEl.dataset.statusTimeoutId;
    }

    statusEl.className = `status ${type}`;
    statusEl.textContent = message;

    requestAnimationFrame(() => {
        statusEl.classList.add('status--visible');
    });

    const timeoutId = window.setTimeout(() => {
        hideStatus(tabId);
    }, STATUS_TIMEOUT_MS);
    statusEl.dataset.statusTimeoutId = String(timeoutId);
}

export function hideStatus(tabId) {
    const statusEl = document.getElementById(`${tabId}-status`);
    if (!statusEl) {
        return;
    }

    if (statusEl.dataset.statusTimeoutId) {
        clearTimeout(Number(statusEl.dataset.statusTimeoutId));
        delete statusEl.dataset.statusTimeoutId;
    }

    statusEl.classList.remove('status--visible');
}

export function showProgress(tabId, message) {
    const progressEl = document.getElementById(tabId + '-progress');
    const textEl = document.getElementById(tabId + '-progress-text');
    if (progressEl && textEl) {
        textEl.textContent = message;
        progressEl.classList.add('show');
    }
}

export function hideProgress(tabId) {
    const progressEl = document.getElementById(tabId + '-progress');
    if (progressEl) {
        progressEl.classList.remove('show');
    }
}
