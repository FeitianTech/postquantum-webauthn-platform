const STATUS_TIMEOUT_MS = 5000;

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
    statusEl.style.removeProperty('bottom');

    statusEl.className = `status ${type}`;
    statusEl.textContent = message;

    adjustStatusPosition(statusEl, tabId);

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
    statusEl.className = 'status';
    statusEl.textContent = '';
    statusEl.style.removeProperty('bottom');
}

export function hideAllStatuses() {
    const statuses = document.querySelectorAll('.status');
    statuses.forEach(statusEl => {
        hideStatus(statusEl);
    });
}

function adjustStatusPosition(statusEl, tabIdOrElement) {
    let progressEl = null;

    if (typeof tabIdOrElement === 'string') {
        progressEl = document.getElementById(`${tabIdOrElement}-progress`);
    } else if (statusEl?.id?.endsWith('-status')) {
        const prefix = statusEl.id.slice(0, -'-status'.length);
        progressEl = document.getElementById(`${prefix}-progress`);
    }

    if (!progressEl || !progressEl.classList.contains('show')) {
        statusEl.style.removeProperty('bottom');
        return;
    }

    const progressHeight = Math.ceil(progressEl.getBoundingClientRect().height);
    const spacer = 12;
    statusEl.style.bottom = `calc(var(--global-toast-offset) + ${progressHeight + spacer}px)`;
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

        const statusId = progressEl.id?.endsWith('-progress')
            ? `${progressEl.id.slice(0, -'-progress'.length)}-status`
            : null;
        const statusEl = statusId ? document.getElementById(statusId) : null;
        if (statusEl?.classList.contains('status--visible')) {
            adjustStatusPosition(statusEl, tabIdOrElement);
        }
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
