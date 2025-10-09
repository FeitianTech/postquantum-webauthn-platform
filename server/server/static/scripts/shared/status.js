export function showStatus(tabId, message, type) {
    const statusEl = document.getElementById(tabId + '-status');
    if (!statusEl) {
        return;
    }
    statusEl.className = 'status ' + type;
    statusEl.textContent = message;
    statusEl.style.display = 'block';

    setTimeout(() => {
        hideStatus(tabId);
    }, 10000);
}

export function hideStatus(tabId) {
    const statusEl = document.getElementById(tabId + '-status');
    if (statusEl) {
        statusEl.style.display = 'none';
    }
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
