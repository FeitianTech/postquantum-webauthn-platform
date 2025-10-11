const BODY_LOADING_CLASS = 'app-loading';
const BODY_LOADED_CLASS = 'app-loaded';

let elements = null;
let initialized = false;
let hasCompleted = false;
let hideTimer = null;
let currentProgress = 0;
let currentMetadataCount = 0;

function getElements() {
    if (elements) {
        return elements;
    }

    const root = document.getElementById('app-loader');
    if (!root) {
        return null;
    }

    const status = document.getElementById('app-loader-status');
    const progressBar = document.getElementById('app-loader-progress');
    const progressFill = root.querySelector('.app-loader__progress-fill');
    const percentage = document.getElementById('app-loader-percentage');
    const metadata = document.getElementById('app-loader-metadata');

    elements = {
        root,
        status,
        progressBar,
        progressFill,
        percentage,
        metadata,
    };

    return elements;
}

function ensureInitialized() {
    if (initialized) {
        return getElements();
    }

    const els = getElements();
    if (!els) {
        return null;
    }

    initialized = true;

    if (!els.root.classList.contains('app-loader--hidden')) {
        els.root.setAttribute('aria-hidden', 'false');
    }

    if (typeof document !== 'undefined' && document.body) {
        document.body.classList.add(BODY_LOADING_CLASS);
    }

    updateMetadataCount(0);
    updateProgress(0);

    return els;
}

function updateStatus(message) {
    const els = getElements();
    if (!els || hasCompleted) {
        return;
    }

    if (els.status) {
        els.status.textContent = message;
    }
}

function updateProgress(value) {
    const els = getElements();
    if (!els || hasCompleted) {
        return;
    }

    const progress = Math.max(0, Math.min(100, Math.round(value)));
    if (progress === currentProgress) {
        return;
    }

    currentProgress = progress;

    if (els.progressFill) {
        els.progressFill.style.width = `${progress}%`;
    }

    if (els.progressBar) {
        els.progressBar.setAttribute('aria-valuenow', String(progress));
    }

    if (els.percentage) {
        els.percentage.textContent = `${progress}%`;
    }
}

function updateMetadataCount(count) {
    const els = getElements();
    if (!els || hasCompleted) {
        return;
    }

    const safeCount = Math.max(0, Math.floor(count));
    if (safeCount === currentMetadataCount) {
        return;
    }

    currentMetadataCount = safeCount;

    if (els.metadata) {
        els.metadata.textContent = `Metadata loaded: ${safeCount.toLocaleString()}`;
    }
}

function revealApplication() {
    if (typeof document === 'undefined' || !document.body) {
        return;
    }

    document.body.classList.remove(BODY_LOADING_CLASS);
    document.body.classList.add(BODY_LOADED_CLASS);
}

export function initializeLoader() {
    ensureInitialized();
}

export function loaderIsActive() {
    const els = getElements();
    return Boolean(els) && !hasCompleted;
}

export function loaderSetPhase(message, options = {}) {
    const els = ensureInitialized();
    if (!els || hasCompleted) {
        return;
    }

    if (typeof message === 'string' && message) {
        updateStatus(message);
    }

    if (options && typeof options === 'object') {
        const { progress } = options;
        if (typeof progress === 'number' && !Number.isNaN(progress)) {
            updateProgress(progress);
        }
    }
}

export function loaderSetProgress(progress) {
    updateProgress(progress);
}

export function loaderSetMetadataCount(count) {
    updateMetadataCount(count);
}

export function loaderComplete(options = {}) {
    if (hasCompleted) {
        return;
    }

    const els = getElements();
    if (!els) {
        hasCompleted = true;
        revealApplication();
        return;
    }

    const opts = options && typeof options === 'object' ? options : {};
    const message = typeof opts.message === 'string' && opts.message.trim()
        ? opts.message.trim()
        : '';
    const delay = typeof opts.delay === 'number' && !Number.isNaN(opts.delay)
        ? Math.max(0, opts.delay)
        : 520;

    if (message) {
        updateStatus(message);
    }

    updateProgress(100);

    hasCompleted = true;

    if (hideTimer) {
        clearTimeout(hideTimer);
    }

    revealApplication();

    hideTimer = setTimeout(() => {
        els.root.classList.add('app-loader--hidden');
        els.root.setAttribute('aria-hidden', 'true');
    }, delay);
}
