const BODY_LOADING_CLASS = 'app-loading';
const BODY_LOADED_CLASS = 'app-loaded';

const PROGRESS_INTERVAL_MS = 24;
const PROGRESS_STEP = 1;

let elements = null;
let initialized = false;
let hasCompleted = false;
let hideTimer = null;
let displayedProgress = 0;
let targetProgress = 0;
let progressTimer = null;

function getScheduler() {
    if (typeof window !== 'undefined' && window) {
        return window;
    }
    return globalThis;
}

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

    elements = {
        root,
        status,
        progressBar,
        progressFill,
        percentage,
    };

    return elements;
}

function renderProgress(value) {
    const els = getElements();
    if (!els) {
        return;
    }

    const safeValue = Math.max(0, Math.min(100, Math.round(value)));

    if (els.progressFill) {
        els.progressFill.style.width = `${safeValue}%`;
    }

    if (els.progressBar) {
        els.progressBar.setAttribute('aria-valuenow', String(safeValue));
    }

    if (els.percentage) {
        els.percentage.textContent = `${safeValue}%`;
    }
}

function stopProgressAnimation() {
    if (progressTimer === null) {
        return;
    }

    const scheduler = getScheduler();
    if (typeof scheduler.clearInterval === 'function') {
        scheduler.clearInterval(progressTimer);
    } else {
        clearInterval(progressTimer);
    }
    progressTimer = null;
}

function stepProgress() {
    if (displayedProgress >= targetProgress) {
        stopProgressAnimation();
        return;
    }

    displayedProgress = Math.min(targetProgress, displayedProgress + PROGRESS_STEP);
    renderProgress(displayedProgress);

    if (displayedProgress >= targetProgress) {
        stopProgressAnimation();
    }
}

function startProgressAnimation() {
    if (progressTimer !== null || displayedProgress >= targetProgress) {
        return;
    }

    const scheduler = getScheduler();
    if (typeof scheduler.setInterval === 'function') {
        progressTimer = scheduler.setInterval(stepProgress, PROGRESS_INTERVAL_MS);
    } else {
        progressTimer = setInterval(stepProgress, PROGRESS_INTERVAL_MS);
    }

    stepProgress();
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
    hasCompleted = false;
    displayedProgress = 0;
    targetProgress = 0;
    stopProgressAnimation();
    renderProgress(displayedProgress);

    if (!els.root.classList.contains('app-loader--hidden')) {
        els.root.setAttribute('aria-hidden', 'false');
    }

    if (typeof document !== 'undefined' && document.body) {
        document.body.classList.add(BODY_LOADING_CLASS);
    }

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

    const sanitized = Math.max(0, Math.min(100, Math.round(value)));

    if (sanitized < displayedProgress) {
        renderProgress(displayedProgress);
        return;
    }

    if (sanitized > targetProgress) {
        targetProgress = sanitized;
    }

    if (targetProgress < displayedProgress) {
        targetProgress = displayedProgress;
    }

    renderProgress(displayedProgress);

    if (displayedProgress < targetProgress) {
        startProgressAnimation();
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
    ensureInitialized();
    updateProgress(progress);
}

export function loaderSetMetadataCount() {
    // Metadata counts are no longer displayed; this function is kept for compatibility.
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
        const scheduler = getScheduler();
        if (typeof scheduler.clearTimeout === 'function') {
            scheduler.clearTimeout(hideTimer);
        } else {
            clearTimeout(hideTimer);
        }
    }

    revealApplication();

    const scheduler = getScheduler();
    hideTimer = (typeof scheduler.setTimeout === 'function' ? scheduler.setTimeout : setTimeout)(() => {
        els.root.classList.add('app-loader--hidden');
        els.root.setAttribute('aria-hidden', 'true');
    }, delay);
}
