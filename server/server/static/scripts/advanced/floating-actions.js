import { state } from '../shared/state.js';

const MINI_REVEAL_START = 0.98;

function resolveSubTab(value) {
    return value === 'authentication' ? 'authentication' : 'registration';
}

function isAdvancedTabActive() {
    const tab = document.getElementById('advanced-tab');
    return tab instanceof HTMLElement && tab.classList.contains('active');
}

function clamp01(value) {
    if (!Number.isFinite(value)) {
        return 0;
    }
    if (value <= 0) {
        return 0;
    }
    if (value >= 1) {
        return 1;
    }
    return value;
}

export function initializeAdvancedFloatingActions() {
    const container = document.querySelector('.advanced-floating-actions');
    const header = document.querySelector('#advanced-tab .advanced-header');
    const advancedTab = document.getElementById('advanced-tab');
    if (!(container instanceof HTMLElement) || !(header instanceof HTMLElement) || !(advancedTab instanceof HTMLElement)) {
        return;
    }

    const groups = Array.from(container.querySelectorAll('.advanced-floating-actions__group'));

    const setActiveGroup = subTab => {
        const resolved = resolveSubTab(subTab);
        groups.forEach(group => {
            if (!(group instanceof HTMLElement)) {
                return;
            }
            const match = group.dataset.subtab === resolved;
            group.classList.toggle('active', match);
        });
    };

    const updateActive = () => {
        setActiveGroup(resolveSubTab(state.currentSubTab));
    };

    let stickyAnchor = 0;
    let headerSupportsSticky = true;
    let miniProgress = 0;
    let lastAppliedProgress = -1;
    let lastVisibility = false;
    let miniHeader = null;
    let miniStyleObserver = null;
    let miniHeaderWatcher = null;

    const evaluateCssToPixels = (value, relativeElement = header) => {
        if (typeof value !== 'string') {
            return Number.NaN;
        }
        const trimmed = value.trim();
        if (!trimmed) {
            return Number.NaN;
        }
        if (trimmed.endsWith('px')) {
            return parseFloat(trimmed);
        }
        if (typeof window !== 'undefined' && typeof document !== 'undefined' && document.documentElement instanceof HTMLElement) {
            const rootFont = window.getComputedStyle(document.documentElement).fontSize;
            if (trimmed.endsWith('rem')) {
                const base = parseFloat(trimmed);
                const rootSize = typeof rootFont === 'string' ? parseFloat(rootFont) : Number.NaN;
                if (Number.isFinite(base) && Number.isFinite(rootSize)) {
                    return base * rootSize;
                }
            }
            if (trimmed.endsWith('em')) {
                const base = parseFloat(trimmed);
                const context = relativeElement instanceof HTMLElement ? relativeElement : header;
                const contextFont = context instanceof HTMLElement && typeof window.getComputedStyle === 'function'
                    ? window.getComputedStyle(context).fontSize
                    : null;
                const contextSize = typeof contextFont === 'string' ? parseFloat(contextFont) : Number.NaN;
                if (Number.isFinite(base) && Number.isFinite(contextSize)) {
                    return base * contextSize;
                }
            }
        }
        const numeric = parseFloat(trimmed);
        if (Number.isFinite(numeric)) {
            return numeric;
        }
        if (typeof document !== 'undefined' && document.body instanceof HTMLElement) {
            const probe = document.createElement('div');
            probe.style.position = 'fixed';
            probe.style.top = trimmed;
            probe.style.left = '0';
            probe.style.visibility = 'hidden';
            probe.style.pointerEvents = 'none';
            document.body.appendChild(probe);
            const rect = probe.getBoundingClientRect();
            document.body.removeChild(probe);
            if (rect && Number.isFinite(rect.top)) {
                return rect.top;
            }
        }
        return Number.NaN;
    };

    const computeStickyAnchor = () => {
        if (typeof window === 'undefined' || typeof window.getComputedStyle !== 'function') {
            stickyAnchor = 0;
            headerSupportsSticky = false;
            return;
        }
        const style = window.getComputedStyle(header);
        const position = style ? (style.position || style.getPropertyValue('position')) : '';
        headerSupportsSticky = position === 'sticky';
        if (!headerSupportsSticky) {
            stickyAnchor = 0;
            return;
        }
        const directTop = style ? (style.getPropertyValue('top') || style.top) : '';
        let parsed = evaluateCssToPixels(directTop, header);
        if (!Number.isFinite(parsed)) {
            const tabStyle = window.getComputedStyle(advancedTab);
            const stickyBase = evaluateCssToPixels(tabStyle ? tabStyle.getPropertyValue('--advanced-layout-sticky-top') : '', advancedTab);
            const offset = evaluateCssToPixels('2.5rem', header);
            if (Number.isFinite(stickyBase) && Number.isFinite(offset)) {
                parsed = stickyBase - offset;
            }
        }
        stickyAnchor = Number.isFinite(parsed) ? parsed : 0;
    };

    const convertMiniProgress = progress => {
        const normalized = clamp01(progress);
        if (normalized <= MINI_REVEAL_START) {
            return 0;
        }
        const span = 1 - MINI_REVEAL_START;
        if (span <= 0) {
            return 1;
        }
        return clamp01((normalized - MINI_REVEAL_START) / span);
    };

    const applyVisibility = (visible, progressValue) => {
        const normalized = visible ? clamp01(progressValue) : 0;
        if (Math.abs(normalized - lastAppliedProgress) > 0.001) {
            container.style.setProperty('--advanced-floating-progress', normalized.toFixed(4));
            lastAppliedProgress = normalized;
        }
        const shouldShow = visible && normalized > 0;
        if (shouldShow !== lastVisibility) {
            container.classList.toggle('advanced-floating-actions--visible', shouldShow);
            container.setAttribute('aria-hidden', shouldShow ? 'false' : 'true');
            lastVisibility = shouldShow;
        }
    };

    const readMiniHeaderProgress = element => {
        if (!(element instanceof HTMLElement)) {
            return 0;
        }
        let value = element.style ? element.style.getPropertyValue('--header-mini-progress') : '';
        let parsed = value ? parseFloat(value) : Number.NaN;
        if (!Number.isFinite(parsed) && typeof window !== 'undefined' && typeof window.getComputedStyle === 'function') {
            const computed = window.getComputedStyle(element).getPropertyValue('--header-mini-progress');
            parsed = computed ? parseFloat(computed) : Number.NaN;
        }
        return Number.isFinite(parsed) ? clamp01(parsed) : 0;
    };

    const attachMiniObserver = element => {
        if (!(element instanceof HTMLElement)) {
            return false;
        }
        if (miniHeaderWatcher) {
            miniHeaderWatcher.disconnect();
            miniHeaderWatcher = null;
        }
        if (miniStyleObserver) {
            miniStyleObserver.disconnect();
            miniStyleObserver = null;
        }
        miniHeader = element;
        miniProgress = readMiniHeaderProgress(miniHeader);
        if (typeof MutationObserver === 'function') {
            miniStyleObserver = new MutationObserver(() => {
                miniProgress = readMiniHeaderProgress(miniHeader);
                evaluateVisibility();
            });
            miniStyleObserver.observe(miniHeader, { attributes: true, attributeFilter: ['style'] });
        }
        evaluateVisibility();
        return true;
    };

    const ensureMiniObserver = () => {
        if (attachMiniObserver(document.querySelector('.header-mini'))) {
            return;
        }
        if (typeof MutationObserver === 'function' && document.body instanceof HTMLElement) {
            miniHeaderWatcher = new MutationObserver(() => {
                if (attachMiniObserver(document.querySelector('.header-mini'))) {
                    return;
                }
            });
            miniHeaderWatcher.observe(document.body, { childList: true, subtree: true });
            return;
        }
        if (typeof window !== 'undefined') {
            const retry = () => {
                if (attachMiniObserver(document.querySelector('.header-mini'))) {
                    return;
                }
                window.setTimeout(retry, 250);
            };
            retry();
        }
    };

    const evaluateVisibility = () => {
        if (miniHeader instanceof HTMLElement && (typeof MutationObserver !== 'function')) {
            miniProgress = readMiniHeaderProgress(miniHeader);
        }
        computeStickyAnchor();
        if (!headerSupportsSticky || !isAdvancedTabActive()) {
            applyVisibility(false, 0);
            return;
        }
        const rect = header.getBoundingClientRect();
        if (!rect || !Number.isFinite(rect.top) || !Number.isFinite(rect.bottom)) {
            applyVisibility(false, 0);
            return;
        }
        const threshold = stickyAnchor + 0.5;
        const stuck = rect.top <= threshold && rect.bottom > threshold;
        if (!stuck) {
            applyVisibility(false, 0);
            return;
        }
        const derived = convertMiniProgress(miniProgress);
        applyVisibility(derived > 0, derived);
    };

    const handleScroll = () => {
        evaluateVisibility();
    };

    const handleResize = () => {
        evaluateVisibility();
    };

    if (typeof window !== 'undefined' && typeof window.addEventListener === 'function') {
        window.addEventListener('scroll', handleScroll, { passive: true });
        window.addEventListener('resize', handleResize);
        window.addEventListener('pageshow', handleResize);
    }

    if (typeof ResizeObserver === 'function') {
        const resizeObserver = new ResizeObserver(() => {
            evaluateVisibility();
        });
        resizeObserver.observe(header);
    }

    document.addEventListener('advanced:subtab-changed', () => {
        updateActive();
        evaluateVisibility();
    });

    document.addEventListener('tab:changed', event => {
        if (event.detail?.tab === 'advanced') {
            updateActive();
            evaluateVisibility();
            return;
        }
        applyVisibility(false, 0);
    });

    ensureMiniObserver();
    updateActive();
    evaluateVisibility();
}
