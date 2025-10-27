import { state } from '../shared/state.js';

function resolveSubTab(value) {
    return value === 'authentication' ? 'authentication' : 'registration';
}

function isAdvancedTabActive() {
    const tab = document.getElementById('advanced-tab');
    return tab instanceof HTMLElement && tab.classList.contains('active');
}

export function initializeAdvancedFloatingActions() {
    const container = document.querySelector('.advanced-floating-actions');
    const header = document.querySelector('#advanced-tab .advanced-header');
    if (!(container instanceof HTMLElement) || !(header instanceof HTMLElement)) {
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

    const applyVisibility = visible => {
        const shouldShow = visible && isAdvancedTabActive();
        container.classList.toggle('advanced-floating-actions--visible', shouldShow);
        container.setAttribute('aria-hidden', shouldShow ? 'false' : 'true');
    };

    let stickyTop = 0;

    const evaluateCssToPixels = value => {
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
                const headerFont = window.getComputedStyle(header).fontSize;
                const headerSize = typeof headerFont === 'string' ? parseFloat(headerFont) : Number.NaN;
                if (Number.isFinite(base) && Number.isFinite(headerSize)) {
                    return base * headerSize;
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

    const computeStickyTop = () => {
        if (typeof window === 'undefined' || typeof window.getComputedStyle !== 'function') {
            stickyTop = 0;
            return;
        }
        const style = window.getComputedStyle(header);
        const value = style ? style.getPropertyValue('top') || style.top : '';
        const parsed = evaluateCssToPixels(value);
        if (Number.isFinite(parsed)) {
            stickyTop = parsed;
            return;
        }
        stickyTop = 0;
    };

    const evaluateVisibility = () => {
        if (!isAdvancedTabActive()) {
            applyVisibility(false);
            return;
        }
        const rect = header.getBoundingClientRect();
        const threshold = stickyTop + 0.5;
        const stuck = rect.top <= threshold && rect.bottom > threshold;
        applyVisibility(stuck);
    };

    const handleScroll = () => {
        evaluateVisibility();
    };

    const handleResize = () => {
        computeStickyTop();
        evaluateVisibility();
    };

    if (typeof window !== 'undefined' && typeof window.addEventListener === 'function') {
        window.addEventListener('scroll', handleScroll, { passive: true });
        window.addEventListener('resize', handleResize);
        window.addEventListener('pageshow', handleResize);
    }

    if (typeof ResizeObserver === 'function') {
        const resizeObserver = new ResizeObserver(() => {
            computeStickyTop();
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
            handleResize();
            return;
        }
        applyVisibility(false);
    });

    computeStickyTop();
    updateActive();
    evaluateVisibility();
}
