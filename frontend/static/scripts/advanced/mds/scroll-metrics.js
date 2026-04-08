import { updateScrollTopButtonVisibilityInState } from './scroll-top-button-visibility.js';

export function clearHorizontalFloatingStyles(horizontal) {
    if (!horizontal) {
        return;
    }
    horizontal.style.left = '';
    horizontal.style.right = '';
    horizontal.style.bottom = '';
    horizontal.style.top = '';
    horizontal.style.width = '';
    horizontal.style.transform = '';
}

export function hideHorizontalScroll(state, clearHorizontalFloatingStylesFn = clearHorizontalFloatingStyles) {
    if (!state) {
        return;
    }

    const horizontal =
        state.horizontalScrollContainer instanceof HTMLElement ? state.horizontalScrollContainer : null;

    if (!horizontal) {
        return;
    }

    clearHorizontalFloatingStylesFn(horizontal);
    horizontal.hidden = true;
    horizontal.setAttribute('hidden', '');
    horizontal.setAttribute('aria-hidden', 'true');
    horizontal.classList.remove('is-ready');
    horizontal.classList.remove('is-overflowing');
    horizontal.classList.remove('is-floating');
}

export function updateFloatingHorizontalScrollPosition(
    state,
    metrics = {},
    options = {},
) {
    if (!state) {
        return;
    }

    const horizontal =
        state.horizontalScrollContainer instanceof HTMLElement ? state.horizontalScrollContainer : null;
    const container = state.tableContainer instanceof HTMLElement ? state.tableContainer : null;

    if (!horizontal || !container) {
        return;
    }

    const {
        clearHorizontalFloatingStylesFn = clearHorizontalFloatingStyles,
        sideMargin = 16,
        bottomMargin = 24,
    } = options;

    const rect = metrics.containerRect || container.getBoundingClientRect();
    if (!rect) {
        clearHorizontalFloatingStylesFn(horizontal);
        horizontal.classList.remove('is-floating');
        return;
    }

    const viewportHeight =
        typeof metrics.viewportHeight === 'number'
            ? metrics.viewportHeight
            : typeof window !== 'undefined'
              ? window.innerHeight || document.documentElement?.clientHeight || 0
              : 0;
    const viewportWidth =
        typeof metrics.viewportWidth === 'number'
            ? metrics.viewportWidth
            : typeof window !== 'undefined'
              ? window.innerWidth || document.documentElement?.clientWidth || 0
              : 0;

    if (!viewportHeight || !viewportWidth) {
        clearHorizontalFloatingStylesFn(horizontal);
        horizontal.classList.remove('is-floating');
        return;
    }

    const rawWidth = Number.isFinite(rect.width) ? rect.width : viewportWidth;
    const maxWidth = viewportWidth - sideMargin * 2;
    let width = rawWidth;
    if (maxWidth > 0) {
        width = Math.min(width, maxWidth);
    }
    width = Math.max(0, width);
    if (!width) {
        clearHorizontalFloatingStylesFn(horizontal);
        horizontal.classList.remove('is-floating');
        return;
    }
    horizontal.style.width = `${Math.round(width)}px`;

    const maxLeft = viewportWidth - sideMargin - width;
    const preferredLeft = Number.isFinite(rect.left) ? rect.left : sideMargin;
    let left;
    if (maxLeft >= sideMargin) {
        left = Math.min(Math.max(preferredLeft, sideMargin), maxLeft);
    } else {
        left = Math.max(preferredLeft, sideMargin);
    }
    horizontal.style.left = `${Math.round(left)}px`;
    horizontal.style.right = 'auto';

    const offsetFromBottom = viewportHeight - rect.bottom;
    const bottomOffset = Math.max(bottomMargin, offsetFromBottom);
    horizontal.style.bottom = `${Math.round(bottomOffset)}px`;
    horizontal.style.top = 'auto';
    horizontal.classList.add('is-floating');
}

export function updateHorizontalScrollMetrics(state, options = {}) {
    if (!state) {
        return;
    }

    const {
        hideHorizontalScrollFn = hideHorizontalScroll,
        updateFloatingHorizontalScrollPositionFn = updateFloatingHorizontalScrollPosition,
        getIsSyncing = () => false,
        setIsSyncing = () => {},
        clearHorizontalFloatingStylesFn = clearHorizontalFloatingStyles,
    } = options;

    const table = state.table instanceof HTMLElement ? state.table : null;
    const container = state.tableContainer instanceof HTMLElement ? state.tableContainer : null;
    const horizontal =
        state.horizontalScrollContainer instanceof HTMLElement ? state.horizontalScrollContainer : null;
    const content =
        state.horizontalScrollContent instanceof HTMLElement ? state.horizontalScrollContent : null;

    if (!horizontal) {
        return;
    }

    const tableWidth = table ? table.scrollWidth : 0;
    const containerWidth = container ? container.clientWidth : 0;
    const targetWidth = Math.max(tableWidth, containerWidth);
    const safeWidth = Number.isFinite(targetWidth) ? targetWidth : 0;

    if (content) {
        content.style.width = `${safeWidth}px`;
    }

    const overflowing = table && container ? tableWidth > containerWidth + 1 : false;
    horizontal.classList.toggle('is-overflowing', Boolean(overflowing));

    const viewportHeight =
        typeof window !== 'undefined'
            ? window.innerHeight || document.documentElement?.clientHeight || 0
            : 0;
    const viewportWidth =
        typeof window !== 'undefined'
            ? window.innerWidth || document.documentElement?.clientWidth || 0
            : 0;
    const containerRect = container ? container.getBoundingClientRect() : null;

    const containerVisible =
        containerRect &&
        viewportHeight > 0 &&
        containerRect.bottom > 0 &&
        containerRect.top < viewportHeight;

    if (!containerVisible) {
        hideHorizontalScrollFn(state, clearHorizontalFloatingStylesFn);
        return;
    }

    if (horizontal.hidden) {
        horizontal.hidden = false;
        horizontal.removeAttribute('hidden');
    }
    horizontal.setAttribute('aria-hidden', 'false');
    horizontal.classList.add('is-ready');

    if (container && !getIsSyncing()) {
        setIsSyncing(true);
        horizontal.scrollLeft = container.scrollLeft;
        setIsSyncing(false);
    }

    updateFloatingHorizontalScrollPositionFn(
        state,
        {
            containerRect,
            viewportHeight,
            viewportWidth,
        },
        {
            clearHorizontalFloatingStylesFn,
        },
    );
}

export function syncHorizontalScrollPositions(source, target, getIsSyncing = () => false, setIsSyncing = () => {}) {
    if (!source || !target) {
        return;
    }
    if (getIsSyncing()) {
        return;
    }
    setIsSyncing(true);
    try {
        target.scrollLeft = source.scrollLeft;
    } finally {
        setIsSyncing(false);
    }
}

export function showScrollTopButton(state) {
    if (!state?.scrollTopButton) {
        return;
    }
    if (state.scrollTopButtonVisible) {
        return;
    }
    state.scrollTopButton.hidden = false;
    state.scrollTopButton.setAttribute('aria-hidden', 'false');
    state.scrollTopButtonVisible = true;
}

export function hideScrollTopButton(state) {
    if (!state?.scrollTopButton) {
        return;
    }
    if (state.scrollTopButton.hidden) {
        state.scrollTopButtonVisible = false;
        state.scrollTopButton.setAttribute('aria-hidden', 'true');
        return;
    }
    state.scrollTopButton.hidden = true;
    state.scrollTopButton.setAttribute('aria-hidden', 'true');
    state.scrollTopButtonVisible = false;
}

export function updateScrollTopButtonVisibility(state, options = {}) {
    return updateScrollTopButtonVisibilityInState(state, {
        ...options,
        hideScrollTopButtonFn: options.hideScrollTopButtonFn || hideScrollTopButton,
        showScrollTopButtonFn: options.showScrollTopButtonFn || showScrollTopButton,
    });
}

export function scrollMdsSectionToTop(state, scheduleScrollTopButtonUpdate) {
    if (typeof window !== 'undefined' && typeof window.scrollTo === 'function') {
        window.scrollTo({ top: 0, left: 0, behavior: 'smooth' });
    } else if (state?.root && typeof state.root.scrollIntoView === 'function') {
        state.root.scrollIntoView({ block: 'start', behavior: 'smooth' });
    }

    scheduleScrollTopButtonUpdate();
}

export function handleWindowScroll(
    scheduleScrollTopButtonUpdate,
    scheduleColumnResizerMetricsUpdate,
    scheduleHorizontalScrollMetricsUpdate,
) {
    scheduleScrollTopButtonUpdate();
    scheduleColumnResizerMetricsUpdate();
    scheduleHorizontalScrollMetricsUpdate();
}
