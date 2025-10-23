let hideTimeout;

const BASE_MODAL_Z_INDEX = 1200;
const MODAL_STACK_INCREMENT = 50;

const stickyHeaderControllers = new WeakMap();

function parseModalZIndex(value) {
    if (typeof value === 'number' && !Number.isNaN(value)) {
        return value;
    }

    if (typeof value === 'string' && value.trim() !== '') {
        const parsed = Number.parseInt(value, 10);
        if (!Number.isNaN(parsed)) {
            return parsed;
        }
    }

    return null;
}

function getElementZIndex(element) {
    if (!element) {
        return null;
    }

    const datasetCandidates = [
        element.dataset.modalStackZIndex,
        element.dataset.modalBaseZIndex,
    ];

    for (const candidate of datasetCandidates) {
        const parsed = parseModalZIndex(candidate);
        if (parsed !== null) {
            return parsed;
        }
    }

    if (typeof window !== 'undefined' && typeof window.getComputedStyle === 'function') {
        const computed = window.getComputedStyle(element);
        const parsed = parseModalZIndex(computed?.zIndex);
        if (parsed !== null) {
            return parsed;
        }
    }

    return null;
}

function ensureModalBaseZIndex(modal) {
    if (!modal) {
        return BASE_MODAL_Z_INDEX;
    }

    const stored = parseModalZIndex(modal.dataset.modalBaseZIndex);
    if (stored !== null) {
        return stored;
    }

    const computed = (typeof window !== 'undefined' && typeof window.getComputedStyle === 'function')
        ? window.getComputedStyle(modal)
        : null;
    const parsed = parseModalZIndex(computed?.zIndex);
    const base = parsed !== null ? parsed : BASE_MODAL_Z_INDEX;
    modal.dataset.modalBaseZIndex = String(base);
    return base;
}

function getHighestOpenModalZIndex(excludeModal = null) {
    const openModals = Array.from(document.querySelectorAll('.modal.open'));
    let highest = BASE_MODAL_Z_INDEX;

    openModals.forEach(openModalEl => {
        if (openModalEl === excludeModal) {
            return;
        }

        const zIndex = getElementZIndex(openModalEl);
        if (typeof zIndex === 'number' && zIndex > highest) {
            highest = zIndex;
        }
    });

    return highest;
}

export function showInfoPopup(iconElement) {
    const popup = iconElement.querySelector('.info-popup');
    if (!popup) {
        return;
    }

    if (hideTimeout) {
        clearTimeout(hideTimeout);
        hideTimeout = null;
    }

    document.querySelectorAll('.info-popup.show').forEach(p => p.classList.remove('show'));
    popup.classList.add('show');

    if (!popup.hasAttribute('data-english-dimensions')) {
        requestAnimationFrame(() => {
            const enText = popup.querySelector('.text-en.active');
            if (enText) {
                const enComputedStyle = window.getComputedStyle(enText);
                const popupComputedStyle = window.getComputedStyle(popup);

                popup.setAttribute('data-english-width', popupComputedStyle.width);
                popup.setAttribute('data-english-height', popupComputedStyle.height);
                popup.setAttribute('data-english-text-height', enComputedStyle.height);
                popup.setAttribute('data-english-dimensions', 'true');

                popup.style.width = popupComputedStyle.width;
                popup.style.minWidth = popupComputedStyle.width;
                popup.style.height = popupComputedStyle.height;
                popup.style.minHeight = popupComputedStyle.height;
            }
        });
    }

    if (!popup.hasAttribute('data-listeners-added')) {
        popup.addEventListener('mouseenter', () => {
            if (hideTimeout) {
                clearTimeout(hideTimeout);
                hideTimeout = null;
            }
            popup.classList.add('show');
        });

        popup.addEventListener('mouseleave', () => {
            hideTimeout = setTimeout(() => {
                popup.classList.remove('show');
            }, 200);
        });

        popup.setAttribute('data-listeners-added', 'true');
    }
}

export function hideInfoPopup(iconElement) {
    const popup = iconElement.querySelector('.info-popup');
    if (!popup) {
        return;
    }
    hideTimeout = setTimeout(() => {
        if (!popup.matches(':hover') && !iconElement.matches(':hover')) {
            popup.classList.remove('show');
        }
    }, 200);
}

export function toggleLanguage(toggleElement) {
    const popup = toggleElement.closest('.info-popup') || toggleElement.closest('.alert');
    if (!popup) {
        console.error('Could not find parent container for language toggle');
        return;
    }

    const enText = popup.querySelector('.text-en');
    const zhText = popup.querySelector('.text-zh');

    if (!enText || !zhText) {
        console.error('Could not find text elements for language toggle');
        return;
    }

    if (!popup.hasAttribute('data-english-dimensions')) {
        const enComputedStyle = window.getComputedStyle(enText);
        const popupComputedStyle = window.getComputedStyle(popup);

        popup.setAttribute('data-english-width', popupComputedStyle.width);
        popup.setAttribute('data-english-height', popupComputedStyle.height);
        popup.setAttribute('data-english-text-height', enComputedStyle.height);
        popup.setAttribute('data-english-dimensions', 'true');

        popup.style.width = popupComputedStyle.width;
        popup.style.height = popupComputedStyle.height;
        popup.style.minHeight = popupComputedStyle.height;
    }

    if (enText.classList.contains('active')) {
        enText.classList.remove('active');
        enText.classList.add('hidden');
        zhText.classList.remove('hidden');
        zhText.classList.add('active');
        toggleElement.textContent = '中';

        const storedHeight = popup.getAttribute('data-english-text-height');
        if (storedHeight) {
            zhText.style.height = storedHeight;
            zhText.style.minHeight = storedHeight;
        }
    } else {
        zhText.classList.remove('active');
        zhText.classList.add('hidden');
        enText.classList.remove('hidden');
        enText.classList.add('active');
        toggleElement.textContent = 'ENG';

        const storedHeight = popup.getAttribute('data-english-text-height');
        if (storedHeight) {
            enText.style.height = storedHeight;
            enText.style.minHeight = storedHeight;
        }
    }
}

export function updateGlobalScrollLock() {
    const overlayActive = document.getElementById('json-editor-overlay')?.classList.contains('active');
    const modalActive = document.querySelector('.modal.open');
    const mdsModalActive = document.querySelector('.mds-modal:not([hidden])');
    const mdsDetailActive = document.querySelector('.mds-detail-page--open');
    const shouldLock = Boolean(overlayActive || modalActive || mdsModalActive || mdsDetailActive);

    const targets = [document.body, document.documentElement].filter(Boolean);
    targets.forEach(target => {
        target.classList.toggle('modal-open', shouldLock);
    });
}

export function resetModalScroll(modal) {
    if (!modal) {
        return;
    }

    modal.scrollTop = 0;
    modal.querySelectorAll('.modal-content, .modal-body, textarea, pre, code, .credential-code-block').forEach(element => {
        if (element) {
            element.scrollTop = 0;
            if (element.scrollLeft !== undefined) {
                element.scrollLeft = 0;
            }
        }
    });
}

export function openModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) {
        modal.classList.remove('closing');
        delete modal.dataset.modalClosing;
        resetModalScroll(modal);

        const baseZIndex = ensureModalBaseZIndex(modal);
        const highestOtherModal = getHighestOpenModalZIndex(modal);
        const targetZIndex = Math.max(baseZIndex, highestOtherModal + MODAL_STACK_INCREMENT);

        modal.dataset.modalStackZIndex = String(targetZIndex);
        modal.style.zIndex = String(targetZIndex);

        modal.classList.add('open');

        requestAnimationFrame(() => resetModalScroll(modal));
        updateGlobalScrollLock();
    }
}

export function closeModal(modalId) {
    const modal = document.getElementById(modalId);
    if (!modal) {
        return;
    }

    const finalizeClose = () => {
        if (modal.dataset.modalStackZIndex) {
            const baseZIndex = ensureModalBaseZIndex(modal);
            if (modal.dataset.modalBaseZIndex) {
                modal.style.zIndex = modal.dataset.modalBaseZIndex;
            } else if (typeof baseZIndex === 'number') {
                modal.style.zIndex = String(baseZIndex);
            } else {
                modal.style.removeProperty('z-index');
            }
            delete modal.dataset.modalStackZIndex;
        }
        requestAnimationFrame(() => resetModalScroll(modal));
        updateGlobalScrollLock();
    };

    const isDetailScreen = modal.classList.contains('detail-screen');

    if (!isDetailScreen) {
        modal.classList.remove('open');
        finalizeClose();
        return;
    }

    if (!modal.classList.contains('open')) {
        modal.classList.remove('closing');
        delete modal.dataset.modalClosing;
        finalizeClose();
        return;
    }

    if (modal.dataset.modalClosing === 'true') {
        return;
    }

    modal.dataset.modalClosing = 'true';

    const scheduleTimeout =
        typeof window !== 'undefined' && typeof window.setTimeout === 'function'
            ? window.setTimeout.bind(window)
            : setTimeout;
    const cancelTimeout =
        typeof window !== 'undefined' && typeof window.clearTimeout === 'function'
            ? window.clearTimeout.bind(window)
            : clearTimeout;

    let cleanupScheduled = false;
    let fallbackTimeoutId = null;

    const cleanup = () => {
        if (cleanupScheduled) {
            return;
        }
        cleanupScheduled = true;

        if (fallbackTimeoutId !== null) {
            cancelTimeout(fallbackTimeoutId);
            fallbackTimeoutId = null;
        }

        modal.removeEventListener('transitionend', handleTransitionEnd);
        modal.classList.remove('closing');
        delete modal.dataset.modalClosing;

        finalizeClose();
    };

    const handleTransitionEnd = event => {
        if (!event || event.target !== modal || event.propertyName !== 'opacity') {
            return;
        }
        cleanup();
    };

    modal.addEventListener('transitionend', handleTransitionEnd);

    modal.classList.add('closing');
    modal.classList.remove('open');

    fallbackTimeoutId = scheduleTimeout(() => {
        cleanup();
    }, 700);
}

export function toggleJsonEditorExpansion(forceCollapse = false) {
    const container = document.getElementById('json-editor-container');
    const overlay = document.getElementById('json-editor-overlay');
    const closeButton = document.getElementById('json-editor-close');

    if (!container || !overlay) {
        return;
    }

    const shouldExpand = forceCollapse ? false : !container.classList.contains('expanded');

    if (shouldExpand) {
        container.classList.add('expanded');
        container.setAttribute('aria-expanded', 'true');
        overlay.classList.add('active');
        const editor = document.getElementById('json-editor');
        if (editor) {
            editor.scrollTop = 0;
            if (typeof editor.focus === 'function') {
                editor.focus();
            }
        }
    } else {
        overlay.classList.remove('active');
        container.classList.remove('expanded');
        container.setAttribute('aria-expanded', 'false');
        if (closeButton) {
            closeButton.blur();
        }
    }

    if (closeButton) {
        closeButton.setAttribute('aria-hidden', shouldExpand ? 'false' : 'true');
        closeButton.tabIndex = shouldExpand ? 0 : -1;
    }

    updateGlobalScrollLock();
}

export function initializeStickyHeaderForElement(header, options = {}) {
    if (!(header instanceof HTMLElement)) {
        return null;
    }

    const existing = stickyHeaderControllers.get(header);
    if (existing) {
        return existing;
    }

    const {
        root: rootOption = document.body instanceof HTMLElement ? document.body : header.parentElement,
        cloneSource = null,
        cloneSelector = null,
        createContent = null,
        miniClass: providedMiniClass = 'header-mini',
        miniInnerClass: providedMiniInnerClass = null,
        activeClass: providedActiveClass = null,
        measuringClass: providedMeasuringClass = null,
        progressProperty = '--header-mini-progress',
        heightProperty = '--header-mini-height',
        scrollTarget = typeof window !== 'undefined' ? window : null,
    } = options || {};

    const miniClass = typeof providedMiniClass === 'string' && providedMiniClass.trim()
        ? providedMiniClass.trim()
        : 'header-mini';
    const miniInnerClass = typeof providedMiniInnerClass === 'string' && providedMiniInnerClass.trim()
        ? providedMiniInnerClass.trim()
        : `${miniClass}__inner`;
    const activeClass = typeof providedActiveClass === 'string' && providedActiveClass.trim()
        ? providedActiveClass.trim()
        : `${miniClass}--active`;
    const measuringClass = typeof providedMeasuringClass === 'string' && providedMeasuringClass.trim()
        ? providedMeasuringClass.trim()
        : `${miniClass}--measuring`;

    let root = rootOption;
    if (!(root instanceof HTMLElement) && typeof document !== 'undefined') {
        root = document.body || header.parentElement;
    }
    if (!(root instanceof HTMLElement)) {
        header.dataset.stickyInitialized = 'true';
        return null;
    }

    let contentNode = null;
    if (typeof createContent === 'function') {
        try {
            contentNode = createContent({ header });
        } catch (error) {
            contentNode = null;
        }
    }

    if (!(contentNode instanceof Node)) {
        let sourceNode = null;
        if (cloneSource instanceof HTMLElement) {
            sourceNode = cloneSource;
        } else if (typeof cloneSelector === 'string' && cloneSelector) {
            const candidate = header.querySelector(cloneSelector);
            if (candidate instanceof HTMLElement) {
                sourceNode = candidate;
            }
        }
        if (!(sourceNode instanceof HTMLElement)) {
            sourceNode = header;
        }
        contentNode = sourceNode.cloneNode(true);
    }

    if (!(contentNode instanceof Node)) {
        header.dataset.stickyInitialized = 'true';
        return null;
    }

    const miniHeader = document.createElement('div');
    miniHeader.className = miniClass;
    miniHeader.setAttribute('aria-hidden', 'true');

    const miniInner = document.createElement('div');
    miniInner.className = miniInnerClass;
    miniInner.appendChild(contentNode);
    miniHeader.appendChild(miniInner);

    if (typeof options.insert === 'function') {
        try {
            options.insert(miniHeader, { header, root });
        } catch (error) {
            root.appendChild(miniHeader);
        }
    } else {
        root.appendChild(miniHeader);
    }

    const raf = typeof window !== 'undefined' && typeof window.requestAnimationFrame === 'function'
        ? window.requestAnimationFrame.bind(window)
        : (fn => setTimeout(fn, 16));

    const cleanupHandlers = [];

    const scrollElement = scrollTarget instanceof HTMLElement ? scrollTarget : (typeof window !== 'undefined' ? window : null);
    const isElementScrollTarget = scrollElement instanceof HTMLElement;

    const getScrollPosition = () => {
        if (typeof options.getScrollPosition === 'function') {
            try {
                const custom = options.getScrollPosition({ header, scrollElement });
                if (Number.isFinite(custom)) {
                    return custom;
                }
            } catch (error) {
                // Ignore custom getter errors.
            }
        }

        if (isElementScrollTarget) {
            return Number.isFinite(scrollElement.scrollTop) ? scrollElement.scrollTop : 0;
        }

        if (typeof window !== 'undefined') {
            if (typeof window.scrollY === 'number') {
                return window.scrollY;
            }
            if (typeof window.pageYOffset === 'number') {
                return window.pageYOffset;
            }
        }

        if (typeof document !== 'undefined') {
            if (document.documentElement && typeof document.documentElement.scrollTop === 'number') {
                return document.documentElement.scrollTop;
            }
            if (document.body && typeof document.body.scrollTop === 'number') {
                return document.body.scrollTop;
            }
        }

        return 0;
    };

    const clamp01 = value => {
        if (!Number.isFinite(value)) {
            return 0;
        }
        if (value < 0) {
            return 0;
        }
        if (value > 1) {
            return 1;
        }
        return value;
    };

    let headerBottom = 0;
    let miniHeight = 1;
    let revealRange = 1;
    let lastProgress = -1;
    let pendingUpdate = false;
    let pendingGeometryUpdate = false;

    const applyProgress = progress => {
        if (Math.abs(progress - lastProgress) < 0.001) {
            return;
        }

        lastProgress = progress;

        miniHeader.style.setProperty(progressProperty, progress.toFixed(4));

        if (progress > 0) {
            if (activeClass) {
                miniHeader.classList.add(activeClass);
            }
            miniHeader.removeAttribute('aria-hidden');
        } else {
            if (activeClass) {
                miniHeader.classList.remove(activeClass);
            }
            miniHeader.setAttribute('aria-hidden', 'true');
        }
    };

    const evaluateProgress = () => {
        pendingUpdate = false;

        const scrollPosition = getScrollPosition();
        const delta = scrollPosition - headerBottom;
        const rawProgress = delta > 0 ? delta / revealRange : 0;
        const progress = clamp01(rawProgress);

        applyProgress(progress);
    };

    const requestProgressEvaluation = () => {
        if (pendingUpdate) {
            return;
        }

        pendingUpdate = true;
        raf(() => {
            evaluateProgress();
        });
    };

    const measureMiniHeader = () => {
        if (measuringClass) {
            miniHeader.classList.add(measuringClass);
        }
        const previousProgress = miniHeader.style.getPropertyValue(progressProperty);
        miniHeader.style.setProperty(progressProperty, '1');

        const rect = miniInner.getBoundingClientRect();
        const measuredHeight = rect && typeof rect.height === 'number' ? rect.height : miniInner.offsetHeight;

        miniHeight = Number.isFinite(measuredHeight) && measuredHeight > 0 ? measuredHeight : 1;
        revealRange = miniHeight;
        miniHeader.style.setProperty(heightProperty, `${miniHeight}px`);

        if (previousProgress) {
            miniHeader.style.setProperty(progressProperty, previousProgress);
        } else {
            miniHeader.style.setProperty(progressProperty, '0');
        }

        if (measuringClass) {
            miniHeader.classList.remove(measuringClass);
        }
        lastProgress = -1;
    };

    const measureHeaderBottom = () => {
        if (typeof options.measureHeaderBottom === 'function') {
            try {
                const customBottom = options.measureHeaderBottom({ header, scrollElement, getScrollPosition });
                if (Number.isFinite(customBottom)) {
                    headerBottom = customBottom;
                    return;
                }
            } catch (error) {
                // Ignore custom measurement errors.
            }
        }

        const rect = header.getBoundingClientRect();
        const height = rect && typeof rect.height === 'number' ? rect.height : header.offsetHeight;

        if (isElementScrollTarget) {
            const containerRect = scrollElement.getBoundingClientRect();
            const relativeTop = rect && containerRect && typeof rect.top === 'number' && typeof containerRect.top === 'number'
                ? rect.top - containerRect.top + getScrollPosition()
                : header.offsetTop || 0;
            headerBottom = relativeTop + (Number.isFinite(height) ? height : 0);
            return;
        }

        const top = rect && typeof rect.top === 'number' ? rect.top : header.offsetTop || 0;
        headerBottom = getScrollPosition() + (Number.isFinite(top) ? top : 0) + (Number.isFinite(height) ? height : 0);
    };

    const updateGeometry = () => {
        pendingGeometryUpdate = false;
        measureHeaderBottom();
        measureMiniHeader();
        requestProgressEvaluation();
    };

    const requestGeometryUpdate = () => {
        if (pendingGeometryUpdate) {
            return;
        }

        pendingGeometryUpdate = true;
        raf(() => {
            updateGeometry();
        });
    };

    const handleScroll = () => {
        requestProgressEvaluation();
    };

    const handleResize = () => {
        requestGeometryUpdate();
    };

    if (scrollElement && typeof scrollElement.addEventListener === 'function') {
        scrollElement.addEventListener('scroll', handleScroll, { passive: true });
        cleanupHandlers.push(() => {
            scrollElement.removeEventListener('scroll', handleScroll);
        });
    }

    if (typeof window !== 'undefined' && typeof window.addEventListener === 'function') {
        window.addEventListener('resize', handleResize);
        cleanupHandlers.push(() => {
            window.removeEventListener('resize', handleResize);
        });

        const handlePageshow = () => {
            requestGeometryUpdate();
        };

        window.addEventListener('pageshow', handlePageshow);
        cleanupHandlers.push(() => {
            window.removeEventListener('pageshow', handlePageshow);
        });
    }

    if (typeof ResizeObserver === 'function') {
        const resizeObserver = new ResizeObserver(() => {
            requestGeometryUpdate();
        });
        resizeObserver.observe(header);
        cleanupHandlers.push(() => {
            resizeObserver.disconnect();
        });
    }

    requestGeometryUpdate();

    const controller = {
        header,
        miniHeader,
        miniInner,
        refreshGeometry: () => {
            requestGeometryUpdate();
        },
        evaluate: () => {
            requestProgressEvaluation();
        },
        reset: () => {
            applyProgress(0);
        },
        destroy: () => {
            cleanupHandlers.forEach(handler => {
                try {
                    handler();
                } catch (error) {
                    // Ignore cleanup errors.
                }
            });
            cleanupHandlers.length = 0;
            if (miniHeader.parentNode) {
                miniHeader.parentNode.removeChild(miniHeader);
            }
            stickyHeaderControllers.delete(header);
            if (header.dataset.stickyInitialized === 'true') {
                delete header.dataset.stickyInitialized;
            }
        },
    };

    stickyHeaderControllers.set(header, controller);
    header.dataset.stickyInitialized = 'true';

    if (typeof window !== 'undefined') {
        window.addEventListener('beforeunload', () => {
            cleanupHandlers.forEach(handler => {
                try {
                    handler();
                } catch (error) {
                    // Ignore cleanup errors to avoid blocking unload.
                }
            });
        }, { once: true });
    }

    return controller;
}

export function initializeStickyHeader() {
    const header = document.querySelector('.header');
    if (!(header instanceof HTMLElement)) {
        return null;
    }

    const navTabs = header.querySelector('.nav-tabs');
    const root = document.body instanceof HTMLElement ? document.body : header.parentElement;

    return initializeStickyHeaderForElement(header, {
        root,
        cloneSource: navTabs instanceof HTMLElement ? navTabs : header,
    });
}

export function refreshStickyHeader(header) {
    const controller = stickyHeaderControllers.get(header);
    if (!controller) {
        return;
    }
    controller.refreshGeometry();
    controller.evaluate();
}

export function resetStickyHeader(header) {
    const controller = stickyHeaderControllers.get(header);
    if (!controller) {
        return;
    }
    controller.reset();
}
