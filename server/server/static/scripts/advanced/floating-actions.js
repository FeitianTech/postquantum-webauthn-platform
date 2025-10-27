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
    const sentinel = document.querySelector('#advanced-tab .advanced-header__sentinel');
    if (!(container instanceof HTMLElement) || !(sentinel instanceof HTMLElement)) {
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

    let lastVisible = false;

    const observer = typeof IntersectionObserver === 'function'
        ? new IntersectionObserver(entries => {
            const entry = entries && entries.length ? entries[0] : null;
            if (!entry) {
                return;
            }
            const visible = entry.isIntersecting;
            const nextVisible = !visible && entry.boundingClientRect.top < 0;
            if (nextVisible === lastVisible) {
                applyVisibility(nextVisible);
                return;
            }
            lastVisible = nextVisible;
            applyVisibility(nextVisible);
        }, { threshold: [0] })
        : null;

    if (observer) {
        observer.observe(sentinel);
    }

    const handleScrollFallback = () => {
        if (observer) {
            return;
        }
        const rect = sentinel.getBoundingClientRect();
        const nextVisible = rect.top < 0;
        if (nextVisible !== lastVisible) {
            lastVisible = nextVisible;
        }
        applyVisibility(lastVisible);
    };

    if (!observer && typeof window !== 'undefined' && typeof window.addEventListener === 'function') {
        window.addEventListener('scroll', handleScrollFallback, { passive: true });
    }

    document.addEventListener('advanced:subtab-changed', () => {
        updateActive();
        if (!observer) {
            handleScrollFallback();
        }
    });

    document.addEventListener('tab:changed', event => {
        if (event.detail?.tab === 'advanced') {
            updateActive();
            if (!observer) {
                handleScrollFallback();
            } else {
                applyVisibility(lastVisible);
            }
            return;
        }
        applyVisibility(false);
    });

    updateActive();
    if (!observer) {
        handleScrollFallback();
    } else {
        applyVisibility(false);
    }
}
