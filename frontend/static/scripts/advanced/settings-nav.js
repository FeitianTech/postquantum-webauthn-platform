import { state } from '../shared/state.js';

function getTargetId(item) {
    if (!item || !item.dataset) {
        return null;
    }

    if (state.currentSubTab === 'authentication') {
        return item.dataset.authenticationTarget || item.dataset.registrationTarget || null;
    }

    return item.dataset.registrationTarget || null;
}

export function initializeAdvancedSettingsNavigation() {
    const nav = document.querySelector('.settings-nav');
    if (!nav) {
        return;
    }

    const navItems = Array.from(nav.querySelectorAll('.settings-nav__item'));
    if (navItems.length === 0) {
        return;
    }

    const observerOptions = {
        root: null,
        rootMargin: '-45% 0px -45% 0px',
        threshold: [0, 0.25, 0.5, 0.75, 1],
    };

    let activeTarget = null;

    const observer = new IntersectionObserver((entries) => {
        const visible = entries
            .filter(entry => entry.isIntersecting)
            .sort((a, b) => a.boundingClientRect.top - b.boundingClientRect.top);

        if (visible.length === 0) {
            return;
        }

        const topEntry = visible[0];
        if (topEntry.target.id && topEntry.target.id !== activeTarget) {
            setActive(topEntry.target.id);
        }
    }, observerOptions);

    function setActive(targetId) {
        activeTarget = targetId;
        navItems.forEach(navItem => {
            const target = getTargetId(navItem);
            navItem.classList.toggle('settings-nav__item--active', target === targetId);
        });
    }

    function observeSections() {
        observer.disconnect();
        const seen = new Set();

        navItems.forEach(item => {
            const targetId = getTargetId(item);
            if (!targetId || seen.has(targetId)) {
                return;
            }

            const sentinel = document.getElementById(targetId);
            if (sentinel) {
                observer.observe(sentinel);
                seen.add(targetId);
            }
        });

        const firstTarget = getTargetId(navItems[0]);
        if (firstTarget) {
            setActive(firstTarget);
        }
    }

    navItems.forEach(item => {
        item.addEventListener('click', (event) => {
            event.preventDefault();
            const targetId = getTargetId(item);
            if (!targetId) {
                return;
            }

            const sentinel = document.getElementById(targetId);
            if (!sentinel) {
                return;
            }

            const scrollTargetId = sentinel.dataset.scrollTarget;
            let targetElement = scrollTargetId ? document.getElementById(scrollTargetId) : sentinel;
            if (!targetElement || targetElement.offsetParent === null) {
                targetElement = sentinel;
            }

            targetElement.scrollIntoView({ behavior: 'smooth', block: 'start' });

            setActive(targetId);
        });
    });

    observeSections();

    document.addEventListener('advanced:subtab-changed', () => {
        observeSections();
    });

    document.addEventListener('tab:changed', (event) => {
        if (event.detail?.tab === 'advanced') {
            observeSections();
        }
    });
}
