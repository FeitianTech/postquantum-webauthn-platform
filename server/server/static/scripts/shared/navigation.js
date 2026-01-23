import { state } from './state.js';
import { updateJsonEditor } from '../advanced/json-editor.js';
import { dismissAllTransientMessages } from './status.js';

const HEADER_MOBILE_BREAKPOINT = 900;

let headerMenuControls = null;

function isMobileViewport() {
    if (typeof window === 'undefined') {
        return false;
    }
    return Number.isFinite(window.innerWidth) ? window.innerWidth <= HEADER_MOBILE_BREAKPOINT : false;
}

function getHeaderMenuControls() {
    return headerMenuControls;
}

function setBodyMenuState(open) {
    if (typeof document === 'undefined') {
        return;
    }
    const targets = [document.body, document.documentElement]
        .filter((element) => element instanceof HTMLElement);
    if (!targets.length) {
        return;
    }
    targets.forEach(target => {
        target.classList.toggle('header-menu-open', open);
    });
}

export function switchTab(tab, options = {}) {
    const { preserveScroll = false, preserveMessages = false } = options || {};

    if (!preserveMessages) {
        dismissAllTransientMessages();
    }

    const controls = getHeaderMenuControls();
    if (controls && typeof controls.close === 'function') {
        controls.close({ focusToggle: false, allowDesktop: true });
    }

    document.querySelectorAll('.tab-content').forEach(content => {
        content.classList.toggle('active', content.id === `${tab}-tab`);
    });

    document.querySelectorAll('.nav-tab').forEach(navTab => {
        navTab.classList.toggle('active', navTab.dataset.tab === tab);
    });

    if (tab === 'advanced') {
        updateJsonEditor();
    }

    if (!preserveScroll) {
        requestAnimationFrame(() => {
            if (typeof window.scrollTo === 'function') {
                try {
                    window.scrollTo({ top: 0, behavior: 'auto' });
                } catch (error) {
                    window.scrollTo(0, 0);
                }
            } else if (typeof document !== 'undefined') {
                if (document.documentElement) {
                    document.documentElement.scrollTop = 0;
                }
                if (document.body) {
                    document.body.scrollTop = 0;
                }
            }
        });
    }

    document.dispatchEvent(new CustomEvent('tab:changed', { detail: { tab } }));
}

export function initializeNavigationMenu() {
    if (headerMenuControls) {
        return headerMenuControls;
    }

    if (typeof document === 'undefined') {
        return null;
    }

    const header = document.querySelector('.header');
    if (!(header instanceof HTMLElement)) {
        return null;
    }

    const toggle = header.querySelector('[data-header-menu-toggle]');
    const navContainer = header.querySelector('[data-header-nav]');
    const overlay = header.querySelector('[data-header-overlay]');
    const nav = navContainer ? navContainer.querySelector('.nav-tabs') : null;

    if (!(toggle instanceof HTMLElement) || !(navContainer instanceof HTMLElement) || !(overlay instanceof HTMLElement) || !(nav instanceof HTMLElement)) {
        return null;
    }

    let open = false;

    const updateExpanded = nextState => {
        open = nextState;
        if (open) {
            header.classList.add('header--menu-open');
            toggle.setAttribute('aria-expanded', 'true');
            overlay.hidden = false;
            overlay.setAttribute('aria-hidden', 'false');
        } else {
            header.classList.remove('header--menu-open');
            toggle.setAttribute('aria-expanded', 'false');
            overlay.hidden = true;
            overlay.setAttribute('aria-hidden', 'true');
        }
        setBodyMenuState(open);
    };

    const controls = {
        open: () => {
            if (open || !isMobileViewport()) {
                return;
            }
            updateExpanded(true);
        },
        close: ({ focusToggle = false, allowDesktop = false } = {}) => {
            if (!open) {
                return;
            }
            if (!allowDesktop && !isMobileViewport()) {
                return;
            }
            updateExpanded(false);
            if (focusToggle && typeof toggle.focus === 'function') {
                toggle.focus();
            }
        },
        toggle: () => {
            if (open) {
                controls.close();
            } else {
                controls.open();
            }
        },
    };

    const handleToggleClick = event => {
        if (event) {
            event.preventDefault();
        }
        if (!isMobileViewport()) {
            return;
        }
        controls.toggle();
    };

    const handleOverlayClick = () => {
        controls.close({ focusToggle: true, allowDesktop: true });
    };

    const handleKeyDown = event => {
        if (!event || event.key !== 'Escape') {
            return;
        }
        controls.close({ focusToggle: true, allowDesktop: true });
    };

    const handleResize = () => {
        if (!isMobileViewport()) {
            controls.close({ focusToggle: false, allowDesktop: true });
        }
    };

    toggle.addEventListener('click', handleToggleClick);
    overlay.addEventListener('click', handleOverlayClick);
    document.addEventListener('keydown', handleKeyDown);

    const navTabs = Array.from(nav.querySelectorAll('.nav-tab'));
    navTabs.forEach(tab => {
        tab.addEventListener('click', () => {
            controls.close({ focusToggle: false, allowDesktop: true });
        });
    });

    if (typeof window !== 'undefined') {
        window.addEventListener('resize', handleResize);
        window.addEventListener('orientationchange', handleResize);
    }

    headerMenuControls = controls;
    return controls;
}

export function switchSubTab(subTab) {
    state.currentSubTab = subTab;

    dismissAllTransientMessages();

    document.querySelectorAll('.sub-tab').forEach(btn => {
        btn.classList.remove('active');
    });
    const button = document.getElementById(subTab + '-tab-btn');
    if (button) {
        button.classList.add('active');
    }

    document.querySelectorAll('.sub-tab-content').forEach(content => {
        content.classList.remove('active');
    });
    const form = document.getElementById(subTab + '-form');
    if (form) {
        form.classList.add('active');
    }

    document.querySelectorAll('.advanced-header__actions-group').forEach(group => {
        group.classList.toggle('active', group.dataset.subtab === subTab);
    });

    updateJsonEditor();

    document.dispatchEvent(new CustomEvent('advanced:subtab-changed', { detail: { subTab } }));
}

export function toggleSection(sectionId, eventOrElement) {
    const content = document.getElementById(sectionId);
    if (!content) {
        return;
    }

    let header = null;

    if (eventOrElement) {
        if (eventOrElement.currentTarget instanceof HTMLElement) {
            header = eventOrElement.currentTarget;
        } else if (eventOrElement.target instanceof Element) {
            header = eventOrElement.target.closest('.section-header');
        } else if (eventOrElement instanceof HTMLElement) {
            header = eventOrElement;
        }
    }

    if (!header) {
        const previous = content.previousElementSibling;
        if (previous instanceof HTMLElement && previous.classList.contains('section-header')) {
            header = previous;
        }
    }

    if (!header && content.parentElement) {
        const candidate = content.parentElement.querySelector('.section-header');
        if (candidate instanceof HTMLElement) {
            header = candidate;
        }
    }

    if (!header) {
        const headers = document.querySelectorAll('.section-header');
        for (const element of headers) {
            const handler = element.getAttribute('onclick') || '';
            if (handler.includes(`toggleSection('${sectionId}'`) || handler.includes(`toggleSection("${sectionId}"`)) {
                header = element;
                break;
            }
        }
    }

    const icon = header ? header.querySelector('.expand-icon') : null;

    if (content.classList.contains('expanded')) {
        content.classList.remove('expanded');
        if (header) {
            header.classList.remove('expanded');
        }
        if (icon) {
            icon.classList.remove('rotated');
        }
    } else {
        content.classList.add('expanded');
        if (header) {
            header.classList.add('expanded');
        }
        if (icon) {
            icon.classList.add('rotated');
        }
    }
}
