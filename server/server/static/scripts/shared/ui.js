import { state } from './state.js';

let hideTimeout;

const BASE_MODAL_Z_INDEX = 1200;
const MODAL_STACK_INCREMENT = 50;

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
    if (modal) {
        modal.classList.remove('open');
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
    }
}

export function toggleJsonEditorExpansion(forceCollapse = false) {
    const container = document.getElementById('json-editor-container');
    const overlay = document.getElementById('json-editor-overlay');

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
    }

    updateGlobalScrollLock();
}
