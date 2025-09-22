import { state } from './state.js';

let hideTimeout;

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
    const shouldLock = Boolean(overlayActive || modalActive || mdsModalActive);

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
        modal.classList.add('open');
        requestAnimationFrame(() => resetModalScroll(modal));
        updateGlobalScrollLock();
    }
}

export function closeModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) {
        modal.classList.remove('open');
        requestAnimationFrame(() => resetModalScroll(modal));
        updateGlobalScrollLock();
    }
}

export function toggleJsonEditorExpansion(forceCollapse = false) {
    const container = document.getElementById('json-editor-container');
    const overlay = document.getElementById('json-editor-overlay');
    const toggleButton = document.getElementById('json-editor-expand');

    if (!container || !overlay || !toggleButton) {
        return;
    }

    const shouldExpand = forceCollapse ? false : !container.classList.contains('expanded');

    if (shouldExpand) {
        container.classList.add('expanded');
        overlay.classList.add('active');
        toggleButton.innerHTML = '<span aria-hidden="true">✕</span>';
        toggleButton.setAttribute('aria-label', 'Close expanded JSON editor');
        toggleButton.setAttribute('title', 'Close expanded JSON editor');
        toggleButton.setAttribute('aria-expanded', 'true');
        const editor = document.getElementById('json-editor');
        if (editor) {
            editor.scrollTop = 0;
        }
    } else {
        container.classList.remove('expanded');
        overlay.classList.remove('active');
        toggleButton.innerHTML = '<span aria-hidden="true">⛶</span>';
        toggleButton.setAttribute('aria-label', 'Expand JSON editor');
        toggleButton.setAttribute('title', 'Expand JSON editor');
        toggleButton.setAttribute('aria-expanded', 'false');
    }

    updateGlobalScrollLock();
}
