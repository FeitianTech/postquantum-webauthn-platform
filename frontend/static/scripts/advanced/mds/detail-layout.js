export function notifyGlobalScrollLock() {
    if (typeof window !== 'undefined' && typeof window.updateGlobalScrollLock === 'function') {
        window.updateGlobalScrollLock();
        return;
    }

    if (typeof document === 'undefined') {
        return;
    }

    const overlayActive = document.getElementById('json-editor-overlay')?.classList.contains('active');
    const modalActive = document.querySelector('.modal.open');
    const mdsModalActive = document.querySelector('.mds-modal:not([hidden])');
    const detailPageActive = document.querySelector('.mds-detail-page.mds-detail-page--open');
    const shouldLock = Boolean(overlayActive || modalActive || mdsModalActive || detailPageActive);

    const targets = [document.body, document.documentElement].filter(Boolean);
    targets.forEach(target => target.classList.toggle('modal-open', shouldLock));
}

export function resizeCertificateTextareas(state) {
    if (!state) {
        return;
    }

    const fields = [state.certificateInput, state.certificateOutput];
    fields.forEach(field => {
        if (!(field instanceof HTMLElement)) {
            return;
        }
        if (field instanceof HTMLTextAreaElement) {
            field.style.height = 'auto';
            field.style.overflowY = 'hidden';
            field.style.overflowX = 'hidden';
            const { scrollHeight } = field;
            if (Number.isFinite(scrollHeight)) {
                field.style.height = `${scrollHeight}px`;
            }
            return;
        }

        field.style.removeProperty('height');
    });
}

export function scheduleCertificateTextareaResize(state) {
    const adjust = () => resizeCertificateTextareas(state);
    if (typeof requestAnimationFrame === 'function') {
        requestAnimationFrame(() => requestAnimationFrame(adjust));
    } else {
        setTimeout(adjust, 0);
    }
}

export function resetCertificateTextareaHeights(state) {
    if (!state) {
        return;
    }
    [state.certificateInput, state.certificateOutput].forEach(field => {
        if (field instanceof HTMLElement) {
            field.style.height = '';
        }
    });
}

export function suppressListSection(section) {
    if (!section) {
        return;
    }
    if (!('mdsDetailVisibility' in section.dataset)) {
        section.dataset.mdsDetailVisibility = section.style.visibility || '';
    }
    if (!('mdsDetailPointerEvents' in section.dataset)) {
        section.dataset.mdsDetailPointerEvents = section.style.pointerEvents || '';
    }
    if (!('mdsDetailUserSelect' in section.dataset)) {
        section.dataset.mdsDetailUserSelect = section.style.userSelect || '';
    }
    section.setAttribute('aria-hidden', 'true');
    section.style.visibility = 'hidden';
    section.style.pointerEvents = 'none';
    section.style.userSelect = 'none';
}

export function restoreListSection(section) {
    if (!section) {
        return;
    }
    section.removeAttribute('aria-hidden');
    const toCssProperty = name => name.replace(/[A-Z]/g, match => `-${match.toLowerCase()}`);
    const apply = (property, key) => {
        const value = section.dataset[key];
        if (value !== undefined && value !== null && value !== '') {
            section.style[property] = value;
        } else {
            section.style[property] = '';
            section.style.removeProperty(toCssProperty(property));
        }
        delete section.dataset[key];
    };
    apply('visibility', 'mdsDetailVisibility');
    apply('pointerEvents', 'mdsDetailPointerEvents');
    apply('userSelect', 'mdsDetailUserSelect');
}
