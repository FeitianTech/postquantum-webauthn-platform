export function openAuthenticatorRawWindowInState(state, deps = {}) {
    const {
        openAuthenticatorRawDataWindow,
        formatDetailSubtitle,
        getAuthenticatorRawData,
        stringifyAuthenticatorRawData,
    } = deps;

    openAuthenticatorRawDataWindow({
        state,
        formatDetailSubtitle,
        getAuthenticatorRawData,
        stringifyAuthenticatorRawData,
    });
}

export function updateAuthenticatorRawButtonInState(state, entry, deps = {}) {
    const { getAuthenticatorRawData } = deps;

    const button = state?.authenticatorModalRawButton;
    if (!(button instanceof HTMLButtonElement)) {
        return;
    }

    const rawData = getAuthenticatorRawData(entry);
    const hasRawData = rawData && typeof rawData === 'object' && Object.keys(rawData).length > 0;

    button.disabled = !hasRawData;
    button.setAttribute('aria-disabled', hasRawData ? 'false' : 'true');
    button.setAttribute('title', hasRawData ? 'View raw authenticator data' : 'Raw authenticator data unavailable');
    if (hasRawData) {
        button.removeAttribute('tabindex');
    } else {
        button.setAttribute('tabindex', '-1');
    }

    state?.authenticatorStickyHeader?.sync();
}

export async function openAuthenticatorModalInState(state, entry, deps = {}) {
    if (!state?.authenticatorModal) {
        return;
    }

    const {
        hasInlineDetail,
        normaliseAaguid,
        resolveMetadataEntry,
        hideScrollTopButton,
        updateAuthenticatorRawButton,
        applyDetailHeader,
        populateDetailContent,
        suppressListSection,
        notifyGlobalScrollLock,
        resetScrollPositions,
    } = deps;

    if (entry && !hasInlineDetail(entry)) {
        const query = {};
        if (typeof entry.entryId === 'string' && entry.entryId) {
            query.entryId = entry.entryId;
        } else if (typeof entry.aaguid === 'string' && entry.aaguid) {
            query.aaguid = normaliseAaguid(entry.aaguid);
        } else if (typeof entry.id === 'string' && entry.id) {
            query.aaid = entry.id;
        }

        try {
            const resolved = await resolveMetadataEntry(query);
            if (resolved) {
                entry = resolved;
            }
        } catch (error) {
            console.warn('Failed to resolve full authenticator metadata entry.', error);
        }
    }

    const modal = state.authenticatorModal;
    const sticky = state.authenticatorStickyHeader || null;
    const certificateSticky = state.certificateStickyHeader || null;

    if (state?.certificatePage && !state.certificatePage.hidden && certificateSticky) {
        certificateSticky.prepareForClose?.();
        certificateSticky.hide();
    }

    if (entry) {
        state.activeDetailEntry = entry;
    }
    const detailEntry = state.activeDetailEntry || entry || null;
    hideScrollTopButton();

    updateAuthenticatorRawButton(detailEntry);

    applyDetailHeader(detailEntry, state.authenticatorModalTitle, state.authenticatorModalSubtitle);
    populateDetailContent(state.authenticatorModalContent, detailEntry);
    sticky?.sync();

    let currentScroll = 0;
    if (typeof window !== 'undefined') {
        currentScroll =
            window.pageYOffset ||
            document.documentElement?.scrollTop ||
            document.body?.scrollTop ||
            0;
    }
    state.listScrollTop = currentScroll;

    suppressListSection(state.listSection);

    modal.classList.remove('mds-detail-page--open');
    modal.classList.remove('mds-detail-page--closing');
    modal.hidden = false;
    modal.setAttribute('aria-hidden', 'false');
    if (sticky) {
        sticky.show();
    }
    const activateModal = () => {
        if (modal.hidden) {
            return;
        }
        modal.classList.add('mds-detail-page--open');
        notifyGlobalScrollLock();
    };
    if (typeof requestAnimationFrame === 'function') {
        requestAnimationFrame(activateModal);
    } else {
        activateModal();
    }

    resetScrollPositions(state.authenticatorModalBody, modal, state.authenticatorModalContent);

    const focusTarget = state.authenticatorModalClose instanceof HTMLElement
        ? state.authenticatorModalClose
        : null;
    if (focusTarget) {
        requestAnimationFrame(() => {
            focusTarget.focus();
        });
    }
}

export function closeAuthenticatorModalInState(state, deps = {}) {
    if (!state?.authenticatorModal) {
        return;
    }

    const {
        restoreListSection,
        resetScrollPositions,
        notifyGlobalScrollLock,
        scheduleScrollTopButtonUpdate,
        updateAuthenticatorRawButton,
    } = deps;

    const modal = state.authenticatorModal;
    const sticky = state.authenticatorStickyHeader || null;

    if (modal.hidden) {
        return;
    }

    const previousScroll =
        typeof state.listScrollTop === 'number' ? state.listScrollTop : null;

    const finishClose = () => {
        modal.hidden = true;
        modal.setAttribute('aria-hidden', 'true');
        modal.classList.remove('mds-detail-page--closing');

        restoreListSection(state.listSection);

        resetScrollPositions(state.authenticatorModalBody, modal, state.authenticatorModalContent);
        notifyGlobalScrollLock();
        state.activeDetailEntry = null;
        updateAuthenticatorRawButton(null);
        sticky?.hide();
        scheduleScrollTopButtonUpdate();
        if (previousScroll !== null && typeof window !== 'undefined') {
            requestAnimationFrame(() => {
                window.scrollTo(0, previousScroll);
            });
        }
        state.listScrollTop = null;
    };

    const beginClose = () => {
        restoreListSection(state.listSection);
        if (typeof requestAnimationFrame === 'function') {
            requestAnimationFrame(() => restoreListSection(state.listSection));
        }
        modal.classList.remove('mds-detail-page--open');
        modal.classList.add('mds-detail-page--closing');
        sticky?.prepareForClose();

        const scheduleTimeout =
            typeof window !== 'undefined' && typeof window.setTimeout === 'function'
                ? window.setTimeout.bind(window)
                : setTimeout;
        const cancelTimeout =
            typeof window !== 'undefined' && typeof window.clearTimeout === 'function'
                ? window.clearTimeout.bind(window)
                : clearTimeout;

        let timeoutId = null;
        const clear = () => {
            if (timeoutId !== null) {
                cancelTimeout(timeoutId);
                timeoutId = null;
            }
        };

        const handleTransitionEnd = event => {
            if (event?.target !== modal) {
                return;
            }
            modal.removeEventListener('transitionend', handleTransitionEnd);
            clear();
            finishClose();
        };

        modal.addEventListener('transitionend', handleTransitionEnd);
        timeoutId = scheduleTimeout(() => {
            modal.removeEventListener('transitionend', handleTransitionEnd);
            clear();
            finishClose();
        }, 500);
    };

    beginClose();
}
