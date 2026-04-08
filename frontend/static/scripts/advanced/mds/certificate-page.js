export async function openCertificatePageInState(state, certificate, sourceButton = null, deps = {}) {
    if (!state?.certificatePage) {
        return;
    }

    const {
        normaliseCertificateBase64,
        decodeCertificate,
        setCertificateFieldContent,
        formatCertificateInput,
        formatCertificateOutput,
        setCertificateSummaryContent,
        renderCertificateSummary,
        hideScrollTopButton,
        suppressListSection,
        notifyGlobalScrollLock,
        resetScrollPositions,
        scheduleCertificateTextareaResize,
        beginCertificateLoadingCursor,
        endCertificateLoadingCursor,
    } = deps;

    const cleaned = normaliseCertificateBase64(certificate);
    if (!cleaned) {
        return;
    }

    const triggerButton = sourceButton instanceof HTMLButtonElement ? sourceButton : null;

    if (triggerButton) {
        triggerButton.classList.add('is-loading');
        triggerButton.setAttribute('aria-busy', 'true');
        triggerButton.disabled = true;
    }

    beginCertificateLoadingCursor();

    let details = null;
    let decodeError = null;
    try {
        details = await decodeCertificate(cleaned);
    } catch (error) {
        decodeError = error;
    } finally {
        endCertificateLoadingCursor();
        if (triggerButton) {
            triggerButton.classList.remove('is-loading');
            triggerButton.removeAttribute('aria-busy');
            triggerButton.disabled = false;
        }
    }

    if (state.certificateInput) {
        setCertificateFieldContent(state.certificateInput, formatCertificateInput(cleaned));
        state.certificateInput.scrollTop = 0;
        state.certificateInput.scrollLeft = 0;
    }

    if (decodeError) {
        const message = decodeError instanceof Error ? decodeError.message : 'Unable to decode certificate.';
        if (state.certificateOutput) {
            setCertificateFieldContent(state.certificateOutput, message);
            state.certificateOutput.scrollTop = 0;
            state.certificateOutput.scrollLeft = 0;
        }
        setCertificateSummaryContent(message);
        if (state.certificateTitle) {
            state.certificateTitle.textContent = 'Attestation Certificate';
        }
        if (state.certificateSubtitle) {
            state.certificateSubtitle.textContent = '';
            state.certificateSubtitle.hidden = true;
        }
    } else {
        if (state.certificateOutput) {
            setCertificateFieldContent(state.certificateOutput, formatCertificateOutput(details));
            state.certificateOutput.scrollTop = 0;
            state.certificateOutput.scrollLeft = 0;
        }
        const summaryContent = renderCertificateSummary(details);
        if (summaryContent) {
            setCertificateSummaryContent(summaryContent);
        } else {
            setCertificateSummaryContent('No decoded certificate details available.');
        }
        const subject = details && typeof details.subject === 'string' ? details.subject.trim() : '';
        if (state.certificateTitle) {
            state.certificateTitle.textContent = subject || 'Attestation Certificate';
        }
        const issuer = details && typeof details.issuer === 'string' ? details.issuer.trim() : '';
        if (state.certificateSubtitle) {
            if (issuer) {
                state.certificateSubtitle.textContent = issuer;
                state.certificateSubtitle.hidden = false;
            } else {
                state.certificateSubtitle.textContent = '';
                state.certificateSubtitle.hidden = true;
            }
        }
    }

    hideScrollTopButton();

    const sticky = state.certificateStickyHeader || null;
    const authenticatorSticky = state.authenticatorStickyHeader || null;

    if (authenticatorSticky) {
        authenticatorSticky.prepareForClose?.();
        authenticatorSticky.hide();
    }

    if (sticky) {
        sticky.show();
    }

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

    const page = state.certificatePage;
    page.classList.remove('mds-detail-page--open');
    page.classList.remove('mds-detail-page--closing');
    page.hidden = false;
    page.setAttribute('aria-hidden', 'false');

    const activatePage = () => {
        if (page.hidden) {
            return;
        }
        page.classList.add('mds-detail-page--open');
        notifyGlobalScrollLock();
    };
    if (typeof requestAnimationFrame === 'function') {
        requestAnimationFrame(activatePage);
    } else {
        activatePage();
    }

    resetScrollPositions(
        state.certificatePageBody,
        page,
        state.certificateSummary,
        state.certificateInput,
        state.certificateOutput,
    );
    scheduleCertificateTextareaResize(state);

    const focusTarget = state.certificateClose instanceof HTMLElement ? state.certificateClose : null;
    if (focusTarget) {
        requestAnimationFrame(() => focusTarget.focus());
    }

    sticky?.sync();
}

export function closeCertificatePageInState(state, deps = {}) {
    if (!state?.certificatePage) {
        return;
    }

    const {
        restoreListSection,
        resetScrollPositions,
        resetCertificateTextareaHeights,
        notifyGlobalScrollLock,
        scheduleScrollTopButtonUpdate,
    } = deps;

    const page = state.certificatePage;
    if (page.hidden) {
        return;
    }

    const sticky = state.certificateStickyHeader || null;

    const previousScroll =
        typeof state.listScrollTop === 'number' ? state.listScrollTop : null;

    const clearSubtitle = () => {
        if (state.certificateSubtitle) {
            state.certificateSubtitle.textContent = '';
            state.certificateSubtitle.hidden = true;
        }
    };

    const finishClose = () => {
        page.hidden = true;
        page.setAttribute('aria-hidden', 'true');
        page.classList.remove('mds-detail-page--closing');
        resetScrollPositions(
            state.certificatePageBody,
            page,
            state.certificateSummary,
            state.certificateInput,
            state.certificateOutput,
        );
        resetCertificateTextareaHeights(state);
        clearSubtitle();
        notifyGlobalScrollLock();
        restoreListSection(state.listSection);
        scheduleScrollTopButtonUpdate();
        sticky?.hide();

        if (state?.authenticatorModal && !state.authenticatorModal.hidden) {
            const authenticatorSticky = state.authenticatorStickyHeader || null;
            if (authenticatorSticky) {
                authenticatorSticky.show();
                authenticatorSticky.sync?.();
            }
        }
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
        page.classList.remove('mds-detail-page--open');
        page.classList.add('mds-detail-page--closing');
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
            if (event?.target !== page) {
                return;
            }
            page.removeEventListener('transitionend', handleTransitionEnd);
            clear();
            finishClose();
        };

        page.addEventListener('transitionend', handleTransitionEnd);
        timeoutId = scheduleTimeout(() => {
            page.removeEventListener('transitionend', handleTransitionEnd);
            clear();
            finishClose();
        }, 500);
    };

    beginClose();
}
