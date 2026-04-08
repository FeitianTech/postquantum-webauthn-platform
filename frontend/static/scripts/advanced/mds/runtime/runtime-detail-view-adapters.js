export function createMdsDetailViewAdapters(config = {}) {
    const {
        getState,
        getMdsData,
        normaliseAaguid,
        hasInlineDetail,
        formatDetailSubtitle,
        buildDetailContent,
        clearRowHighlightInState,
        findRowByKeyInState,
        applyRowHighlightByKeyInState,
        isElementVisibleInDom,
        waitForElementVisibleInDom,
        showAuthenticatorDetailInState,
        hideAuthenticatorDetailInState,
        normaliseCertificateBase64,
        formatCertificateInput,
        formatCertificateOutput,
        setCertificateSummaryContentInState,
        setCertificateFieldContentValue,
        applyCertificateLoadingCursorVisibilityByCount,
        mdsCertificateLoadingCursorClass,
        openCertificatePageInState,
        closeCertificatePageInState,
        openAuthenticatorRawWindowInState,
        updateAuthenticatorRawButtonInState,
        openAuthenticatorModalInState,
        closeAuthenticatorModalInState,
        openAuthenticatorRawDataWindow,
        getAuthenticatorRawData,
        stringifyAuthenticatorRawData,
        hideScrollTopButton,
        suppressListSection,
        notifyGlobalScrollLock,
        restoreListSection,
        scheduleCertificateTextareaResize,
        resetCertificateTextareaHeights,
        scheduleScrollTopButtonUpdate,
        scrollRowIntoView,
        setHighlightedRow,
        renderMdsTable,
        createIconCell,
        createNameCell,
        createTextCell,
        createIdCell,
        createTagCell,
        stabiliseColumnWidths,
        scheduleColumnResizerMetricsUpdate,
        scheduleHorizontalScrollMetricsUpdate,
        scheduleRowHeightLock,
        renderCertificateSummary,
        columnCount,
        decodeCertificate,
        resolveMetadataEntry,
    } = config;

    let certificateCursorRequestCount = 0;

    function renderTable(entries, options = {}) {
        return renderMdsTable(getState(), entries, options, {
            COLUMN_COUNT: columnCount,
            normaliseAaguid,
            createIconCell,
            createNameCell,
            createTextCell,
            createIdCell,
            createTagCell,
            hideScrollTopButton,
            stabiliseColumnWidths,
            scheduleColumnResizerMetricsUpdate,
            resetScrollPositions,
            scheduleHorizontalScrollMetricsUpdate,
            applyRowHighlightByKey: applyRowHighlightByKeyProxy,
            scheduleScrollTopButtonUpdate,
            scheduleRowHeightLock,
        });
    }

    function applyDetailHeader(entry, titleEl, subtitleEl) {
        if (titleEl) {
            titleEl.textContent = entry?.name?.trim() ? entry.name : 'Authenticator';
        }
        if (subtitleEl) {
            subtitleEl.textContent = formatDetailSubtitle(entry);
        }

        getState()?.authenticatorStickyHeader?.sync();
    }

    function populateDetailContent(target, entry) {
        if (!target) {
            return;
        }
        target.innerHTML = '';
        const content = buildDetailContent(entry, {
            onOpenCertificatePage: openCertificatePage,
        });
        if (content) {
            target.appendChild(content);
        }
    }

    function resetScrollPositions(...elements) {
        const apply = element => {
            if (!element) {
                return;
            }
            if (typeof element.scrollTo === 'function') {
                element.scrollTo({ top: 0, left: 0 });
                return;
            }
            if (typeof element.scrollTop === 'number') {
                element.scrollTop = 0;
            }
            if (typeof element.scrollLeft === 'number') {
                element.scrollLeft = 0;
            }
        };

        elements.forEach(apply);
        if (typeof requestAnimationFrame === 'function') {
            requestAnimationFrame(() => {
                elements.forEach(apply);
            });
        }
    }

    function clearRowHighlight() {
        return clearRowHighlightInState(getState());
    }

    function findRowByKey(key) {
        return findRowByKeyInState(getState(), key);
    }

    function applyRowHighlightByKeyProxy(key, options = {}) {
        return applyRowHighlightByKeyInState(getState(), key, setHighlightedRow, options);
    }

    function isElementVisible(element) {
        return isElementVisibleInDom(element);
    }

    function waitForElementVisible(element, { timeout = 2000, interval = 32 } = {}) {
        return waitForElementVisibleInDom(element, { timeout, interval });
    }

    function showAuthenticatorDetail(entry, options = {}) {
        return showAuthenticatorDetailInState({
            state: getState(),
            entry,
            options,
            mdsData: getMdsData(),
            normaliseAaguid,
            clearRowHighlight: clearRowHighlightInState,
            findRowByKey: findRowByKeyInState,
            scrollRowIntoView,
            openAuthenticatorModal: openAuthenticatorModalProxy,
        });
    }

    function hideAuthenticatorDetail() {
        return hideAuthenticatorDetailInState({
            state: getState(),
            closeAuthenticatorModal: closeAuthenticatorModalProxy,
        });
    }

    function setCertificateSummaryContent(content) {
        return setCertificateSummaryContentInState(getState(), content);
    }

    function setCertificateFieldContent(field, value) {
        return setCertificateFieldContentValue(field, value);
    }

    function applyCertificateLoadingCursorVisibility() {
        return applyCertificateLoadingCursorVisibilityByCount(
            certificateCursorRequestCount,
            mdsCertificateLoadingCursorClass,
        );
    }

    function beginCertificateLoadingCursor() {
        certificateCursorRequestCount += 1;
        applyCertificateLoadingCursorVisibility();
    }

    function endCertificateLoadingCursor() {
        certificateCursorRequestCount = Math.max(0, certificateCursorRequestCount - 1);
        applyCertificateLoadingCursorVisibility();
    }

    async function openCertificatePage(certificate, sourceButton = null) {
        return openCertificatePageInState(getState(), certificate, sourceButton, {
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
        });
    }

    function closeCertificatePage() {
        return closeCertificatePageInState(getState(), {
            restoreListSection,
            resetScrollPositions,
            resetCertificateTextareaHeights,
            notifyGlobalScrollLock,
            scheduleScrollTopButtonUpdate,
        });
    }

    function openAuthenticatorRawWindow() {
        return openAuthenticatorRawWindowInState(getState(), {
            openAuthenticatorRawDataWindow,
            formatDetailSubtitle,
            getAuthenticatorRawData,
            stringifyAuthenticatorRawData,
        });
    }

    function updateAuthenticatorRawButton(entry) {
        return updateAuthenticatorRawButtonInState(getState(), entry, {
            getAuthenticatorRawData,
        });
    }

    async function openAuthenticatorModalProxy(entry) {
        return openAuthenticatorModalInState(getState(), entry, {
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
        });
    }

    function closeAuthenticatorModalProxy() {
        return closeAuthenticatorModalInState(getState(), {
            restoreListSection,
            resetScrollPositions,
            notifyGlobalScrollLock,
            scheduleScrollTopButtonUpdate,
            updateAuthenticatorRawButton,
        });
    }

    return {
        renderTable,
        applyDetailHeader,
        populateDetailContent,
        resetScrollPositions,
        clearRowHighlight,
        findRowByKey,
        applyRowHighlightByKey: applyRowHighlightByKeyProxy,
        isElementVisible,
        waitForElementVisible,
        showAuthenticatorDetail,
        hideAuthenticatorDetail,
        setCertificateSummaryContent,
        setCertificateFieldContent,
        applyCertificateLoadingCursorVisibility,
        beginCertificateLoadingCursor,
        endCertificateLoadingCursor,
        openCertificatePage,
        closeCertificatePage,
        openAuthenticatorRawWindow,
        updateAuthenticatorRawButton,
        openAuthenticatorModal: openAuthenticatorModalProxy,
        closeAuthenticatorModal: closeAuthenticatorModalProxy,
    };
}
