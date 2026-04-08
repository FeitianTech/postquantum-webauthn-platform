import { COLUMN_COUNT } from '../mds-constants.js';
import { normaliseAaguid, renderCertificateSummary } from '../mds-utils.js';
import { buildDetailContent } from './detail-content.js';
import { formatDetailSubtitle } from './detail-user-sections.js';
import { getAuthenticatorRawData } from './raw-data.js';
import { stringifyAuthenticatorRawData } from './raw-stringify.js';
import { openAuthenticatorRawWindow as openAuthenticatorRawDataWindow } from './raw-window.js';
import {
    createIconCell as createIconCellFromModule,
    createIdCell as createIdCellFromModule,
    createNameCell as createNameCellFromModule,
    createTagCell as createTagCellFromModule,
    createTextCell as createTextCellFromModule,
} from './table-cells.js';
import {
    applyCertificateLoadingCursorVisibility as applyCertificateLoadingCursorVisibilityByCount,
    formatCertificateInput as formatCertificateInputValue,
    formatCertificateOutput as formatCertificateOutputValue,
    setCertificateFieldContent as setCertificateFieldContentValue,
    setCertificateSummaryContent as setCertificateSummaryContentInState,
} from './certificate-utils.js';
import {
    closeCertificatePageInState,
    openCertificatePageInState,
} from './certificate-page.js';
import {
    closeAuthenticatorModalInState,
    openAuthenticatorModalInState,
    openAuthenticatorRawWindowInState,
    updateAuthenticatorRawButtonInState,
} from './authenticator-modal.js';
import {
    applyRowHighlightByKey as applyRowHighlightByKeyInState,
    clearRowHighlight as clearRowHighlightInState,
    findRowByKey as findRowByKeyInState,
    hideAuthenticatorDetail as hideAuthenticatorDetailInState,
    isElementVisible as isElementVisibleInDom,
    showAuthenticatorDetail as showAuthenticatorDetailInState,
    waitForElementVisible as waitForElementVisibleInDom,
} from './row-highlight.js';
import {
    notifyGlobalScrollLock,
    resetCertificateTextareaHeights,
    restoreListSection,
    scheduleCertificateTextareaResize,
    suppressListSection,
} from './detail-layout.js';
import { renderMdsTable } from './table-render.js';
import { createMdsDetailViewAdapters } from './runtime-detail-view-adapters.js';

const MDS_CERTIFICATE_LOADING_CURSOR_CLASS = 'mds-certificate-loading-cursor';

export function createDetailRuntime({
    getState,
    getMdsData,
    hasInlineDetail,
    resolveMetadataEntry,
    normaliseCertificateBase64,
    decodeCertificate,
    hideScrollTopButton,
    scheduleScrollTopButtonUpdate,
    scrollRowIntoView,
    setHighlightedRow,
    stabiliseColumnWidths,
    scheduleColumnResizerMetricsUpdate,
    scheduleHorizontalScrollMetricsUpdate,
    scheduleRowHeightLock,
}) {
    const createTextCell = (text, title) => createTextCellFromModule(text, title);
    const createIdCell = id => createIdCellFromModule(id);
    const createIconCell = entry => createIconCellFromModule(entry);
    const createTagCell = (items, neutral = false) => createTagCellFromModule(items, neutral);
    const createNameCell = entry =>
        createNameCellFromModule(entry, {
            onShowAuthenticatorDetail: selectedEntry => {
                showAuthenticatorDetail(selectedEntry);
            },
        });

    const {
        renderTable,
        applyDetailHeader,
        populateDetailContent,
        resetScrollPositions,
        clearRowHighlight,
        findRowByKey,
        applyRowHighlightByKey,
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
        openAuthenticatorModal,
        closeAuthenticatorModal,
    } = createMdsDetailViewAdapters({
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
        formatCertificateInput: formatCertificateInputValue,
        formatCertificateOutput: formatCertificateOutputValue,
        setCertificateSummaryContentInState,
        setCertificateFieldContentValue,
        applyCertificateLoadingCursorVisibilityByCount,
        mdsCertificateLoadingCursorClass: MDS_CERTIFICATE_LOADING_CURSOR_CLASS,
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
        columnCount: COLUMN_COUNT,
        decodeCertificate,
        resolveMetadataEntry,
    });

    return {
        renderTable,
        applyDetailHeader,
        populateDetailContent,
        resetScrollPositions,
        clearRowHighlight,
        findRowByKey,
        applyRowHighlightByKey,
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
        openAuthenticatorModal,
        closeAuthenticatorModal,
    };
}
