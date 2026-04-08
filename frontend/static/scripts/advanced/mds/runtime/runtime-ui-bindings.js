import { normaliseAaguid } from '../../mds-utils.js';
import { hasInlineDetail as hasInlineDetailValue } from '../metadata/metadata-helpers.js';
import { createDetailRuntime } from './runtime-detail-runtime.js';
import { createAuthenticatorNavigationAdapters } from './runtime-authenticator-navigation-adapters.js';

export function createUiRuntimeBindings({
    getState,
    getMdsData,
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
    waitForStateReady,
    isLoading,
    loadPromise,
    resetFilters,
    applyFilters,
    waitForLayoutSettled,
    waitForRowByKey,
}) {
    const detailBindings = createDetailRuntime({
        getState,
        getMdsData,
        hasInlineDetail: hasInlineDetailValue,
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
    });

    const navigationBindings = createAuthenticatorNavigationAdapters({
        waitForStateReady,
        getState,
        normaliseAaguid,
        isLoading,
        loadPromise,
        hasInlineDetail: hasInlineDetailValue,
        resolveMetadataEntry,
        openAuthenticatorModal: detailBindings.openAuthenticatorModal,
        resetFilters,
        showAuthenticatorDetail: detailBindings.showAuthenticatorDetail,
        hideAuthenticatorDetail: detailBindings.hideAuthenticatorDetail,
        waitForElementVisible: detailBindings.waitForElementVisible,
        applyFilters,
        waitForLayoutSettled,
        waitForRowByKey,
        setHighlightedRow,
    });

    return {
        ...detailBindings,
        ...navigationBindings,
    };
}
