import {
    finaliseHighlightedAuthenticatorRowInState,
    focusAuthenticatorByAaguidInState,
    highlightAuthenticatorRowByAaguidInState,
    openAuthenticatorModalByAaguidInState,
    resolveEntryByAaguidInState,
} from './authenticator-navigation.js';

export function createAuthenticatorNavigationAdapters(config = {}) {
    const {
        waitForStateReady,
        getState,
        normaliseAaguid,
        isLoading,
        loadPromise,
        hasInlineDetail,
        resolveMetadataEntry,
        openAuthenticatorModal,
        resetFilters,
        showAuthenticatorDetail,
        hideAuthenticatorDetail,
        waitForElementVisible,
        applyFilters,
        waitForLayoutSettled,
        waitForRowByKey,
        setHighlightedRow,
    } = config;

    async function resolveEntryByAaguid(aaguid) {
        return resolveEntryByAaguidInState(aaguid, {
            waitForStateReady,
            getState,
            normaliseAaguid,
            isLoading,
            loadPromise,
            hasInlineDetail,
            resolveMetadataEntry,
        });
    }

    async function openAuthenticatorModalByAaguid(aaguid) {
        return openAuthenticatorModalByAaguidInState(aaguid, {
            resolveEntryByAaguid,
            openAuthenticatorModal,
        });
    }

    async function focusAuthenticatorByAaguid(aaguid) {
        return focusAuthenticatorByAaguidInState(aaguid, {
            resolveEntryByAaguid,
            resetFilters,
            showAuthenticatorDetail,
        });
    }

    async function highlightAuthenticatorRowByAaguid(aaguid, options = {}) {
        return highlightAuthenticatorRowByAaguidInState(aaguid, options, {
            resolveEntryByAaguid,
            getState,
            normaliseAaguid,
            hideAuthenticatorDetail,
            waitForElementVisible,
            resetFilters,
            applyFilters,
            waitForLayoutSettled,
            waitForRowByKey,
            setHighlightedRow,
        });
    }

    function finaliseHighlightedAuthenticatorRow(options = {}) {
        return finaliseHighlightedAuthenticatorRowInState(options, {
            getState,
            setHighlightedRow,
        });
    }

    return {
        resolveEntryByAaguid,
        openAuthenticatorModalByAaguid,
        focusAuthenticatorByAaguid,
        highlightAuthenticatorRowByAaguid,
        finaliseHighlightedAuthenticatorRow,
    };
}
