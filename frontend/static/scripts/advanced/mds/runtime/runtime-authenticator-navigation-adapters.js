import {
    finaliseHighlightedAuthenticatorRowInState,
    highlightAuthenticatorRowByAaguidInState,
    resolveEntryByAaguidInState,
} from '../authenticator-navigation.js';

export function createAuthenticatorNavigationAdapters(config = {}) {
    const {
        waitForStateReady,
        getState,
        normaliseAaguid,
        isLoading,
        loadPromise,
        hasInlineDetail,
        resolveMetadataEntry,
        resetFilters,
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
        highlightAuthenticatorRowByAaguid,
        finaliseHighlightedAuthenticatorRow,
    };
}
