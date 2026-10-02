// Where the explorer's entries come from and what an answer means. No DOM.
import { MDS_EXPLORER_FULL_PATH, MDS_INFO_PATH, MISSING_METADATA_MESSAGE } from '../constants.js';

/** @param {any} error */
function isAbortError(error) {
    return Boolean(error && error.name === 'AbortError');
}

export function hasInlineDetail(entry) {
    return Boolean(
        entry
        && typeof entry === 'object'
        && entry.isLightweightEntry !== true
        && entry.metadataStatement
        && typeof entry.metadataStatement === 'object',
    );
}

export function cloneMetadataEntry(entry) {
    if (!entry || typeof entry !== 'object') {
        return null;
    }
    return structuredClone(entry);
}

async function fetchExplorerAnswer(source, signal) {
    const fetchOptions = {
        cache: source.cache,
    };
    if (signal) {
        fetchOptions.signal = signal;
    }

    const response = await fetch(source.url, fetchOptions);
    let payload = null;
    try {
        payload = await response.json();
    } catch {
        payload = null;
    }
    return { response, payload };
}

// Asks the source the explorer source chooses (../explorer-source.js). The
// packaged file is an optimisation: any problem loading it falls back to the
// per-session API. An abort is never swallowed.
export async function requestExplorerSnapshot(
    explorerSource,
    { forceReload = false, signal = null, apiPath = MDS_EXPLORER_FULL_PATH } = {},
) {
    const hasExplorerSource = Boolean(explorerSource && typeof explorerSource.resolve === 'function');
    const primarySource = hasExplorerSource
        ? explorerSource.resolve({ forceReload })
        : { url: apiPath, cache: forceReload ? 'reload' : 'no-store', kind: 'api' };

    if (primarySource.kind !== 'static') {
        return fetchExplorerAnswer(primarySource, signal);
    }

    let result = null;
    try {
        result = await fetchExplorerAnswer(primarySource, signal);
        if (!result.response.ok || !result.payload || typeof result.payload !== 'object') {
            result = null;
        }
    } catch (error) {
        if (isAbortError(error)) {
            throw error;
        }
        result = null;
    }
    return result || fetchExplorerAnswer(explorerSource.fallback({ forceReload }), signal);
}

function answerError(payload) {
    return payload && typeof payload.error === 'string' && payload.error ? payload.error : '';
}

// What an answer is: `missing` (a 404: no snapshot), `failed` (with the sentence
// the status line shows) or `snapshot`.
export function classifyExplorerAnswer({ response, payload }, missingMessage = MISSING_METADATA_MESSAGE) {
    if (!response.ok) {
        if (response.status === 404) {
            return { kind: 'missing', message: answerError(payload) || missingMessage };
        }
        return {
            kind: 'failed',
            message: answerError(payload) || `Explorer request failed with status ${response.status}.`,
        };
    }
    if (!payload || typeof payload !== 'object') {
        return { kind: 'failed', message: 'Explorer response was not valid JSON.' };
    }
    return { kind: 'snapshot', payload };
}

export function explorerLoadFailure(error) {
    return error instanceof Error && error.message
        ? error.message
        : 'Unable to load the packaged authenticator explorer.';
}

// A snapshot's entries as the table shows them: copies, entries with their
// detail inline marked so, and any entry already resolved in full kept whole.
export function prepareSnapshotEntries(snapshot, resolvedEntryCache = new Map()) {
    const incomingEntries = Array.isArray(snapshot?.entries) ? snapshot.entries : [];
    return incomingEntries
        .map(entry => cloneMetadataEntry(entry))
        .filter(entry => entry && typeof entry === 'object')
        .map(entry => {
            if (hasInlineDetail(entry)) {
                entry.isLightweightEntry = false;
            }
            const cached = entry.entryId ? resolvedEntryCache.get(entry.entryId) : null;
            return cached && typeof cached === 'object' ? { ...entry, ...cached } : entry;
        });
}

// What the page starts from (GET /api/mds/metadata/info: the packaged summary,
// `snapshotUrl` and `customEntriesState`). Null when it cannot be had: the
// explorer then asks the API.
/** @param {{ signal?: AbortSignal }} [options] */
export async function fetchExplorerInfo({ signal } = {}) {
    try {
        const response = await fetch(MDS_INFO_PATH, { cache: 'no-store', signal });
        if (!response.ok) {
            return null;
        }
        const payload = await response.json();
        return payload && typeof payload === 'object' && !Array.isArray(payload) ? payload : null;
    } catch (error) {
        if (isAbortError(error)) {
            throw error;
        }
        return null;
    }
}

// No entry at all: the server has no snapshot (it answers 200 with nothing in
// it) and no metadata was uploaded.
export function isMissingSnapshot(snapshot) {
    return !Array.isArray(snapshot?.entries) || snapshot.entries.length === 0;
}
