// Where the explorer's entries come from and what an answer means, for both UIs:
// the legacy tab (metadata/explorer-load.js, explorer-state-loader.js) and web's
// MDS section. No DOM.
import { MDS_EXPLORER_FULL_PATH, MDS_INFO_PATH, MISSING_METADATA_MESSAGE } from '../constants.js';
import { cloneMetadataEntry, hasInlineDetail } from '../metadata/metadata-helpers.js';
import { normaliseAaguid } from '../utils/resolvers.js';

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

// Asks the source the explorer source chooses (metadata/explorer-source.js). The
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
        if (error && error.name === 'AbortError') {
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

// Entries without an `entryId` are the client's own row format, which the
// server no longer sends; only the legacy tab can still parse them.
export function needsLegacyEntryParser(payload) {
    const payloadEntries = Array.isArray(payload?.entries) ? payload.entries : [];
    return (
        payloadEntries.length > 0
        && payloadEntries.some(entry => {
            if (!entry || typeof entry !== 'object') {
                return true;
            }
            return !Object.prototype.hasOwnProperty.call(entry, 'entryId');
        })
    );
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

// Entries by AAGUID (the credential cards look entries up that way); every entry
// with an `entryId` also goes into the resolved-entry cache.
export function indexEntriesByAaguid(entries, resolvedEntryCache = new Map()) {
    const byAaguid = new Map();
    entries.forEach(entry => {
        const key = normaliseAaguid(entry?.aaguid || entry?.id);
        if (key) {
            byAaguid.set(key, entry);
        }
        if (entry?.entryId) {
            resolvedEntryCache.set(entry.entryId, entry);
        }
    });
    return byAaguid;
}

// What the page starts from (GET /api/mds/metadata/info: the packaged summary,
// `snapshotUrl` and `customEntriesState`), which the legacy page reads from the
// index instead. Null when it cannot be had: the explorer then asks the API.
export async function fetchExplorerInfo({ signal } = {}) {
    try {
        const response = await fetch(MDS_INFO_PATH, { cache: 'no-store', signal });
        if (!response.ok) {
            return null;
        }
        const payload = await response.json();
        return payload && typeof payload === 'object' && !Array.isArray(payload) ? payload : null;
    } catch (error) {
        if (error && error.name === 'AbortError') {
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
