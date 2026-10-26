import { MDS_CUSTOM_ENTRIES_PATH, MDS_LIST_PATH } from './constants.js';
import { requestExplorerAnswer } from './explorer/loading.js';

/** @import { ExplorerAnswer, MdsInfo, MdsSnapshot } from './explorer/loading.js' */

/**
 * Where a part of the explorer is asked for: its URL, the fetch's cache mode, and
 * `static` (the packaged list) or `api` (the session's own entries).
 * @typedef {{ url: string, cache: RequestCache, kind: 'static' | 'api' }} SnapshotLocation
 * @typedef {object} ExplorerSource
 * @property {() => SnapshotLocation} list
 * @property {(options?: { forceReload?: boolean }) => SnapshotLocation | null} custom
 * @property {(meta: unknown) => void} noteSnapshotMeta
 */

/**
 * What a load's two answers come to: `failed` (with the sentence the status line
 * shows), or `parts`: the packaged list (null when the server has none, a 404)
 * and the session's own entries (null when they were not asked for).
 * @typedef {(
 *     | { kind: 'failed', message: string }
 *     | { kind: 'parts', packaged: MdsSnapshot | null, custom: MdsSnapshot | null }
 * )} ExplorerOutcome
 */

/**
 * Where the explorer's two parts are loaded from.
 *
 * The packaged list is the same for everyone: one URL, fetched without the
 * session's cookie and revalidated by its ETag. The session's own entries
 * (its uploads, and the counts) are asked for while the session has (or may
 * have) uploads, and on every forced reload.
 * @param {MdsInfo | null} initialInfo
 * @returns {ExplorerSource}
 */
export function createExplorerSource(initialInfo) {
    let customEntriesState =
        initialInfo && typeof initialInfo.customEntriesState === 'string'
            ? initialInfo.customEntriesState
            : 'unknown';

    /** @type {ExplorerSource['list']} */
    function list() {
        return { url: MDS_LIST_PATH, cache: 'default', kind: 'static' };
    }

    /** @type {ExplorerSource['custom']} */
    function custom({ forceReload = false } = {}) {
        if (!forceReload && customEntriesState === 'none') {
            return null;
        }
        return { url: MDS_CUSTOM_ENTRIES_PATH, cache: forceReload ? 'reload' : 'no-store', kind: 'api' };
    }

    function noteSnapshotMeta(meta) {
        if (meta && typeof meta.hasCustomEntries === 'boolean') {
            customEntriesState = meta.hasCustomEntries ? 'present' : 'none';
        }
    }

    return { list, custom, noteSnapshotMeta };
}

// Asks for both parts at once: the packaged list and, when the source says so,
// the session's own entries.
/**
 * @param {ExplorerSource} explorerSource
 * @param {{ forceReload?: boolean, signal?: AbortSignal | null }} [options]
 * @returns {Promise<{ list: ExplorerAnswer, custom: ExplorerAnswer | null }>}
 */
export async function requestExplorerParts(explorerSource, { forceReload = false, signal = null } = {}) {
    const customLocation = explorerSource.custom({ forceReload });
    const [list, custom] = await Promise.all([
        requestExplorerAnswer(explorerSource.list(), signal),
        customLocation ? requestExplorerAnswer(customLocation, signal) : null,
    ]);
    return { list, custom };
}

function answerError(payload) {
    return payload && typeof payload.error === 'string' && payload.error ? payload.error : '';
}

/**
 * The sentence for an answer that is no object to show, or '' for one that is.
 * @param {ExplorerAnswer} answer
 */
function failureOf({ response, payload }) {
    if (!response.ok) {
        return answerError(payload) || `Explorer request failed with status ${response.status}.`;
    }
    return payload && typeof payload === 'object' ? '' : 'Explorer response was not valid JSON.';
}

// What a load's answers are. The list answering 404 is a server without a
// snapshot: there is then no packaged list, and only the session's uploads show.
/**
 * @param {{ list: ExplorerAnswer, custom: ExplorerAnswer | null }} answers
 * @returns {ExplorerOutcome}
 */
export function classifyExplorerParts({ list, custom }) {
    const packagedMissing = list.response.status === 404;
    const failure = (packagedMissing ? '' : failureOf(list)) || (custom ? failureOf(custom) : '');
    if (failure) {
        return { kind: 'failed', message: failure };
    }
    return { kind: 'parts', packaged: packagedMissing ? null : list.payload, custom: custom ? custom.payload : null };
}

/**
 * @param {unknown} error
 * @returns {string}
 */
export function explorerLoadFailure(error) {
    return error instanceof Error && error.message
        ? error.message
        : 'Unable to load the packaged authenticator explorer.';
}
