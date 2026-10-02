import { MDS_EXPLORER_FULL_PATH } from './constants.js';

/** @import { MdsInfo } from './explorer/loading.js' */

/**
 * Where a snapshot is asked for: its URL, the fetch's cache mode, and `static`
 * (the packaged file) or `api` (the session's list).
 * @typedef {{ url: string, cache: RequestCache, kind: 'static' | 'api' }} SnapshotLocation
 * @typedef {object} ExplorerSource
 * @property {(options?: { forceReload?: boolean }) => SnapshotLocation} resolve
 * @property {(options?: { forceReload?: boolean }) => SnapshotLocation} fallback
 * @property {(meta: unknown) => void} noteSnapshotMeta
 */

/**
 * @param {boolean} forceReload
 * @returns {SnapshotLocation}
 */
function apiSource(forceReload) {
    return {
        url: MDS_EXPLORER_FULL_PATH,
        cache: forceReload ? 'reload' : 'no-store',
        kind: 'api',
    };
}

/**
 * Decide where the explorer snapshot is loaded from.
 *
 * Sessions without uploaded metadata see exactly the packaged snapshot, which
 * the browser can cache as a static file. Sessions with (or possibly with)
 * uploads, and explicit refreshes, use the per-session API.
 * @param {MdsInfo | null} initialInfo
 * @returns {ExplorerSource}
 */
export function createExplorerSource(initialInfo) {
    const staticUrl =
        initialInfo && typeof initialInfo.snapshotUrl === 'string' && initialInfo.snapshotUrl
            ? initialInfo.snapshotUrl
            : null;
    let customEntriesState =
        initialInfo && typeof initialInfo.customEntriesState === 'string'
            ? initialInfo.customEntriesState
            : 'unknown';

    /** @type {ExplorerSource['resolve']} */
    function resolve({ forceReload = false } = {}) {
        if (!forceReload && staticUrl && customEntriesState === 'none') {
            return { url: staticUrl, cache: 'default', kind: 'static' };
        }
        return apiSource(forceReload);
    }

    /** @type {ExplorerSource['fallback']} */
    function fallback({ forceReload = false } = {}) {
        return apiSource(forceReload);
    }

    function noteSnapshotMeta(meta) {
        if (meta && typeof meta.hasCustomEntries === 'boolean') {
            customEntriesState = meta.hasCustomEntries ? 'present' : 'none';
        }
    }

    return { resolve, fallback, noteSnapshotMeta };
}
