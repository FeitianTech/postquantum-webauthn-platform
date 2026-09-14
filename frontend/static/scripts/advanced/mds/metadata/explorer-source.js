import { MDS_EXPLORER_FULL_PATH } from '../constants.js';

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

    function resolve({ forceReload = false } = {}) {
        if (!forceReload && staticUrl && customEntriesState === 'none') {
            return { url: staticUrl, cache: 'default', kind: 'static' };
        }
        return apiSource(forceReload);
    }

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
