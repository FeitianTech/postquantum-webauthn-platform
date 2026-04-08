import { createMdsDataExplorerAdapters } from './runtime-data-explorer-adapters.js';
import { createMdsDataLoadingAdapters } from './runtime-data-loading-adapters.js';

export function createMdsDataAdapters(config = {}) {
    const loadingAdapters = createMdsDataLoadingAdapters(config);
    const explorerAdapters = createMdsDataExplorerAdapters({
        ...config,
        applyMetadataEntries: loadingAdapters.applyMetadataEntries,
        buildLoadedStatus: loadingAdapters.buildLoadedStatus,
    });

    return {
        ...loadingAdapters,
        ...explorerAdapters,
    };
}
