/**
 * Lazy loading infrastructure for FIDO MDS metadata
 * Optimizes initial page load by deferring full parameter parsing
 * Loads all entries but only parses UI-visible fields initially
 */

const BACKGROUND_BATCH_SIZE = 200;
const BACKGROUND_BATCH_DELAY_MS = 16; // One animation frame

export class MdsLazyLoader {
    constructor() {
        this.allEntries = [];
        this.fullyParsedIndices = new Set();
        this.fullyParsedKeys = new Map(); // aaguid -> entry
        this.isBackgroundLoading = false;
        this.backgroundLoadComplete = false;
        this.backgroundLoadAborted = false;
        this.backgroundLoadPromise = null;
        this.onProgressCallback = null;
        this.onCompleteCallback = null;
        this.metadata = null;
    }

    /**
     * Initialize with full metadata object
     */
    initialize(metadata) {
        this.metadata = metadata;
        this.allEntries = Array.isArray(metadata?.entries) ? metadata.entries : [];
        this.fullyParsedIndices = new Set();
        this.fullyParsedKeys = new Map();
        this.isBackgroundLoading = false;
        this.backgroundLoadComplete = false;
        this.backgroundLoadAborted = false;
        this.backgroundLoadPromise = null;
    }

    /**
     * Get all raw entries for lightweight parsing
     */
    getAllRawEntries() {
        return this.allEntries;
    }

    /**
     * Get specific raw entry by index
     */
    getRawEntryByIndex(index) {
        return this.allEntries[index] || null;
    }

    /**
     * Get specific raw entry by AAGUID or ID
     */
    getRawEntryByKey(key) {
        if (!key) {
            return null;
        }

        // Check if already cached
        const cached = this.fullyParsedKeys.get(key);
        if (cached) {
            return cached;
        }

        // Search through all entries
        for (let i = 0; i < this.allEntries.length; i++) {
            const entry = this.allEntries[i];
            const entryAaguid = this.normalizeKey(entry?.aaguid || entry?.metadataStatement?.aaguid);
            const entryId = this.normalizeKey(entry?.aaid);

            if (entryAaguid === key || entryId === key) {
                this.fullyParsedKeys.set(key, entry);
                return entry;
            }
        }

        return null;
    }

    /**
     * Find entries that contain specific attestation certificates
     */
    findEntriesWithCertificate(certificateBase64) {
        if (!certificateBase64) {
            return [];
        }

        const normalized = this.normalizeCertificate(certificateBase64);
        if (!normalized) {
            return [];
        }

        const matchingEntries = [];

        for (let i = 0; i < this.allEntries.length; i++) {
            const entry = this.allEntries[i];
            const certificates = entry?.metadataStatement?.attestationRootCertificates || [];
            
            const hasMatch = certificates.some(cert => {
                const certNormalized = this.normalizeCertificate(cert);
                return certNormalized === normalized;
            });

            if (hasMatch) {
                matchingEntries.push(entry);
            }
        }

        return matchingEntries;
    }

    /**
     * Mark an entry as fully parsed
     */
    markEntryFullyParsed(index, key) {
        this.fullyParsedIndices.add(index);
        if (key) {
            const entry = this.allEntries[index];
            if (entry) {
                this.fullyParsedKeys.set(key, entry);
            }
        }
    }

    /**
     * Check if an entry is fully parsed
     */
    isEntryFullyParsed(index) {
        return this.fullyParsedIndices.has(index);
    }

    /**
     * Start background loading of full entry details
     */
    async startBackgroundLoading(options = {}) {
        if (this.isBackgroundLoading || this.backgroundLoadComplete) {
            return this.backgroundLoadPromise;
        }

        this.isBackgroundLoading = true;
        this.backgroundLoadAborted = false;
        const signal = options.signal;
        const onBatchProcessed = options.onBatchProcessed;

        this.backgroundLoadPromise = this.runBackgroundLoading(signal, onBatchProcessed);
        return this.backgroundLoadPromise;
    }

    /**
     * Internal: Run background loading with yielding
     */
    async runBackgroundLoading(signal, onBatchProcessed) {
        const totalEntries = this.allEntries.length;
        let currentIndex = 0;

        // Skip already parsed entries
        while (currentIndex < totalEntries && this.fullyParsedIndices.has(currentIndex)) {
            currentIndex++;
        }

        while (currentIndex < totalEntries) {
            // Check for abort
            if (signal?.aborted || this.backgroundLoadAborted) {
                this.isBackgroundLoading = false;
                this.backgroundLoadAborted = true;
                return;
            }

            // Process a batch
            const batchEnd = Math.min(currentIndex + BACKGROUND_BATCH_SIZE, totalEntries);
            const batchIndices = [];
            
            for (let i = currentIndex; i < batchEnd; i++) {
                if (!this.fullyParsedIndices.has(i)) {
                    batchIndices.push(i);
                    this.fullyParsedIndices.add(i);
                }
            }

            // Notify about batch to process
            if (batchIndices.length > 0 && onBatchProcessed) {
                await onBatchProcessed(batchIndices);
            }

            // Report progress
            if (this.onProgressCallback) {
                const parsed = this.fullyParsedIndices.size;
                const progress = Math.round((parsed / totalEntries) * 100);
                this.onProgressCallback(parsed, totalEntries, progress);
            }

            currentIndex = batchEnd;

            // Yield to browser
            if (currentIndex < totalEntries) {
                await this.yieldToBrowser();
            }
        }

        this.isBackgroundLoading = false;
        this.backgroundLoadComplete = true;

        if (this.onCompleteCallback) {
            this.onCompleteCallback();
        }
    }

    /**
     * Abort background loading
     */
    abortBackgroundLoading() {
        this.backgroundLoadAborted = true;
    }

    /**
     * Set callback for background loading progress
     */
    onProgress(callback) {
        this.onProgressCallback = callback;
    }

    /**
     * Set callback for background loading completion
     */
    onComplete(callback) {
        this.onCompleteCallback = callback;
    }

    /**
     * Get loading statistics
     */
    getStats() {
        return {
            total: this.allEntries.length,
            fullyParsed: this.fullyParsedIndices.size,
            pending: this.allEntries.length - this.fullyParsedIndices.size,
            isBackgroundLoading: this.isBackgroundLoading,
            backgroundLoadComplete: this.backgroundLoadComplete,
            percentComplete: this.allEntries.length > 0 
                ? Math.round((this.fullyParsedIndices.size / this.allEntries.length) * 100) 
                : 100,
        };
    }

    /**
     * Check if all entries are fully parsed
     */
    isFullyLoaded() {
        return this.backgroundLoadComplete || this.fullyParsedIndices.size === this.allEntries.length;
    }

    /**
     * Normalize AAGUID/ID key for comparison
     */
    normalizeKey(value) {
        if (!value) {
            return '';
        }
        const str = String(value).toLowerCase().trim();
        return str.replace(/[^0-9a-f]/g, '');
    }

    /**
     * Normalize certificate for comparison
     */
    normalizeCertificate(cert) {
        if (!cert || typeof cert !== 'string') {
            return '';
        }
        return cert.replace(/[\s\r\n-]/g, '').replace(/^.*BEGIN CERTIFICATE.*$|^.*END CERTIFICATE.*$/gm, '');
    }

    /**
     * Yield to browser for responsiveness
     */
    yieldToBrowser() {
        return new Promise(resolve => {
            if (typeof requestIdleCallback === 'function') {
                requestIdleCallback(resolve, { timeout: BACKGROUND_BATCH_DELAY_MS });
            } else if (typeof requestAnimationFrame === 'function') {
                requestAnimationFrame(() => setTimeout(resolve, 0));
            } else {
                setTimeout(resolve, BACKGROUND_BATCH_DELAY_MS);
            }
        });
    }
}

/**
 * Create a new lazy loader instance
 */
export function createMdsLazyLoader() {
    return new MdsLazyLoader();
}
