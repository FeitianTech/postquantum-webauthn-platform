const CERTIFICATE_DECODE_API_PATH = '/api/mds/decode-certificate';

function buildEntryIndexByAaguid(mdsData, normaliseAaguid) {
    const index = new Map();
    if (!Array.isArray(mdsData)) {
        return index;
    }

    for (const entry of mdsData) {
        const key = normaliseAaguid(entry?.aaguid || entry?.id);
        if (key && !index.has(key)) {
            index.set(key, entry);
        }
    }
    return index;
}

function ensureLazyLoaderEntriesHydrated(cleanedCertificate, deps = {}) {
    const {
        lazyLoader,
        mdsData,
        mdsState,
        normaliseAaguid,
        upgradeEntryToFull,
        transformEntry,
    } = deps;

    if (!lazyLoader || lazyLoader.isFullyLoaded()) {
        return;
    }

    const matchingRawEntries = lazyLoader.findEntriesWithCertificate(cleanedCertificate);
    if (!Array.isArray(matchingRawEntries) || !matchingRawEntries.length) {
        return;
    }

    const byAaguid = mdsState?.byAaguid instanceof Map ? mdsState.byAaguid : null;
    const indexedEntriesByAaguid = buildEntryIndexByAaguid(mdsData, normaliseAaguid);
    const processedKeys = new Set();

    for (const rawEntry of matchingRawEntries) {
        const key = normaliseAaguid(rawEntry?.aaguid || rawEntry?.metadataStatement?.aaguid);
        if (key && processedKeys.has(key)) {
            continue;
        }
        if (key) {
            processedKeys.add(key);
        }

        let existingEntry = key && byAaguid ? byAaguid.get(key) : null;
        if (!existingEntry && key) {
            existingEntry = indexedEntriesByAaguid.get(key) || null;
        }

        if (existingEntry) {
            if (existingEntry.isLightweightEntry) {
                const fullEntry = upgradeEntryToFull(existingEntry);
                Object.assign(existingEntry, fullEntry);
            }

            if (typeof existingEntry.index === 'number') {
                lazyLoader.markEntryFullyParsed(existingEntry.index, key);
            }
            continue;
        }

        const index = mdsData.length;
        const transformed = transformEntry(rawEntry, index);
        if (!transformed) {
            continue;
        }

        mdsData.push(transformed);
        if (key) {
            indexedEntriesByAaguid.set(key, transformed);
            byAaguid?.set(key, transformed);
        }
        lazyLoader.markEntryFullyParsed(index, key);
    }
}

async function requestDecodedCertificate(cleanedCertificate) {
    const response = await fetch(CERTIFICATE_DECODE_API_PATH, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
        body: JSON.stringify({ certificate: cleanedCertificate }),
        cache: 'no-store',
    });

    if (!response.ok) {
        throw new Error(`Certificate decode failed with status ${response.status}`);
    }

    const payload = await response.json();
    return payload?.details ?? null;
}

export async function decodeCertificateWithState(certificateBase64, deps = {}) {
    const {
        normaliseCertificateBase64,
        certificateCache,
    } = deps;

    const cleaned = normaliseCertificateBase64(certificateBase64);
    if (!cleaned) {
        throw new Error('No certificate data available.');
    }

    if (certificateCache.has(cleaned)) {
        return certificateCache.get(cleaned);
    }

    ensureLazyLoaderEntriesHydrated(cleaned, deps);

    const details = await requestDecodedCertificate(cleaned);
    certificateCache.set(cleaned, details);
    return details;
}
