export function updateBackgroundLoadingStatus(parsed, total, lastUpdatedDate, setStatus) {
    const safeTotal = Number.isFinite(total) && total > 0 ? total : 0;
    const safeParsed = Number.isFinite(parsed) && parsed > 0 ? parsed : 0;
    const percentComplete = safeTotal > 0 ? Math.round((safeParsed / safeTotal) * 100) : 100;
    const statusParts = [
        `Loaded ${safeTotal.toLocaleString()} authenticators.`,
    ];
    if (lastUpdatedDate) {
        statusParts.push(`Last updated: ${lastUpdatedDate}.`);
    }
    if (safeParsed < safeTotal) {
        statusParts.push(`Processing full details… ${percentComplete}% complete`);
    }

    const statusMessage = statusParts.join(' ');
    const variant = safeParsed < safeTotal ? 'info' : 'success';
    setStatus(statusMessage, variant);
}

export async function populateCertificateDerivedInfoInternal(entries, options = {}, deps = {}) {
    const { upgradeLightweightEntries = false } = options;
    const {
        upgradeEntryToFull,
        normaliseCertificateBase64,
        decodeCertificate,
    } = deps;

    if (!Array.isArray(entries) || !entries.length) {
        return;
    }

    const seen = new Set();
    const certificates = [];

    entries.forEach(entry => {
        if (upgradeLightweightEntries && entry.isLightweightEntry && entry.deferredRawEntry) {
            const fullEntry = upgradeEntryToFull(entry);
            Object.assign(entry, fullEntry);
        }

        const list = Array.isArray(entry?.attestationCertificates) ? entry.attestationCertificates : [];
        list.forEach(certificate => {
            const cleaned = normaliseCertificateBase64(certificate);
            if (cleaned && !seen.has(cleaned)) {
                seen.add(cleaned);
                certificates.push(cleaned);
            }
        });
    });

    if (!certificates.length) {
        return;
    }

    const detailMap = new Map();

    const decodeTasks = certificates.map(certificate =>
        decodeCertificate(certificate)
            .then(details => ({ certificate, details, error: null }))
            .catch(error => ({ certificate, details: null, error })),
    );

    const decodedResults = await Promise.all(decodeTasks);
    decodedResults.forEach(result => {
        if (result.error) {
            console.error('Failed to decode attestation root certificate:', result.error);
        }
        detailMap.set(result.certificate, result.details);
    });

    entries.forEach(entry => {
        const algorithmSet = new Set();
        const algorithms = [];
        const commonNameSet = new Set();
        const commonNames = [];
        const list = Array.isArray(entry?.attestationCertificates) ? entry.attestationCertificates : [];

        list.forEach(certificate => {
            const cleaned = normaliseCertificateBase64(certificate);
            if (!cleaned) {
                return;
            }
            const details = detailMap.get(cleaned);
            if (!details || typeof details !== 'object') {
                return;
            }

            const algorithmInfo = typeof details.algorithmInfo === 'string' ? details.algorithmInfo.trim() : '';
            if (algorithmInfo && !algorithmSet.has(algorithmInfo)) {
                algorithmSet.add(algorithmInfo);
                algorithms.push(algorithmInfo);
            }

            const cnValues = Array.isArray(details.subjectCommonNames) ? details.subjectCommonNames : [];
            cnValues.forEach(name => {
                if (typeof name !== 'string') {
                    return;
                }
                const trimmed = name.trim();
                if (trimmed && !commonNameSet.has(trimmed)) {
                    commonNameSet.add(trimmed);
                    commonNames.push(trimmed);
                }
            });
        });

        entry.certificateAlgorithmInfoList = algorithms;
        entry.certificateAlgorithmInfo = algorithms.length ? algorithms.join(', ') : '—';
        entry.algorithmInfo = entry.certificateAlgorithmInfo;
        entry.certificateCommonNameList = commonNames;
        entry.certificateCommonNames = commonNames.length ? commonNames.join(', ') : '—';
        entry.commonName = entry.certificateCommonNames;
    });
}

export async function populateCertificateDerivedInfoForBatch(entries, deps = {}) {
    await populateCertificateDerivedInfoInternal(entries, {
        upgradeLightweightEntries: true,
    }, deps);
}

export function finalizeBackgroundLoading({ metadata, lastUpdatedDate, mdsData, state, setStatus }) {
    const statusParts = [`Loaded ${mdsData.length.toLocaleString()} authenticators.`];
    if (lastUpdatedDate) {
        statusParts.push(`Last updated: ${lastUpdatedDate}.`);
    }

    const statusMessage = statusParts.join(' ');
    setStatus(statusMessage, 'success');

    if (state?.defaultStatus) {
        state.defaultStatus.html = statusMessage;
        state.defaultStatus.variant = 'success';
    }

    if (metadata?.legalHeader && state?.statusEl) {
        if (state.defaultStatus) {
            state.defaultStatus.title = metadata.legalHeader;
        }
    }
}

export function buildLoadedStatus(snapshot, note, formatSnapshotTimestamp) {
    const meta = snapshot?.meta && typeof snapshot.meta === 'object' ? snapshot.meta : {};
    const entryCount = Array.isArray(snapshot?.entries) ? snapshot.entries.length : 0;
    const parts = [`Loaded ${entryCount.toLocaleString()} authenticators.`];

    const lastUpdated = formatSnapshotTimestamp(meta);
    if (lastUpdated) {
        parts.push(`Last updated ${lastUpdated}.`);
    }

    if (Number.isFinite(meta?.customEntryCount) && meta.customEntryCount > 0) {
        const count = Number(meta.customEntryCount);
        const suffix = count === 1 ? 'entry' : 'entries';
        parts.push(`Including ${count.toLocaleString()} session metadata ${suffix}.`);
    }

    if (note) {
        parts.push(note);
    }

    return parts.join(' ');
}
