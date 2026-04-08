export function getAuthenticatorRawData(entry) {
    if (!entry || typeof entry !== 'object') {
        return null;
    }

    const rawEntry = entry.rawEntry;
    const base = rawEntry && typeof rawEntry === 'object' && !Array.isArray(rawEntry)
        ? { ...rawEntry }
        : {};

    const metadata = entry.metadataStatement && typeof entry.metadataStatement === 'object'
        ? entry.metadataStatement
        : null;
    if (metadata && base.metadataStatement === undefined) {
        base.metadataStatement = metadata;
    }

    if (
        base.metadataStatement
        && typeof base.metadataStatement === 'object'
        && base.metadataStatement.attestationRootCertificates === undefined
        && Array.isArray(entry.attestationCertificates)
        && entry.attestationCertificates.length
    ) {
        base.metadataStatement.attestationRootCertificates = entry.attestationCertificates;
    }

    if (base.attestationCertificateKeyIdentifiers === undefined) {
        const identifiers = Array.isArray(entry.attestationKeyIdentifiers)
            ? entry.attestationKeyIdentifiers
            : [];
        if (identifiers.length) {
            base.attestationCertificateKeyIdentifiers = identifiers;
            if (
                base.metadataStatement
                && typeof base.metadataStatement === 'object'
                && base.metadataStatement.attestationCertificateKeyIdentifiers === undefined
            ) {
                base.metadataStatement.attestationCertificateKeyIdentifiers = identifiers;
            }
        }
    }

    if (base.statusReports === undefined && Array.isArray(entry.statusReports) && entry.statusReports.length) {
        base.statusReports = entry.statusReports;
    }

    if (base.aaguid === undefined && entry.aaguid) {
        base.aaguid = entry.aaguid;
    }

    if (base.id === undefined && entry.id) {
        base.id = entry.id;
    }

    if (base.timeOfLastStatusChange === undefined) {
        if (rawEntry && typeof rawEntry === 'object' && rawEntry.timeOfLastStatusChange) {
            base.timeOfLastStatusChange = rawEntry.timeOfLastStatusChange;
        } else if (entry.timeOfLastStatusChange) {
            base.timeOfLastStatusChange = entry.timeOfLastStatusChange;
        }
    }

    return Object.keys(base).length ? base : null;
}
