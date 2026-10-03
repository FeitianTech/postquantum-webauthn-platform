// The raw view of an explorer entry: the entry rebuilt as MDS publishes it, and
// the words around it. No DOM.
export const RAW_DATA_TITLE = 'Authenticator Raw Data';
export const RAW_DATA_LABEL = 'Raw authenticator metadata';
export const RAW_DATA_BUTTON_TITLE = 'View raw authenticator data';
export const RAW_DATA_UNAVAILABLE_TITLE = 'Raw authenticator data unavailable';

// "${name} – Authenticator Raw Data", or the second part alone without a name.
/**
 * @param {Record<string, any> | null | undefined} entry
 * @returns {string}
 */
export function authenticatorRawTitle(entry) {
    const name = typeof entry?.name === 'string' ? entry.name.trim() : '';
    return name ? `${name} – ${RAW_DATA_TITLE}` : RAW_DATA_TITLE;
}

// A statement that can take a field (JSON would not show one on a list).
function isStatement(value) {
    return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

// The entry as MDS publishes it: its own BLOB entry when it has one, else its
// statement with the roots and key identifiers the explorer took out of it put
// back, its status and biometric status reports, AAGUID, id, time of the last
// status change and rogue list. The entry is not changed: a statement that
// gains a field is a copy.
/**
 * @param {Record<string, any> | null | undefined} entry
 * @returns {Record<string, unknown> | null}
 */
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
        isStatement(base.metadataStatement)
        && base.metadataStatement.attestationRootCertificates === undefined
        && Array.isArray(entry.attestationCertificates)
        && entry.attestationCertificates.length
    ) {
        base.metadataStatement = {
            ...base.metadataStatement,
            attestationRootCertificates: entry.attestationCertificates,
        };
    }

    if (base.attestationCertificateKeyIdentifiers === undefined) {
        const identifiers = Array.isArray(entry.attestationKeyIdentifiers)
            ? entry.attestationKeyIdentifiers
            : [];
        if (identifiers.length) {
            base.attestationCertificateKeyIdentifiers = identifiers;
            if (
                isStatement(base.metadataStatement)
                && base.metadataStatement.attestationCertificateKeyIdentifiers === undefined
            ) {
                base.metadataStatement = {
                    ...base.metadataStatement,
                    attestationCertificateKeyIdentifiers: identifiers,
                };
            }
        }
    }

    for (const key of ['statusReports', 'biometricStatusReports']) {
        if (base[key] === undefined && Array.isArray(entry[key]) && entry[key].length) {
            base[key] = entry[key];
        }
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

    for (const key of ['rogueListURL', 'rogueListHash']) {
        if (base[key] === undefined && entry[key]) {
            base[key] = entry[key];
        }
    }

    return Object.keys(base).length ? base : null;
}
