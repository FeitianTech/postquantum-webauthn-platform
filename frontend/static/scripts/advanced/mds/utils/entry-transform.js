import { CERTIFICATION_OPTIONS } from '../constants.js';
import { extractAttestationKeyIdentifiers, extractList, extractTransports, extractUserVerification } from './extractors.js';
import { formatCertification, formatDate, formatEnum, formatProtocol } from './formatters.js';
import { normaliseIcon, resolveAaguid, resolveIdentifier, resolveName } from './resolvers.js';
import { latestEffectiveDate } from './status-reports.js';

function buildCommonTransformedFields(entry, index, metadata) {
    const name = resolveName(metadata, entry);
    const protocol = formatProtocol(metadata.protocolFamily || metadata.protocolType);
    const { display: certification, status: certificationStatus } = formatCertification(entry?.statusReports || []);
    const identifier = resolveIdentifier(entry, metadata);
    const aaguid = resolveAaguid(entry, metadata) || '';
    const userVerificationList = extractUserVerification(metadata.userVerificationDetails);
    const attachmentList = extractList(metadata.attachmentHint).map(formatEnum);
    const transportsList = extractTransports(metadata);
    const keyProtectionList = extractList(metadata.keyProtection).map(formatEnum);
    const algorithmsList = extractList(metadata.authenticationAlgorithms).map(formatEnum);
    const icon = normaliseIcon(metadata.icon, metadata.iconType);

    const latestStatusDate = latestEffectiveDate(entry?.statusReports || []);
    const rawDate = entry?.timeOfLastStatusChange || latestStatusDate;
    const dateUpdated = rawDate ? formatDate(rawDate) : '';

    return {
        index,
        name,
        protocol,
        certification,
        certificationStatus,
        id: identifier,
        aaguid,
        icon,
        userVerification: userVerificationList.join(', '),
        userVerificationList,
        attachment: attachmentList.join(', '),
        attachmentList,
        transports: transportsList.join(', '),
        transportsList,
        keyProtection: keyProtectionList.join(', '),
        keyProtectionList,
        algorithms: algorithmsList.join(', '),
        algorithmsList,
        certificateAlgorithmInfo: '—',
        certificateAlgorithmInfoList: [],
        certificateCommonNames: '—',
        certificateCommonNameList: [],
        algorithmInfo: '—',
        commonName: '—',
        dateUpdated,
        dateTooltip: rawDate || undefined,
    };
}

export function collectOptionSets(data) {
    const sets = {
        protocol: new Set(),
        certification: new Set(CERTIFICATION_OPTIONS.map(option => formatEnum(option))),
        userVerification: new Set(),
        attachment: new Set(),
        transports: new Set(),
        keyProtection: new Set(),
        algorithms: new Set(),
    };

    data.forEach(entry => {
        if (entry.protocol) {
            sets.protocol.add(entry.protocol);
        }
        if (entry.certificationStatus) {
            sets.certification.add(formatEnum(entry.certificationStatus));
        }
        entry.userVerificationList.forEach(value => sets.userVerification.add(value));
        entry.attachmentList.forEach(value => sets.attachment.add(value));
        entry.transportsList.forEach(value => sets.transports.add(value));
        entry.keyProtectionList.forEach(value => sets.keyProtection.add(value));
        entry.algorithmsList.forEach(value => sets.algorithms.add(value));
    });

    return sets;
}

export function transformEntry(entry, index = 0) {
    const metadata = entry?.metadataStatement ?? {};
    const transformed = buildCommonTransformedFields(entry, index, metadata);
    const attestationCertificates = extractList(metadata.attestationRootCertificates);
    const attestationKeyIdentifiers = extractAttestationKeyIdentifiers(metadata, entry);

    return {
        ...transformed,
        metadataStatement: metadata,
        rawEntry: entry || null,
        statusReports: Array.isArray(entry?.statusReports) ? entry.statusReports : [],
        attestationCertificates,
        attestationKeyIdentifiers,
    };
}

/**
 * Lightweight transformation for initial UI display
 * Only parses fields visible in the list view
 */
export function transformEntryLightweight(entry, index = 0) {
    const metadata = entry?.metadataStatement ?? {};
    const transformed = buildCommonTransformedFields(entry, index, metadata);

    return {
        ...transformed,
        // Defer full parsing
        metadataStatement: null,
        rawEntry: null,
        statusReports: [],
        attestationCertificates: [],
        attestationKeyIdentifiers: [],
        isLightweightEntry: true, // Flag to indicate lightweight parsing
        deferredRawEntry: entry, // Keep reference for on-demand full parsing
    };
}

/**
 * Upgrade a lightweight entry to full entry
 * Completes parsing of deferred fields
 */
export function upgradeEntryToFull(lightweightEntry) {
    if (!lightweightEntry || !lightweightEntry.isLightweightEntry) {
        return lightweightEntry; // Already full or invalid
    }

    const entry = lightweightEntry.deferredRawEntry;
    if (!entry) {
        return lightweightEntry;
    }

    const metadata = entry?.metadataStatement ?? {};
    const attestationCertificates = extractList(metadata.attestationRootCertificates);
    const attestationKeyIdentifiers = extractAttestationKeyIdentifiers(metadata, entry);

    // Create full entry
    return {
        ...lightweightEntry,
        metadataStatement: metadata,
        rawEntry: entry,
        statusReports: Array.isArray(entry?.statusReports) ? entry.statusReports : [],
        attestationCertificates,
        attestationKeyIdentifiers,
        isLightweightEntry: false,
        deferredRawEntry: undefined, // Remove raw entry reference
    };
}