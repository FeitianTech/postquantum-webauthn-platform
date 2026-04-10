export {
    collectOptionSets,
    transformEntry,
    transformEntryLightweight,
    upgradeEntryToFull,
} from './mds-utils/entry-transform.js';

export {
    extractAttestationKeyIdentifiers,
    extractByteArray,
    extractList,
    extractTransports,
    extractUserVerification,
} from './mds-utils/extractors.js';

export {
    formatCertificateDateDisplay,
    formatCertification,
    formatDate,
    formatDetailValue,
    formatEnum,
    formatProtocol,
    formatSignatureHashName,
    formatUpv,
    normaliseEnumKey,
    parseIsoDate,
} from './mds-utils/formatters.js';

export {
    formatGuidCandidate,
    normaliseAaguid,
    normaliseIcon,
    resolveAaguid,
    resolveIdentifier,
    resolveName,
} from './mds-utils/resolvers.js';

export { latestEffectiveDate } from './mds-utils/status-reports.js';

export {
    createSummaryItem,
    decodeBase64Url,
    determinePublicKeyAlgorithm,
    renderCertificatePublicKey,
    renderCertificateSignature,
    renderCertificateSummary,
} from './mds-utils/certificate-render.js';