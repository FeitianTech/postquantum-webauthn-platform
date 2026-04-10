export {
    collectOptionSets,
    transformEntry,
    transformEntryLightweight,
    upgradeEntryToFull,
} from './utils/entry-transform.js';

export {
    extractAttestationKeyIdentifiers,
    extractByteArray,
    extractList,
    extractTransports,
    extractUserVerification,
} from './utils/extractors.js';

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
} from './utils/formatters.js';

export {
    formatGuidCandidate,
    normaliseAaguid,
    normaliseIcon,
    resolveAaguid,
    resolveIdentifier,
    resolveName,
} from './utils/resolvers.js';

export { latestEffectiveDate } from './utils/status-reports.js';

export {
    createSummaryItem,
    decodeBase64Url,
    determinePublicKeyAlgorithm,
    renderCertificatePublicKey,
    renderCertificateSignature,
    renderCertificateSummary,
} from './utils/certificate-render.js';