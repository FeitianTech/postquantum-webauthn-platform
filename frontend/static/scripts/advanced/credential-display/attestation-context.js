import {hexToGuid} from '../../shared/utils/binary.js';
import {
    deriveAaguidFromCredentialData,
    normaliseAaguidValue,
} from '../credentials/utils.js';
import {
    collectCredentialCertificates,
    extractAaguidFromCertificateEntries,
} from './certificate-core.js';

export function extractCredentialAttestationContext(cred) {
    const propertiesData = cred && typeof cred.properties === 'object' && cred.properties !== null
        ? cred.properties
        : {};

    const attestationSummaryData = (() => {
        if (cred && typeof cred.attestationSummary === 'object' && cred.attestationSummary !== null) {
            return cred.attestationSummary;
        }
        if (typeof propertiesData.attestationSummary === 'object' && propertiesData.attestationSummary !== null) {
            return propertiesData.attestationSummary;
        }
        return null;
    })();

    const attestationChecksData = (() => {
        if (cred && typeof cred.attestationChecks === 'object' && cred.attestationChecks !== null) {
            return cred.attestationChecks;
        }
        if (typeof propertiesData.attestationChecks === 'object' && propertiesData.attestationChecks !== null) {
            return propertiesData.attestationChecks;
        }
        if (
            attestationSummaryData
            && typeof attestationSummaryData.metadata === 'object'
            && attestationSummaryData.metadata !== null
        ) {
            return { metadata: attestationSummaryData.metadata };
        }
        return null;
    })();

    return {
        propertiesData,
        attestationSummaryData,
        attestationChecksData,
    };
}

export function resolveCredentialAttestationValue(cred, summaryKey, propertyKey, context) {
    const sources = context || extractCredentialAttestationContext(cred);
    const { propertiesData, attestationSummaryData } = sources;

    if (
        attestationSummaryData
        && attestationSummaryData !== null
        && Object.prototype.hasOwnProperty.call(attestationSummaryData, summaryKey)
    ) {
        return attestationSummaryData[summaryKey];
    }

    if (
        propertiesData
        && propertiesData !== null
        && Object.prototype.hasOwnProperty.call(propertiesData, propertyKey)
    ) {
        return propertiesData[propertyKey];
    }

    if (cred && cred !== null && Object.prototype.hasOwnProperty.call(cred, propertyKey)) {
        return cred[propertyKey];
    }

    return null;
}

export function normaliseAttestationResultValue(value) {
    if (typeof value === 'boolean' || value === null || value === undefined) {
        return value;
    }
    if (typeof value === 'number') {
        if (Number.isNaN(value)) {
            return null;
        }
        if (value === 1) {
            return true;
        }
        if (value === 0) {
            return false;
        }
    }
    if (typeof value === 'string') {
        const trimmed = value.trim();
        if (!trimmed) {
            return null;
        }
        const normalised = trimmed.toLowerCase();
        if (['true', 'yes', 'valid', 'pass', 'passed', 'success', 'ok'].includes(normalised)) {
            return true;
        }
        if (['false', 'no', 'invalid', 'fail', 'failed', 'error', 'ko'].includes(normalised)) {
            return false;
        }
        if (normalised === '1') {
            return true;
        }
        if (normalised === '0') {
            return false;
        }
    }
    return value;
}

export function computeCredentialAaguidMatchStatus(cred, options = {}) {
    if (!cred || typeof cred !== 'object') {
        return null;
    }

    const {
        certificateEntries,
        certificateAaguidHex,
        authDataAaguidHex,
        attestationContext,
    } = options || {};

    let certificateHex = certificateAaguidHex;
    if (certificateHex === undefined) {
        const entries = certificateEntries !== undefined
            ? certificateEntries
            : collectCredentialCertificates(cred);
        certificateHex = extractAaguidFromCertificateEntries(entries);
    }
    certificateHex = normaliseAaguidValue(certificateHex);

    let authDataHex = authDataAaguidHex;
    if (authDataHex === undefined) {
        authDataHex = deriveAaguidFromCredentialData(cred);
    }
    authDataHex = normaliseAaguidValue(authDataHex);

    if (certificateHex && authDataHex) {
        return certificateHex === authDataHex;
    }

    const context = attestationContext
        || extractCredentialAttestationContext(cred);
    const rawFallback = resolveCredentialAttestationValue(
        cred,
        'aaguidMatch',
        'attestationAaguidMatch',
        context,
    );
    const fallback = normaliseAttestationResultValue(rawFallback);
    return typeof fallback === 'boolean' ? fallback : null;
}

export function deriveCredentialStatusIndicators(cred) {
    const attestationContext = extractCredentialAttestationContext(cred);
    const { propertiesData, attestationSummaryData, attestationChecksData } = attestationContext;

    const signatureStatus = normaliseAttestationResultValue(
        resolveCredentialAttestationValue(
            cred,
            'signatureValid',
            'attestationSignatureValid',
            attestationContext,
        ),
    );
    const rootStatus = normaliseAttestationResultValue(
        resolveCredentialAttestationValue(
            cred,
            'rootValid',
            'attestationRootValid',
            attestationContext,
        ),
    );
    const rpidStatus = normaliseAttestationResultValue(
        resolveCredentialAttestationValue(
            cred,
            'rpIdHashValid',
            'attestationRpIdHashValid',
            attestationContext,
        ),
    );

    const certificateEntries = collectCredentialCertificates(cred);
    const certificateAaguidHex = normaliseAaguidValue(
        extractAaguidFromCertificateEntries(certificateEntries)
    );
    const authDataAaguidHex = normaliseAaguidValue(deriveAaguidFromCredentialData(cred));

    const aaguidStatus = computeCredentialAaguidMatchStatus(cred, {
        certificateEntries,
        certificateAaguidHex,
        authDataAaguidHex,
        attestationContext,
    });

    const metadataAvailableCandidates = [
        cred?.metadata?.available,
        propertiesData?.metadata?.available,
        attestationSummaryData?.metadata?.available,
        attestationChecksData?.metadata?.available,
    ];
    const metadataAvailable = metadataAvailableCandidates.some(value => {
        if (typeof value === 'boolean') {
            return value;
        }
        if (typeof value === 'string') {
            const normalized = value.trim().toLowerCase();
            return ['true', '1', 'yes', 'available'].includes(normalized);
        }
        return false;
    });

    const primaryAaguidHex = normaliseAaguidValue(
        cred?.aaguidHex
        || cred?.aaguid
        || cred?.aaguidGuid
        || authDataAaguidHex
        || certificateAaguidHex
    );

    let aaguidGuid = '';
    if (primaryAaguidHex && primaryAaguidHex.length === 32) {
        try {
            aaguidGuid = hexToGuid(primaryAaguidHex);
        } catch (error) {
            aaguidGuid = '';
        }
    }

    return {
        attestationContext,
        signatureStatus,
        rootStatus,
        rpidStatus,
        aaguidStatus,
        metadataAvailable,
        aaguidGuid,
    };
}
