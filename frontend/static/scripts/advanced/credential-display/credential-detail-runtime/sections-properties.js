import {
    escapeHtml,
    formatBoolean,
    renderAttestationResultRow,
} from '../../ui/display-utils.js';
import {
    extractMinPinLengthValue,
} from '../../credentials/utils.js';
import {
    computeCredentialAaguidMatchStatus,
    normaliseAttestationResultValue,
    resolveCredentialAttestationValue,
} from '../attestation-context.js';
import {
    pickFirstString,
} from './helpers.js';

function buildRootChecksHtml(rootChecksRaw) {
    if (!rootChecksRaw || typeof rootChecksRaw !== 'object') {
        return '';
    }

    const rootCheckDescriptors = [
        { key: 'fido_mds', altKey: 'fidoMds', label: 'FIDO MDS' },
        { key: 'chain', altKey: 'chain', label: 'Chain' },
    ];

    const rootCheckParts = [];
    for (const descriptor of rootCheckDescriptors) {
        let rawValue = rootChecksRaw[descriptor.key];
        if (rawValue === undefined) {
            rawValue = rootChecksRaw[descriptor.altKey];
        }

        const status = rawValue === undefined
            ? null
            : normaliseAttestationResultValue(rawValue);

        const color = status === true
            ? '#198754'
            : status === false
                ? '#dc3545'
                : '#6c757d';

        rootCheckParts.push(
            `<span style="color: ${color}; font-weight: 600;">${descriptor.label}</span>`,
        );
    }

    if (!rootCheckParts.length) {
        return '';
    }

    return ` <span style="margin-left: 0.5rem; color: #6c757d;">(${rootCheckParts.join(', ')})</span>`;
}

export function buildPropertiesSection({
    cred,
    attestationContext,
    fallbackCertificates,
    certificateAaguidHex,
    authDataAaguidHex,
}) {
    const {
        propertiesData,
        attestationSummaryData,
        attestationChecksData,
    } = attestationContext;

    const discoverableValue = cred.residentKey ?? cred.discoverable ?? false;
    const largeBlobSupported = cred.largeBlob ?? cred.largeBlobSupported ?? false;
    const minPinLengthValue = extractMinPinLengthValue(cred);

    const metadataWarningMessage = pickFirstString(
        attestationChecksData?.metadata?.verification_warning,
        attestationChecksData?.metadata?.verificationWarning,
        attestationSummaryData?.metadata?.verification_warning,
        attestationSummaryData?.metadata?.verificationWarning,
        propertiesData?.metadata?.verification_warning,
        propertiesData?.metadata?.verificationWarning,
        cred?.metadata?.verification_warning,
        cred?.metadata?.verificationWarning,
    );

    const attestationSignatureValue = normaliseAttestationResultValue(
        resolveCredentialAttestationValue(
            cred,
            'signatureValid',
            'attestationSignatureValid',
            attestationContext,
        ),
    );

    const attestationRootValue = normaliseAttestationResultValue(
        resolveCredentialAttestationValue(
            cred,
            'rootValid',
            'attestationRootValid',
            attestationContext,
        ),
    );

    let rootChecksRaw = null;
    if (
        attestationContext.attestationChecksData
        && typeof attestationContext.attestationChecksData === 'object'
    ) {
        const checksSource = attestationContext.attestationChecksData;
        if (checksSource.root_checks && typeof checksSource.root_checks === 'object') {
            rootChecksRaw = checksSource.root_checks;
        } else if (checksSource.rootChecks && typeof checksSource.rootChecks === 'object') {
            rootChecksRaw = checksSource.rootChecks;
        }
    }

    const rootChecksHtml = buildRootChecksHtml(rootChecksRaw);

    const attestationRpIdHashValue = normaliseAttestationResultValue(
        resolveCredentialAttestationValue(
            cred,
            'rpIdHashValid',
            'attestationRpIdHashValid',
            attestationContext,
        ),
    );

    const attestationAaguidMatchValue = computeCredentialAaguidMatchStatus(cred, {
        certificateEntries: fallbackCertificates,
        certificateAaguidHex,
        authDataAaguidHex,
        attestationContext,
    });

    const attestationChecksNoticeHtml = `
        <p style="margin: 0 0 0.65rem; color: #6c757d; font-size: 0.9rem; line-height: 1.5;">
            In formal WebAuthn, any <strong>false</strong> result below causes registration to fail.
            This platform keeps registration valid for data inspection purposes. 
        </p>`;

    const attestationRowsHtml = [
        renderAttestationResultRow('Signature Valid', attestationSignatureValue),
        renderAttestationResultRow('Root Valid', attestationRootValue, rootChecksHtml),
        renderAttestationResultRow('RPID Hash Valid', attestationRpIdHashValue),
        renderAttestationResultRow('AAGUID Match', attestationAaguidMatchValue),
    ].join('');

    const metadataWarningHtml = metadataWarningMessage
        ? `<div style="margin-top: 0.4rem; color: #c47f16; font-size: 0.85rem;">${escapeHtml(metadataWarningMessage)}</div>`
        : '';

    return `
    <div style="margin-bottom: 1.5rem;">
        <h4 style="color: #0072CE; margin-bottom: 0.5rem;">Properties</h4>
        <div style="font-size: 0.9rem; line-height: 1.4;">
            <div><strong>Discoverable (resident key):</strong> ${formatBoolean(discoverableValue)}</div>
            <div><strong>Supports largeBlob:</strong> ${formatBoolean(largeBlobSupported)}</div>
            ${minPinLengthValue !== null ? `<div><strong>Authenticator minPinLength:</strong> ${escapeHtml(String(minPinLengthValue))}</div>` : ''}
            <div style="margin-top: 0.5rem; padding-top: 0.75rem; border-top: 1px solid rgba(0, 114, 206, 0.15);">
                ${attestationChecksNoticeHtml}
                ${attestationRowsHtml}
                ${metadataWarningHtml}
            </div>
        </div>
    </div>`;
}
