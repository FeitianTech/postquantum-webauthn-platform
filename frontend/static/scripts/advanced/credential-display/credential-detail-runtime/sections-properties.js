import {el} from '../../../shared/ui/dom.js';
import {
    attestationResultRow,
    booleanValue,
    labelledLine,
} from '../detail-nodes.js';
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

function buildRootChecks(rootChecksRaw) {
    if (!rootChecksRaw || typeof rootChecksRaw !== 'object') {
        return null;
    }

    const rootCheckDescriptors = [
        { key: 'fido_mds', altKey: 'fidoMds', label: 'FIDO MDS' },
        { key: 'chain', altKey: 'chain', label: 'Chain' },
    ];

    const rootCheckParts = rootCheckDescriptors.map(descriptor => {
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

        return el('span', { style: `color: ${color}; font-weight: 600;`, text: descriptor.label });
    });

    return el('span', { style: 'margin-left: 0.5rem; color: #6c757d;' },
        '(',
        rootCheckParts.flatMap((part, index) => (index ? [', ', part] : [part])),
        ')',
    );
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

    const rootChecks = buildRootChecks(rootChecksRaw);

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

    const attestationChecksNotice = el('p', {
        style: 'margin: 0 0 0.65rem; color: #6c757d; font-size: 0.9rem; line-height: 1.5;',
    },
    'In formal WebAuthn, any ',
    el('strong', { text: 'false' }),
    ' result below causes registration to fail. This platform keeps registration valid for data inspection purposes.',
    );

    return el('div', { style: 'margin-bottom: 1.5rem;' },
        el('h4', { style: 'color: #0072CE; margin-bottom: 0.5rem;', text: 'Properties' }),
        el('div', { style: 'font-size: 0.9rem; line-height: 1.4;' },
            el('div', {}, el('strong', { text: 'Discoverable (resident key):' }), ' ', booleanValue(discoverableValue)),
            el('div', {}, el('strong', { text: 'Supports largeBlob:' }), ' ', booleanValue(largeBlobSupported)),
            minPinLengthValue !== null
                ? labelledLine('Authenticator minPinLength:', String(minPinLengthValue))
                : null,
            el('div', { style: 'margin-top: 0.5rem; padding-top: 0.75rem; border-top: 1px solid rgba(0, 114, 206, 0.15);' },
                attestationChecksNotice,
                attestationResultRow('Signature Valid', attestationSignatureValue),
                attestationResultRow('Root Valid', attestationRootValue, rootChecks),
                attestationResultRow('RPID Hash Valid', attestationRpIdHashValue),
                attestationResultRow('AAGUID Match', attestationAaguidMatchValue),
                metadataWarningMessage
                    ? el('div', {
                        style: 'margin-top: 0.4rem; color: #c47f16; font-size: 0.85rem;',
                        text: metadataWarningMessage,
                    })
                    : null,
            ),
        ),
    );
}
