import {
    hexToGuid,
} from '../../../shared/utils/binary.js';
import {
    escapeHtml,
} from '../../display-utils.js';
import {
    deriveAaguidDisplayValues,
    deriveAaguidFromCredentialData,
    normaliseAaguidValue,
} from '../../credential-utils.js';

function renderAaguidValue(label, value) {
    return `
            <div class="credential-aaguid-value">
                <span class="credential-aaguid-value-label">${label}</span>
                <div class="credential-code-block">${escapeHtml(value || 'N/A')}</div>
            </div>`;
}

function resolveAaguidHex(cred, attestationContext) {
    let aaguidHex = normaliseAaguidValue(cred.aaguid);

    const {
        propertiesData,
        attestationSummaryData,
        attestationChecksData,
    } = attestationContext;

    const fallbackAaguidCandidates = [
        cred.aaguidHex,
        cred.aaguidGuid,
        cred.aaguidRaw,
        propertiesData?.aaguid,
        propertiesData?.aaguidHex,
        propertiesData?.aaguidGuid,
        propertiesData?.aaguidRaw,
        attestationSummaryData?.aaguid,
        attestationSummaryData?.aaguidHex,
        attestationSummaryData?.aaguidGuid,
        attestationChecksData?.metadata?.aaguid,
        attestationChecksData?.metadata?.hex,
        attestationChecksData?.metadata?.raw,
        attestationChecksData?.metadata?.guid,
        propertiesData?.metadata?.aaguid,
        propertiesData?.metadata?.hex,
        propertiesData?.metadata?.raw,
        propertiesData?.metadata?.guid,
        cred?.metadata?.aaguid,
        cred?.metadata?.hex,
        cred?.metadata?.raw,
        cred?.metadata?.guid,
    ];

    const relyingPartyAaguid = cred?.relyingParty?.aaguid;
    if (relyingPartyAaguid && typeof relyingPartyAaguid === 'object') {
        fallbackAaguidCandidates.push(
            relyingPartyAaguid.raw,
            relyingPartyAaguid.hex,
            relyingPartyAaguid.guid,
        );
    } else if (relyingPartyAaguid) {
        fallbackAaguidCandidates.push(relyingPartyAaguid);
    }

    if (!aaguidHex) {
        for (const candidate of fallbackAaguidCandidates) {
            const normalised = normaliseAaguidValue(candidate);
            if (normalised) {
                aaguidHex = normalised;
                break;
            }
        }
    }

    if (!aaguidHex) {
        aaguidHex = deriveAaguidFromCredentialData(cred);
    }

    return aaguidHex;
}

export function buildAaguidSection(cred, attestationContext) {
    const aaguidHex = resolveAaguidHex(cred, attestationContext);
    const {
        aaguidHex: normalizedAaguidHex,
        aaguidB64,
        aaguidB64u,
    } = deriveAaguidDisplayValues(aaguidHex);

    let aaguidGuid = '';
    if (normalizedAaguidHex && normalizedAaguidHex.length === 32) {
        try {
            aaguidGuid = hexToGuid(normalizedAaguidHex);
        } catch {
            aaguidGuid = '';
        }
    }

    const hasAaguid = Boolean(normalizedAaguidHex);

    const sections = [
        renderAaguidValue('b64', hasAaguid && aaguidB64 ? aaguidB64 : 'N/A'),
        renderAaguidValue('b64u', hasAaguid && aaguidB64u ? aaguidB64u : 'N/A'),
        renderAaguidValue('hex', hasAaguid ? normalizedAaguidHex : 'N/A'),
        renderAaguidValue('guid', aaguidGuid || 'N/A'),
    ];

    return `
        <div class="credential-aaguid-row">
            <span class="credential-aaguid-label">AAGUID</span>
        </div>
        <div class="credential-aaguid-status" role="status" aria-live="polite">
            <span class="credential-aaguid-spinner" aria-hidden="true" hidden></span>
            <span class="credential-aaguid-status-text"></span>
        </div>
        <div class="credential-aaguid-values">
            ${sections.join('')}
        </div>`;
}
