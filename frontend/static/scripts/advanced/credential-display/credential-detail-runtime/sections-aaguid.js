import {
    hexToGuid,
} from '../../../shared/utils/binary.js';
import {el, fragment} from '../../../shared/ui/dom.js';
import {
    deriveAaguidDisplayValues,
    deriveAaguidFromCredentialData,
    normaliseAaguidValue,
} from '../../credentials/utils.js';

function renderAaguidValue(label, value) {
    return el('div', { className: 'credential-aaguid-value' },
        el('span', { className: 'credential-aaguid-value-label', text: label }),
        el('div', { className: 'credential-code-block', text: value || 'N/A' }),
    );
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

    return fragment(
        el('div', { className: 'credential-aaguid-row' },
            el('span', { className: 'credential-aaguid-label', text: 'AAGUID' }),
        ),
        el('div', { className: 'credential-aaguid-status', attrs: { role: 'status', 'aria-live': 'polite' } },
            el('span', { className: 'credential-aaguid-spinner', attrs: { 'aria-hidden': 'true', hidden: true } }),
            el('span', { className: 'credential-aaguid-status-text' }),
        ),
        el('div', { className: 'credential-aaguid-values' },
            renderAaguidValue('b64', hasAaguid && aaguidB64 ? aaguidB64 : 'N/A'),
            renderAaguidValue('b64u', hasAaguid && aaguidB64u ? aaguidB64u : 'N/A'),
            renderAaguidValue('hex', hasAaguid ? normalizedAaguidHex : 'N/A'),
            renderAaguidValue('guid', aaguidGuid || 'N/A'),
        ),
    );
}
