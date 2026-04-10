import {
    base64ToBase64Url,
    base64UrlToHex,
} from '../../../shared/utils/binary.js';
import {
    describeCoseAlgorithm,
    describeCoseKeyType,
    describeMldsaParameterSet,
} from '../../display-utils.js';
import {
    getCoseMapValue,
} from '../../credential-utils.js';
import {
    resolveCredentialAlgorithmIdentifier,
} from '../algorithm.js';

function buildEncodedIdentifierSection({
    title,
    base64Value,
}) {
    const encodedValue = base64ToBase64Url(base64Value);
    const hexValue = base64UrlToHex(encodedValue);

    return `
        <div style="margin-top: 0.5rem;">
            <div><strong>${title}</strong></div>
            <div style="font-family: 'Courier New', monospace; font-size: 0.9rem; margin-left: 1rem; word-break: break-word; overflow-wrap: anywhere;">
                <div><strong>b64</strong></div>
                <div class="credential-code-block">${base64Value}</div>
                <div><strong>b64u</strong></div>
                <div class="credential-code-block">${encodedValue}</div>
                <div><strong>hex</strong></div>
                <div class="credential-code-block">${hexValue}</div>
            </div>
        </div>`;
}

export function buildUserInfoSection(cred, aaguidSectionHtml) {
    let detailsHtml = `
    <div style="margin-bottom: 1.5rem;">
        <h4 style="color: #0072CE; margin-bottom: 0.5rem;">User info at creation</h4>
        <div style="font-size: 0.9rem; line-height: 1.4;">
            <div><strong>Name:</strong> ${cred.userName || cred.email || 'N/A'}</div>
            <div style="margin-bottom: 0.5rem;"><strong>Display name:</strong> ${cred.displayName || cred.userName || cred.email || 'N/A'}</div>
        </div>`;

    if (cred.userHandle) {
        detailsHtml += buildEncodedIdentifierSection({
            title: 'User handle (User ID):',
            base64Value: cred.userHandle,
        });
    }

    if (cred.credentialId) {
        detailsHtml += buildEncodedIdentifierSection({
            title: 'Credential ID:',
            base64Value: cred.credentialId,
        });
    }

    detailsHtml += aaguidSectionHtml;
    detailsHtml += `</div>`;

    return detailsHtml;
}

export function buildAttestationFormatSection(attestationFormatDisplay) {
    return `
    <div style="margin-bottom: 1.5rem;">
        <h4 style="color: #0072CE; margin-bottom: 0.5rem;">Attestation Format</h4>
        <div style="font-size: 0.9rem;">${attestationFormatDisplay}</div>
    </div>`;
}

export function buildAuthenticatorDataSection(cred) {
    if (!cred.flags) {
        return '';
    }

    return `
        <div style="margin-bottom: 1.5rem;">
            <h4 style="color: #0072CE; margin-bottom: 0.5rem;">Authenticator Data (registration)</h4>
            <div style="font-size: 0.9rem; line-height: 1.4;">
                <div><strong>AT:</strong> ${cred.flags.at}, <strong>BE:</strong> ${cred.flags.be}, <strong>BS:</strong> ${cred.flags.bs}, <strong>ED:</strong> ${cred.flags.ed}, <strong>UP:</strong> ${cred.flags.up}, <strong>UV:</strong> ${cred.flags.uv}</div>
                <div><strong>Signature Counter:</strong> ${cred.signCount || 0}</div>
            </div>
        </div>`;
}

export function buildExtensionsSection(cred) {
    if (!cred.clientExtensionOutputs || Object.keys(cred.clientExtensionOutputs).length === 0) {
        return '';
    }

    return `
        <div style="margin-bottom: 1.5rem;">
            <h4 style="color: #0072CE; margin-bottom: 0.5rem;">Client extension outputs (registration)</h4>
            <div class="credential-code-block" style="font-size: 0.9rem; border-radius: 16px;">${JSON.stringify(cred.clientExtensionOutputs, null, 2)}</div>
        </div>`;
}

export function buildPublicKeySection(cred) {
    const hasPublicKeyData = cred.publicKeyAlgorithm !== undefined
        || cred.algorithm !== undefined
        || (cred.publicKeyCose && Object.keys(cred.publicKeyCose).length > 0);

    if (!hasPublicKeyData) {
        return '';
    }

    const coseMap = cred.publicKeyCose || {};
    const resolvedAlgorithm = resolveCredentialAlgorithmIdentifier(cred);
    const fallbackAlgorithm = resolvedAlgorithm !== null
        ? resolvedAlgorithm
        : getCoseMapValue(coseMap, 3);

    const algorithmName = describeCoseAlgorithm(fallbackAlgorithm);
    const coseKeyTypeValue = cred.publicKeyType ?? getCoseMapValue(coseMap, 1);

    const coseKeyTypeLine = coseKeyTypeValue !== undefined && coseKeyTypeValue !== null
        ? `<div><strong>COSE key type:</strong> ${describeCoseKeyType(coseKeyTypeValue)}</div>`
        : '';

    const parameterSet = describeMldsaParameterSet(fallbackAlgorithm);
    const parameterSetLine = parameterSet
        ? `<div><strong>ML-DSA parameter set:</strong> ${parameterSet}</div>`
        : '';

    return `
        <div style="margin-bottom: 1.5rem;">
            <h4 style="color: #0072CE; margin-bottom: 0.5rem;">Public Key</h4>
            <div style="font-size: 0.9rem;">
                <div><strong>Algorithm:</strong> ${algorithmName}</div>
                ${coseKeyTypeLine}
                ${parameterSetLine}
            </div>
        </div>`;
}

export function buildRegistrationDetailSection(combinedRegistrationHtml) {
    if (combinedRegistrationHtml) {
        return `
        <div class="credential-registration-copy">
            ${combinedRegistrationHtml}
        </div>`;
    }

    return `
        <div class="credential-registration-copy">
            <div style="font-style: italic; color: #6c757d;">Registration detail data is not available for this credential.</div>
        </div>`;
}
