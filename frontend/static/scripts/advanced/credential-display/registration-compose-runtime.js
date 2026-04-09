import {
    base64UrlToJson,
    base64UrlToUtf8String,
} from '../../shared/binary-utils.js';
import {
    escapeHtml,
} from '../display-utils.js';
import {closeModal, openModal} from '../../shared/ui.js';
import {
    formatCertificateDetails,
    autoResizeCertificateTextareas,
} from './formatting.js';
import {
    normalizeClientDataString,
} from './data-utils.js';
import {
    normaliseCertificateEntryForModal,
    partitionCertificateEntries,
} from './certificate-core.js';
import {
    getVisibleAttestationCertificates,
} from './certificate-state.js';
import {
    sanitiseAttestationObjectForDisplay,
} from './sanitize-attestation-object.js';
import {
    sanitizeRelyingPartyInfo,
} from './sanitize-common.js';
import {
    captureRegistrationDetailState,
    prepareRegistrationDetailState,
} from './registration-state-runtime.js';
import {
    registrationDetailState,
} from './state.js';

export function buildAttestationSection({
    attestationObjectValue = '',
    attestationDecodeError = '',
    attestationFormatRaw = '',
    attestationStatement = null,
    authenticatorDataValue = '',
    authenticatorDecodeError = '',
} = {}) {
    const attestationObject = registrationDetailState.attestationObject;
    const attestationStatementObject = attestationStatement && typeof attestationStatement === 'object'
        ? attestationStatement
        : attestationObject && typeof attestationObject.attStmt === 'object'
            ? attestationObject.attStmt
            : null;
    const attestationStatementHasContent = attestationStatementObject && Object.keys(attestationStatementObject).length > 0;

    const certificatesAll = Array.isArray(registrationDetailState.attestationCertificates)
        ? registrationDetailState.attestationCertificates
        : [];
    const { valid: certificateInfos } = partitionCertificateEntries(certificatesAll);
    const attestationHasCertificates = certificateInfos.length > 0;

    registrationDetailState.visibleAttestationCertificateIndices = certificateInfos.map(info => info.index);

    const hasAttestationObject = Boolean(
        attestationObject
        && typeof attestationObject === 'object'
        && Object.keys(attestationObject).length > 0,
    );
    const hasAttestationValue = typeof attestationObjectValue === 'string'
        ? attestationObjectValue.trim() !== ''
        : false;

    const hasAttestation = hasAttestationObject
        || hasAttestationValue
        || attestationStatementHasContent
        || attestationHasCertificates;

    if (!hasAttestation) {
        return '';
    }

    const hasAuthenticatorData = Boolean(registrationDetailState.authenticatorData);
    const authenticatorButtonMarkup = hasAuthenticatorData
        ? '<button type="button" class="btn btn-small btn-secondary registration-authenticator-data-button">Authenticator Data</button>'
        : '';
    const shouldShowAuthenticatorError = !hasAuthenticatorData && authenticatorDataValue && authenticatorDecodeError;

    let attestationContent;
    const attestationHeading = '<h4 style="font-weight: 600; color: #0f2740; margin-bottom: 0.5rem;">Attestation Object</h4>';
    if (attestationObject) {
        let attestationJson;
        const attestationDisplay = sanitiseAttestationObjectForDisplay(
            attestationObject,
            attestationFormatRaw,
        ) || attestationObject;
        try {
            attestationJson = JSON.stringify(attestationDisplay, null, 2);
        } catch (error) {
            attestationJson = '';
        }

        if (!attestationJson && attestationObject) {
            try {
                attestationJson = JSON.stringify(attestationObject, null, 2);
            } catch (jsonError) {
                attestationJson = '';
            }
        }

        const attestationBody = attestationJson
            ? `<textarea class="certificate-textarea" readonly spellcheck="false" wrap="soft">${escapeHtml(attestationJson)}</textarea>`
            : '<div style="font-style: italic; color: #6c757d;">Unable to prepare decoded attestationObject.</div>';

        attestationContent = `
            <div style="margin-bottom: 0.75rem;">
                ${attestationHeading}
                ${attestationBody}
            </div>
        `;
    } else if (attestationObjectValue) {
        const message = attestationDecodeError || 'Unable to decode attestationObject.';
        attestationContent = `
            <div style="margin-bottom: 0.75rem;">
                ${attestationHeading}
                <div style="color: #dc3545; font-size: 0.9rem;">${escapeHtml(message)}</div>
            </div>
        `;
    } else {
        attestationContent = `
            <div style="margin-bottom: 0.75rem;">
                ${attestationHeading}
                <div style="font-style: italic; color: #6c757d;">No attestationObject was provided.</div>
            </div>
        `;
    }

    const buttonRowSegments = [];
    let certificateMessageHtml = '';

    if (attestationHasCertificates) {
        const singleCertificate = certificateInfos.length === 1;
        certificateInfos.forEach((info, displayIndex) => {
            const label = singleCertificate
                ? 'Attestation Certificate'
                : `Attestation Certificate ${displayIndex + 1}`;
            buttonRowSegments.push(`<button type="button" class="btn btn-small registration-attestation-cert-button" data-cert-index="${displayIndex}">${escapeHtml(label)}</button>`);
        });
    } else if (hasAttestationObject || hasAttestationValue || attestationStatementHasContent) {
        certificateMessageHtml = '<div style="font-style: italic; color: #6c757d; margin-top: 0.75rem;">No attestation certificates available.</div>';
    }

    if (authenticatorButtonMarkup) {
        buttonRowSegments.push(authenticatorButtonMarkup);
    }

    const buttonRowHtml = buttonRowSegments.length
        ? `<div class="registration-detail-button-row">${buttonRowSegments.join('')}</div>`
        : '';

    const authenticatorMessageHtml = shouldShowAuthenticatorError
        ? `<div style="color: #dc3545; font-size: 0.9rem; margin-top: 0.75rem;">${escapeHtml(authenticatorDecodeError)}</div>`
        : '';

    return `
        <section style="margin-bottom: 1.5rem;">
            <h3 style="color: #0072CE; margin-bottom: 0.75rem;">Attestation Information</h3>
            ${attestationContent}
            ${buttonRowHtml}
            ${certificateMessageHtml}
            ${authenticatorMessageHtml}
        </section>
    `;
}

export async function composeRegistrationDetailHtml({
    credentialJson = null,
    relyingPartyInfo = null,
    attestationObjectValue = '',
    attestationObjectDecoded = null,
    authenticatorDataValue = '',
    authenticatorDataHex = '',
    fallbackCertificates = [],
    fallbackClientData = null,
    fallbackParsedClientData = null,
    includeAttestationSection = true,
    preferFallbackCertificates = false,
} = {}) {
    const credentialDisplay = credentialJson && typeof credentialJson === 'object'
        ? JSON.stringify(credentialJson, null, 2)
        : '';

    const fallbackClientDataString = typeof fallbackClientData === 'string'
        ? fallbackClientData.trim()
        : '';
    const normalizedFallbackClientData = fallbackClientDataString
        ? normalizeClientDataString(fallbackClientDataString)
        : '';

    let clientDataBase64 = credentialJson?.response?.clientDataJSON;
    if (!clientDataBase64 && normalizedFallbackClientData) {
        clientDataBase64 = normalizedFallbackClientData;
    }

    let parsedClientData = null;
    if (clientDataBase64) {
        parsedClientData = base64UrlToJson(clientDataBase64);
    }

    if (!parsedClientData && fallbackParsedClientData && typeof fallbackParsedClientData === 'object') {
        parsedClientData = fallbackParsedClientData;
    }

    let clientDataDisplay = '';
    if (parsedClientData) {
        clientDataDisplay = JSON.stringify(parsedClientData, null, 2);
    } else if (clientDataBase64) {
        clientDataDisplay = base64UrlToUtf8String(clientDataBase64) || clientDataBase64;
    } else if (fallbackClientDataString) {
        clientDataDisplay = fallbackClientDataString;
    } else if (fallbackParsedClientData && typeof fallbackParsedClientData === 'object') {
        clientDataDisplay = JSON.stringify(fallbackParsedClientData, null, 2);
    }

    const credentialSection = credentialDisplay
        ? `<pre class="modal-pre">${escapeHtml(credentialDisplay)}</pre>`
        : '<div style="font-style: italic; color: #6c757d;">No credential response captured.</div>';

    const clientDataSection = clientDataDisplay
        ? `<pre class="modal-pre">${escapeHtml(clientDataDisplay)}</pre>`
        : '<div style="font-style: italic; color: #6c757d;">No clientDataJSON available.</div>';

    const detailPreparation = await prepareRegistrationDetailState({
        attestationObjectValue,
        attestationObjectDecoded,
        authenticatorDataValue,
        fallbackCertificates,
        relyingPartyInfo,
        preferFallbackCertificates,
    });

    const authDataState = registrationDetailState.authenticatorData;
    if (authDataState) {
        if (detailPreparation.authenticatorDataValue && typeof authDataState.base64url !== 'string') {
            authDataState.base64url = detailPreparation.authenticatorDataValue;
        }
        if (authenticatorDataHex && typeof authDataState.raw !== 'string') {
            authDataState.raw = authenticatorDataHex;
        }
    } else if (detailPreparation.authenticatorDataValue || authenticatorDataHex) {
        registrationDetailState.authenticatorData = {};
        if (detailPreparation.authenticatorDataValue) {
            registrationDetailState.authenticatorData.base64url = detailPreparation.authenticatorDataValue;
        }
        if (authenticatorDataHex) {
            registrationDetailState.authenticatorData.raw = authenticatorDataHex;
        }
    }

    const authenticatorSummary = {
        authenticatorDataHex: typeof registrationDetailState.authenticatorDataHex === 'string'
            ? registrationDetailState.authenticatorDataHex
            : '',
        authenticatorDataHash: typeof registrationDetailState.authenticatorDataHash === 'string'
            ? registrationDetailState.authenticatorDataHash
            : '',
    };

    const relyingPartyCopy = sanitizeRelyingPartyInfo(relyingPartyInfo, authenticatorSummary);

    const relyingPartyDisplay = relyingPartyCopy
        ? JSON.stringify(relyingPartyCopy, null, 2)
        : '';

    const relyingPartySection = relyingPartyDisplay
        ? `<pre class="modal-pre">${escapeHtml(relyingPartyDisplay)}</pre>`
        : '<div style="font-style: italic; color: #6c757d;">No relying party data returned.</div>';

    let html = `
        <section style="margin-bottom: 1.5rem;">
            <h3 style="color: #0072CE; margin-bottom: 0.75rem;">Authenticator Response</h3>
            <ol style="padding-left: 1.25rem; margin: 0;">
                <li style="margin-bottom: 1rem;">
                    <div style="font-weight: 600; margin-bottom: 0.5rem;">Response for navigator.credentials.create()</div>
                    ${credentialSection}
                </li>
                <li>
                    <div style="font-weight: 600; margin-bottom: 0.5rem;">Parsed clientDataJSON</div>
                    ${clientDataSection}
                </li>
            </ol>
        </section>
        <section style="margin-bottom: 1.5rem;">
            <h3 style="color: #0072CE; margin-bottom: 0.75rem;">Server-retrieved Data</h3>
            ${relyingPartySection}
        </section>
    `;

    const attestationObject = registrationDetailState.attestationObject;
    const attestationFormatFromRp = typeof relyingPartyInfo?.attestationFmt === 'string'
        ? relyingPartyInfo.attestationFmt
        : '';
    const attestationFormatFromObject = attestationObject && typeof attestationObject.fmt === 'string'
        ? attestationObject.fmt
        : attestationObjectDecoded && typeof attestationObjectDecoded === 'object' && typeof attestationObjectDecoded.fmt === 'string'
            ? attestationObjectDecoded.fmt
            : '';
    const attestationFormatRaw = attestationFormatFromRp || attestationFormatFromObject || '';
    const attestationStatement = attestationObject && typeof attestationObject.attStmt === 'object'
        ? attestationObject.attStmt
        : attestationObjectDecoded && typeof attestationObjectDecoded === 'object' && typeof attestationObjectDecoded.attStmt === 'object'
            ? attestationObjectDecoded.attStmt
            : null;

    const attestationSectionHtml = buildAttestationSection({
        attestationObjectValue: detailPreparation.attestationObjectValue,
        attestationDecodeError: detailPreparation.attestationDecodeError,
        attestationFormatRaw,
        attestationStatement,
        authenticatorDataValue: detailPreparation.authenticatorDataValue,
        authenticatorDecodeError: detailPreparation.authenticatorDecodeError,
    });

    if (includeAttestationSection && attestationSectionHtml) {
        html += attestationSectionHtml;
    }

    const stateSnapshot = captureRegistrationDetailState(detailPreparation);

    return {
        html,
        attestationSectionHtml,
        combinedHtml: includeAttestationSection
            ? html
            : [html, attestationSectionHtml].filter(Boolean).join(''),
        stateSnapshot,
    };
}

export function bindRegistrationDetailButtons(scope) {
    if (!scope) {
        return;
    }

    const certificateButtons = scope.querySelectorAll('.registration-attestation-cert-button');
    certificateButtons.forEach(button => {
        button.addEventListener('click', event => {
            event.preventDefault();
            const indexValue = Number(button.getAttribute('data-cert-index'));
            if (!Number.isNaN(indexValue)) {
                openAttestationCertificateDetail(indexValue);
            }
        });
    });

    const authenticatorButtonEl = scope.querySelector('.registration-authenticator-data-button');
    if (authenticatorButtonEl) {
        authenticatorButtonEl.addEventListener('click', event => {
            event.preventDefault();
            openAuthenticatorDataDetail();
        });
    }
}

function openRegistrationDetailModal(title, bodyHtml) {
    const modal = document.getElementById('registrationDetailModal');
    const titleEl = document.getElementById('registrationDetailModalTitle');
    const bodyEl = document.getElementById('registrationDetailModalBody');
    if (!modal || !titleEl || !bodyEl) {
        return;
    }

    titleEl.textContent = title;
    bodyEl.innerHTML = bodyHtml;
    openModal('registrationDetailModal');

    const resize = () => autoResizeCertificateTextareas(bodyEl);
    if (typeof requestAnimationFrame === 'function') {
        requestAnimationFrame(resize);
    } else {
        setTimeout(resize, 0);
    }
}

export function openAttestationCertificateDetail(index) {
    const visibleCertificates = getVisibleAttestationCertificates();
    const certificate = visibleCertificates[index];
    const singleCertificate = visibleCertificates.length === 1;
    const normalised = normaliseCertificateEntryForModal(certificate);
    if (!normalised) {
        return;
    }

    const parsed = normalised.parsedX5c && typeof normalised.parsedX5c === 'object'
        ? normalised.parsedX5c
        : {};
    const sections = [];
    const errorMessage = typeof parsed.error === 'string' && parsed.error.trim() !== ''
        ? parsed.error.trim()
        : '';
    const summary = formatCertificateDetails(parsed);

    if (summary && summary.trim() !== '') {
        sections.push(`<textarea class="certificate-textarea" readonly spellcheck="false" wrap="soft">${escapeHtml(summary)}</textarea>`);
    } else if (errorMessage) {
        sections.push(`<div style="color: #dc3545; font-size: 0.9rem;">${escapeHtml(errorMessage)}</div>`);
    } else {
        sections.push('<div style="font-style: italic; color: #6c757d;">No decoded certificate details available.</div>');
    }

    const title = singleCertificate
        ? 'Attestation Certificate'
        : `Attestation Certificate ${index + 1}`;

    openRegistrationDetailModal(title, sections.join(''));
}

export function openAuthenticatorDataDetail() {
    const data = registrationDetailState.authenticatorData;
    if (!data) {
        return;
    }

    const sections = [];
    const jsonString = escapeHtml(JSON.stringify(data, null, 2));
    sections.push(`<textarea class="certificate-textarea" readonly spellcheck="false" wrap="soft">${jsonString}</textarea>`);

    openRegistrationDetailModal('Authenticator Data', sections.join(''));
}

export function closeRegistrationDetailModalRuntime() {
    closeModal('registrationDetailModal');
}
