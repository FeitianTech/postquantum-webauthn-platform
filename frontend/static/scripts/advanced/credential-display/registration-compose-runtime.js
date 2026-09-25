import {
    base64UrlToJson,
    base64UrlToUtf8String,
} from '../../shared/utils/binary.js';
import {closeModal, openModal} from '../../shared/ui/core.js';
import {el, fragment} from '../../shared/ui/dom.js';
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
    applyRegistrationDetailSnapshot,
    captureRegistrationDetailState,
    EMPTY_DETAIL_PREPARATION,
    prepareRegistrationDetailState,
} from './registration-state-runtime.js';
import {
    registrationDetailState,
} from './state.js';

const SECTION_STYLE = 'margin-bottom: 1.5rem;';
const SECTION_HEADING_STYLE = 'color: #0072CE; margin-bottom: 0.75rem;';
const PLACEHOLDER_STYLE = 'font-style: italic; color: #6c757d;';
const ERROR_STYLE = 'color: #dc3545; font-size: 0.9rem;';

function placeholder(text, extraStyle = '') {
    return el('div', { style: `${PLACEHOLDER_STYLE}${extraStyle}`, text });
}

function preformatted(text) {
    return el('pre', { className: 'modal-pre', text });
}

function attestationObjectJson(attestationObject, attestationFormatRaw) {
    const attestationDisplay = sanitiseAttestationObjectForDisplay(
        attestationObject,
        attestationFormatRaw,
    ) || attestationObject;
    try {
        return JSON.stringify(attestationDisplay, null, 2);
    } catch (error) {
        try {
            return JSON.stringify(attestationObject, null, 2);
        } catch (jsonError) {
            return '';
        }
    }
}

function certificateButton(label, displayIndex) {
    const button = el('button', {
        className: 'btn btn-small registration-attestation-cert-button',
        attrs: { type: 'button' },
        dataset: { certIndex: displayIndex },
        text: label,
    });
    button.addEventListener('click', event => {
        event.preventDefault();
        openAttestationCertificateDetail(displayIndex);
    });
    return button;
}

function authenticatorDataButton() {
    const button = el('button', {
        className: 'btn btn-small btn-secondary registration-authenticator-data-button',
        attrs: { type: 'button' },
        text: 'Authenticator Data',
    });
    button.addEventListener('click', event => {
        event.preventDefault();
        openAuthenticatorDataDetail();
    });
    return button;
}

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
        return null;
    }

    const hasAuthenticatorData = Boolean(registrationDetailState.authenticatorData);
    const shouldShowAuthenticatorError = !hasAuthenticatorData && authenticatorDataValue && authenticatorDecodeError;

    let attestationBody;
    if (attestationObject) {
        const attestationJson = attestationObjectJson(attestationObject, attestationFormatRaw);
        attestationBody = attestationJson
            ? certificateTextarea(attestationJson)
            : placeholder('Unable to prepare decoded attestationObject.');
    } else if (attestationObjectValue) {
        attestationBody = el('div', {
            style: ERROR_STYLE,
            text: attestationDecodeError || 'Unable to decode attestationObject.',
        });
    } else {
        attestationBody = placeholder('No attestationObject was provided.');
    }

    const buttons = [];
    let certificateMessage = null;
    if (attestationHasCertificates) {
        const singleCertificate = certificateInfos.length === 1;
        certificateInfos.forEach((info, displayIndex) => {
            buttons.push(certificateButton(
                singleCertificate ? 'Attestation Certificate' : `Attestation Certificate ${displayIndex + 1}`,
                displayIndex,
            ));
        });
    } else if (hasAttestationObject || hasAttestationValue || attestationStatementHasContent) {
        certificateMessage = placeholder('No attestation certificates available.', ' margin-top: 0.75rem;');
    }

    if (hasAuthenticatorData) {
        buttons.push(authenticatorDataButton());
    }

    return el('section', { style: SECTION_STYLE },
        el('h3', { style: SECTION_HEADING_STYLE, text: 'Attestation Information' }),
        el('div', { style: 'margin-bottom: 0.75rem;' },
            el('h4', {
                style: 'font-weight: 600; color: #0f2740; margin-bottom: 0.5rem;',
                text: 'Attestation Object',
            }),
            attestationBody,
        ),
        buttons.length ? el('div', { className: 'registration-detail-button-row' }, buttons) : null,
        certificateMessage,
        shouldShowAuthenticatorError
            ? el('div', { style: `${ERROR_STYLE} margin-top: 0.75rem;`, text: authenticatorDecodeError })
            : null,
    );
}

function describeClientData(credentialJson, fallbackClientData, fallbackParsedClientData) {
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

    if (parsedClientData) {
        return JSON.stringify(parsedClientData, null, 2);
    }
    if (clientDataBase64) {
        return base64UrlToUtf8String(clientDataBase64) || clientDataBase64;
    }
    if (fallbackClientDataString) {
        return fallbackClientDataString;
    }
    if (fallbackParsedClientData && typeof fallbackParsedClientData === 'object') {
        return JSON.stringify(fallbackParsedClientData, null, 2);
    }
    return '';
}

function buildResponseSections(credentialJson, clientDataDisplay, relyingPartyCopy) {
    const credentialDisplay = credentialJson && typeof credentialJson === 'object'
        ? JSON.stringify(credentialJson, null, 2)
        : '';
    const relyingPartyDisplay = relyingPartyCopy
        ? JSON.stringify(relyingPartyCopy, null, 2)
        : '';

    return [
        el('section', { style: SECTION_STYLE },
            el('h3', { style: SECTION_HEADING_STYLE, text: 'Authenticator Response' }),
            el('ol', { style: 'padding-left: 1.25rem; margin: 0;' },
                el('li', { style: 'margin-bottom: 1rem;' },
                    el('div', {
                        style: 'font-weight: 600; margin-bottom: 0.5rem;',
                        text: 'Response for navigator.credentials.create()',
                    }),
                    credentialDisplay
                        ? preformatted(credentialDisplay)
                        : placeholder('No credential response captured.'),
                ),
                el('li', {},
                    el('div', { style: 'font-weight: 600; margin-bottom: 0.5rem;', text: 'Parsed clientDataJSON' }),
                    clientDataDisplay
                        ? preformatted(clientDataDisplay)
                        : placeholder('No clientDataJSON available.'),
                ),
            ),
        ),
        el('section', { style: SECTION_STYLE },
            el('h3', { style: SECTION_HEADING_STYLE, text: 'Server-retrieved Data' }),
            relyingPartyDisplay
                ? preformatted(relyingPartyDisplay)
                : placeholder('No relying party data returned.'),
        ),
    ];
}

/**
 * The registration's detail view, built from data: the browser's response, the
 * client data, the relying party's view and the attestation. Returns the view as
 * a fragment of fresh nodes, with the state the snapshot keeps and the relying
 * party view it showed.
 */
export async function composeRegistrationDetail({
    credentialJson = null,
    relyingPartyInfo = null,
    attestationObjectValue = '',
    attestationObjectDecoded = null,
    authenticatorDataValue = '',
    authenticatorDataHex = '',
    fallbackCertificates = [],
    fallbackClientData = null,
    fallbackParsedClientData = null,
    preferFallbackCertificates = false,
    snapshotState = null,
} = {}) {
    const clientDataDisplay = describeClientData(credentialJson, fallbackClientData, fallbackParsedClientData);

    // A saved snapshot already holds the decoded attestation and certificates:
    // show those as they are, without asking the server to decode again.
    const detailPreparation = snapshotState && typeof snapshotState === 'object'
        ? applyRegistrationDetailSnapshot(snapshotState) || { ...EMPTY_DETAIL_PREPARATION }
        : await prepareRegistrationDetailState({
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

    const attestationSection = buildAttestationSection({
        attestationObjectValue: detailPreparation.attestationObjectValue,
        attestationDecodeError: detailPreparation.attestationDecodeError,
        attestationFormatRaw,
        attestationStatement,
        authenticatorDataValue: detailPreparation.authenticatorDataValue,
        authenticatorDecodeError: detailPreparation.authenticatorDecodeError,
    });

    return {
        view: fragment(buildResponseSections(credentialJson, clientDataDisplay, relyingPartyCopy), attestationSection),
        stateSnapshot: captureRegistrationDetailState(detailPreparation),
        relyingPartyCopy,
    };
}

export function certificateTextarea(text) {
    return el('textarea', {
        className: 'certificate-textarea',
        attrs: { readonly: true, spellcheck: 'false', wrap: 'soft' },
        text,
    });
}

function openRegistrationDetailModal(title, body) {
    const modal = document.getElementById('registrationDetailModal');
    const titleEl = document.getElementById('registrationDetailModalTitle');
    const bodyEl = document.getElementById('registrationDetailModalBody');
    if (!modal || !titleEl || !bodyEl) {
        return;
    }

    titleEl.textContent = title;
    bodyEl.replaceChildren(body);
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
    const errorMessage = typeof parsed.error === 'string' && parsed.error.trim() !== ''
        ? parsed.error.trim()
        : '';
    const summary = formatCertificateDetails(parsed);

    let body;
    if (summary && summary.trim() !== '') {
        body = certificateTextarea(summary);
    } else if (errorMessage) {
        body = el('div', { style: 'color: #dc3545; font-size: 0.9rem;', text: errorMessage });
    } else {
        body = el('div', {
            style: 'font-style: italic; color: #6c757d;',
            text: 'No decoded certificate details available.',
        });
    }

    const title = singleCertificate
        ? 'Attestation Certificate'
        : `Attestation Certificate ${index + 1}`;

    openRegistrationDetailModal(title, body);
}

export function openAuthenticatorDataDetail() {
    const data = registrationDetailState.authenticatorData;
    if (!data) {
        return;
    }

    openRegistrationDetailModal('Authenticator Data', certificateTextarea(JSON.stringify(data, null, 2)));
}

export function closeRegistrationDetailModalRuntime() {
    closeModal('registrationDetailModal');
}
